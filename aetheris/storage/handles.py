"""
System handle enumeration + forced handle closing.

Implements the deep unlock path referenced by the obliterator: enumerate the
global handle table via NtQuerySystemInformation(SystemExtendedHandleInformation),
resolve each candidate handle's object name with NtQueryObject, and — for handles
that name the target file — force them shut in the owning process with
DuplicateHandle(DUPLICATE_CLOSE_SOURCE).

Safety / robustness:
  * Enumeration is filtered to a caller-supplied set of PIDs (the known lockers),
    which bounds the (potentially hang-prone) NtQueryObject calls.
  * Handles whose GrantedAccess matches the known "synchronous pipe" value that
    can hang NtQueryObject are skipped.
  * Callers (storage.unlock) enforce the critical-process / protected-path
    guardrails before invoking the close path.
"""
from __future__ import annotations

import os
import ctypes
import threading
from ctypes import wintypes
from dataclasses import dataclass

from ..core import winapi as W
from ..core import logbus

SRC = "storage.handles"


@dataclass(frozen=True)
class HandleEntry:
    """A plain-Python snapshot of one handle-table entry (no dangling views)."""
    pid: int
    handle: int
    access: int
    type_index: int


class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(ctypes.Structure):
    _fields_ = [
        ("Object", ctypes.c_void_p),
        ("UniqueProcessId", ctypes.c_void_p),
        ("HandleValue", ctypes.c_void_p),
        ("GrantedAccess", wintypes.ULONG),
        ("CreatorBackTraceIndex", wintypes.USHORT),
        ("ObjectTypeIndex", wintypes.USHORT),
        ("HandleAttributes", wintypes.ULONG),
        ("Reserved", wintypes.ULONG),
    ]


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", ctypes.c_void_p),
    ]


_HANDLES_OFFSET = 2 * ctypes.sizeof(ctypes.c_void_p)   # NumberOfHandles + Reserved


def _drive_device_map() -> dict[str, str]:
    """Map 'C:' -> '\\Device\\HarddiskVolumeN' for each fixed drive letter."""
    out: dict[str, str] = {}
    if not W.IS_WINDOWS:
        return out
    buf = ctypes.create_unicode_buffer(1024)
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        dos = f"{letter}:"
        if W.kernel32.QueryDosDeviceW(dos, buf, 1024):
            out[dos] = buf.value
    return out


def to_device_path(win_path: str, drive_map: dict[str, str] | None = None) -> str | None:
    """Convert 'C:\\dir\\file' to its '\\Device\\HarddiskVolumeN\\dir\\file' form."""
    win_path = os.path.abspath(win_path)
    if len(win_path) < 2 or win_path[1] != ":":
        return None
    drive_map = drive_map or _drive_device_map()
    device = drive_map.get(win_path[:2].upper())
    if not device:
        return None
    return device + win_path[2:]


def enumerate_handles(pids: set[int] | None = None) -> list[HandleEntry]:
    """
    Return handle-table entries (as value-copied HandleEntry), optionally
    filtered to ``pids``. Values are copied out of the native buffer before it
    is freed, so the returned objects are safe to use after this returns.
    """
    if not W.IS_WINDOWS:
        return []
    size = 0x40000
    buf = None
    for _ in range(8):
        buf = ctypes.create_string_buffer(size)
        retlen = wintypes.ULONG(0)
        status = W.ntdll.NtQuerySystemInformation(
            W.SYSTEM_EXTENDED_HANDLE_INFORMATION, buf, size, ctypes.byref(retlen))
        if (status & 0xFFFFFFFF) == W.STATUS_INFO_LENGTH_MISMATCH:
            size = max(retlen.value + 0x10000, size * 2)
            continue
        if status != 0:
            logbus.warn(SRC, f"NtQuerySystemInformation status 0x{status & 0xFFFFFFFF:08X}")
            return []
        break
    else:
        return []

    base = ctypes.addressof(buf)
    num = ctypes.c_size_t.from_address(base).value
    arr_type = SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * num
    arr = arr_type.from_address(base + _HANDLES_OFFSET)
    out = []
    for e in arr:                              # copy values; buf is freed on return
        pid = int(e.UniqueProcessId or 0)
        if pids is not None and pid not in pids:
            continue
        out.append(HandleEntry(pid, int(e.HandleValue or 0),
                               int(e.GrantedAccess), int(e.ObjectTypeIndex)))
    logbus.trace(SRC, f"enumerated {len(out)} handle(s)"
                      + (f" for pids {sorted(pids)}" if pids else ""))
    return out


def _query_object_name(dup) -> str | None:
    size = 0x1000
    nbuf = ctypes.create_string_buffer(size)
    retlen = wintypes.ULONG(0)
    status = W.ntdll.NtQueryObject(
        dup, W.OBJECT_NAME_INFORMATION, nbuf, size, ctypes.byref(retlen))
    if status != 0:
        return None
    us = UNICODE_STRING.from_buffer_copy(nbuf.raw[:ctypes.sizeof(UNICODE_STRING)])
    if not us.Buffer or us.Length == 0 or us.Length > size:
        return None
    # The name buffer points *inside* nbuf; validate the range before reading so
    # a malformed entry can never cause a wild out-of-bounds read (segfault).
    base = ctypes.addressof(nbuf)
    if not (base <= us.Buffer <= base + size - us.Length):
        return None
    return ctypes.wstring_at(us.Buffer, us.Length // 2)


def _handle_name(hproc, handle_value: int, timeout: float = 0.15) -> str | None:
    """
    Resolve a handle's object name. The NtQueryObject name query can block
    forever on certain synchronous handles (pipes), so it runs in a worker
    thread with a timeout; if it stalls we abandon the duplicate and move on.
    """
    dup = wintypes.HANDLE()
    if not W.kernel32.DuplicateHandle(
        hproc, wintypes.HANDLE(handle_value), W.kernel32.GetCurrentProcess(),
        ctypes.byref(dup), 0, False, W.DUPLICATE_SAME_ACCESS,
    ):
        return None

    box: dict = {"name": None, "done": False}

    def worker():
        try:
            box["name"] = _query_object_name(dup)
        except Exception:
            pass
        box["done"] = True

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    t.join(timeout)
    if not box["done"]:
        # Stuck query: leak the dup (safer than closing under a stuck thread).
        logbus.trace(SRC, f"name query timed out for handle 0x{handle_value:x}")
        return None
    W.kernel32.CloseHandle(dup)
    return box["name"]


def find_file_handles(path: str, pids: set[int]) -> list[tuple[int, int]]:
    """Return (pid, handle_value) for handles in ``pids`` naming ``path``."""
    target = to_device_path(path)
    if target is None:
        return []
    target = target.lower()
    matches: list[tuple[int, int]] = []
    drive_map = _drive_device_map()  # noqa: F841 (kept warm for clarity)
    opened: dict[int, wintypes.HANDLE] = {}
    try:
        for e in enumerate_handles(pids):
            if e.access == W.GRANTED_ACCESS_HANG:
                continue                      # skip hang-prone synchronous handles
            if e.pid not in opened:
                opened[e.pid] = W.kernel32.OpenProcess(W.PROCESS_DUP_HANDLE, False, e.pid)
            hproc = opened[e.pid]
            if not hproc:
                continue
            name = _handle_name(hproc, e.handle)
            if name and name.lower() == target:
                matches.append((e.pid, e.handle))
    finally:
        for h in opened.values():
            if h:
                W.kernel32.CloseHandle(h)
    logbus.trace(SRC, f"{len(matches)} handle(s) name {path}")
    return matches


def close_handle_in_process(pid: int, handle_value: int) -> tuple[bool, str]:
    """Force-close a handle inside another process via DUPLICATE_CLOSE_SOURCE."""
    hproc = W.kernel32.OpenProcess(W.PROCESS_DUP_HANDLE, False, pid)
    if not hproc:
        return False, f"OpenProcess(DUP) pid {pid} failed: {W.last_error_str()}"
    try:
        ok = W.kernel32.DuplicateHandle(
            hproc, wintypes.HANDLE(handle_value), None, None, 0, False,
            W.DUPLICATE_CLOSE_SOURCE)
        if ok:
            logbus.action(SRC, f"force-closed handle 0x{handle_value:x} in pid {pid}")
            return True, "closed"
        return False, f"DuplicateHandle(CLOSE_SOURCE) failed: {W.last_error_str()}"
    finally:
        W.kernel32.CloseHandle(hproc)


# --------------------------------------------------------------------------
# Restart Manager — robust "who has this file open" (replaces psutil.open_files,
# which can hit a native access violation while enumerating some handles).
# --------------------------------------------------------------------------
class _FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]


class _RM_UNIQUE_PROCESS(ctypes.Structure):
    _fields_ = [("dwProcessId", wintypes.DWORD), ("ProcessStartTime", _FILETIME)]


class _RM_PROCESS_INFO(ctypes.Structure):
    _fields_ = [
        ("Process", _RM_UNIQUE_PROCESS),
        ("strAppName", ctypes.c_wchar * 256),
        ("strServiceShortName", ctypes.c_wchar * 64),
        ("ApplicationType", ctypes.c_int),
        ("AppStatus", wintypes.ULONG),
        ("TSSessionId", wintypes.DWORD),
        ("bRestartable", wintypes.BOOL),
    ]


def locking_processes(path: str) -> list[tuple[int, str]]:
    """Return (pid, app_name) for every process holding ``path`` open."""
    if not W.IS_WINDOWS:
        return []
    try:
        rm = ctypes.WinDLL("rstrtmgr")
    except OSError:
        return []
    session = wintypes.DWORD()
    key = (ctypes.c_wchar * 33)()
    if rm.RmStartSession(ctypes.byref(session), 0, key) != 0:
        return []
    try:
        files = (wintypes.LPCWSTR * 1)(path)
        if rm.RmRegisterResources(session, 1, files, 0, None, 0, None) != 0:
            return []
        needed = wintypes.UINT(0)
        count = wintypes.UINT(0)
        reasons = wintypes.DWORD(0)
        rm.RmGetList(session, ctypes.byref(needed), ctypes.byref(count),
                     None, ctypes.byref(reasons))
        if needed.value == 0:
            return []
        arr = (_RM_PROCESS_INFO * needed.value)()
        count = wintypes.UINT(needed.value)
        if rm.RmGetList(session, ctypes.byref(needed), ctypes.byref(count),
                        arr, ctypes.byref(reasons)) != 0:
            return []
        out = []
        for i in range(count.value):
            pi = arr[i]
            out.append((int(pi.Process.dwProcessId), pi.strAppName or "?"))
        logbus.trace(SRC, f"Restart Manager: {len(out)} process(es) lock {path}")
        return out
    finally:
        rm.RmEndSession(session)


def strip_file_handles(path: str, pids: set[int]) -> list[tuple[int, int, bool, str]]:
    """
    Find and force-close every handle to ``path`` held by ``pids``.
    Returns (pid, handle_value, closed, note) per handle.
    """
    results: list[tuple[int, int, bool, str]] = []
    for pid, hv in find_file_handles(path, pids):
        ok, note = close_handle_in_process(pid, hv)
        results.append((pid, hv, ok, note))
    return results


if W.IS_WINDOWS:
    W.ntdll.NtQuerySystemInformation.argtypes = [
        ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(wintypes.ULONG)]
    W.ntdll.NtQuerySystemInformation.restype = ctypes.c_long
    W.ntdll.NtQueryObject.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong,
        ctypes.POINTER(wintypes.ULONG)]
    W.ntdll.NtQueryObject.restype = ctypes.c_long
    W.kernel32.DuplicateHandle.argtypes = [
        wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE,
        ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    W.kernel32.DuplicateHandle.restype = wintypes.BOOL
    W.kernel32.QueryDosDeviceW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    W.kernel32.QueryDosDeviceW.restype = wintypes.DWORD
    W.kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    W.kernel32.OpenProcess.restype = wintypes.HANDLE
