"""
System RAM Matrix — memory release controls.

Real implementations, each gated behind an explicit UI confirmation:

  * empty_working_set(pid)   — SetProcessWorkingSetSize(-1, -1) / EmptyWorkingSet
  * purge_standby_list()     — NtSetSystemInformation(SystemMemoryListInformation)
  * flush_file_cache()       — SetSystemFileCacheSize(-1, -1, 0)

These operations are safe in the sense that Windows re-populates working sets and
caches on demand; they trade a momentary latency spike for freed physical RAM.
They still require the right privileges (SeProfileSingleProcessPrivilege,
SeIncreaseQuotaPrivilege), enabled via core.privileges.enable_forensics_privileges().
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes

from ..core import logbus
from ..core import winapi as W

SRC = "forensics.memory"


def empty_working_set(pid: int) -> tuple[bool, str]:
    """Trim a single process's working set back to the OS."""
    if not W.IS_WINDOWS:
        return False, "Windows only"
    access = W.PROCESS_QUERY_INFORMATION | W.PROCESS_SET_QUOTA
    h = W.kernel32.OpenProcess(access, False, pid)
    if not h:
        return False, f"OpenProcess failed: {W.last_error_str()}"
    try:
        SIZE_T_MAX = ctypes.c_size_t(-1).value
        ok = W.kernel32.SetProcessWorkingSetSize(h, SIZE_T_MAX, SIZE_T_MAX)
        if not ok:
            return False, f"SetProcessWorkingSetSize failed: {W.last_error_str()}"
        logbus.action(SRC, f"trimmed working set of pid {pid}")
        return True, f"working set of pid {pid} trimmed"
    finally:
        W.kernel32.CloseHandle(h)


def empty_all_working_sets() -> tuple[int, int]:
    """Trim every accessible process. Returns (succeeded, attempted)."""
    import psutil
    ok = attempted = 0
    for p in psutil.process_iter(["pid"]):
        attempted += 1
        good, _ = empty_working_set(p.info["pid"])
        ok += 1 if good else 0
    logbus.action(SRC, f"emptied working sets: {ok}/{attempted}")
    return ok, attempted


class _SYSTEM_MEMORY_LIST_COMMAND(ctypes.Structure):
    _fields_ = [("Command", ctypes.c_int)]


def purge_standby_list(low_priority_only: bool = False) -> tuple[bool, str]:
    """
    Purge the standby (cached) page list system-wide via NtSetSystemInformation.
    Requires SeProfileSingleProcessPrivilege.
    """
    if not W.IS_WINDOWS:
        return False, "Windows only"
    cmd = _SYSTEM_MEMORY_LIST_COMMAND()
    cmd.Command = (
        W.MEMORY_PURGE_LOW_PRIORITY_STANDBY_LIST if low_priority_only
        else W.MEMORY_PURGE_STANDBY_LIST
    )
    status = W.ntdll.NtSetSystemInformation(
        W.SYSTEM_MEMORY_LIST_INFORMATION, ctypes.byref(cmd), ctypes.sizeof(cmd)
    )
    if status == 0:
        logbus.action(SRC, "purged standby page list")
        return True, "standby list purged"
    # NTSTATUS is signed; format as unsigned hex for readability.
    return False, f"NtSetSystemInformation NTSTATUS 0x{status & 0xFFFFFFFF:08X}"


def flush_file_cache() -> tuple[bool, str]:
    """Shrink the system working-set / file cache. Requires SeIncreaseQuota."""
    if not W.IS_WINDOWS:
        return False, "Windows only"
    SIZE_T_MAX = ctypes.c_size_t(-1).value
    ok = W.kernel32.SetSystemFileCacheSize(SIZE_T_MAX, SIZE_T_MAX, 0)
    if not ok:
        return False, f"SetSystemFileCacheSize failed: {W.last_error_str()}"
    logbus.action(SRC, "flushed system file cache")
    return True, "system file cache flushed"


if W.IS_WINDOWS:
    W.kernel32.SetProcessWorkingSetSize.argtypes = [
        wintypes.HANDLE, ctypes.c_size_t, ctypes.c_size_t
    ]
    W.kernel32.SetProcessWorkingSetSize.restype = wintypes.BOOL
    W.kernel32.SetSystemFileCacheSize.argtypes = [
        ctypes.c_size_t, ctypes.c_size_t, wintypes.DWORD
    ]
    W.kernel32.SetSystemFileCacheSize.restype = wintypes.BOOL
    W.ntdll.NtSetSystemInformation.argtypes = [
        ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong
    ]
    W.ntdll.NtSetSystemInformation.restype = ctypes.c_long
