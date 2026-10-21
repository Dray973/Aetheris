"""
Omega Rollback — the safety shield.

Three capabilities:

  1. System Restore Point (WMI SystemRestore.CreateRestorePoint, with a
     PowerShell Checkpoint-Computer fallback) before a deep-modification session.
  2. Registry snapshot to a local hive file via RegSaveKeyEx, so a specific key
     tree can be restored exactly.
  3. A RollbackLedger: every reversible action registers an undo callback. The
     UI PANIC button flushes the queue and runs undos in reverse (LIFO).

Nothing here executes a destructive change on its own — modules call
``ledger.register(...)`` alongside the change they make so PANIC can reverse it.
"""
from __future__ import annotations

import ctypes
import os
import subprocess
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from ctypes import wintypes
from dataclasses import dataclass, field

from . import logbus
from . import winapi as W

SRC = "core.safety"


@dataclass
class RollbackEntry:
    label: str
    undo: Callable[[], None]
    ts: float
    id: int = 0
    #: For a transaction group: its member actions, in the order they ran.
    children: list[RollbackEntry] = field(default_factory=list)

    def run(self) -> list[tuple[str, bool, str]]:
        """Undo this entry (a group: its members in reverse). Never raises."""
        if self.children:
            out: list[tuple[str, bool, str]] = []
            for child in reversed(self.children):
                out += child.run()
            return out
        try:
            self.undo()
        except Exception as exc:  # noqa: BLE001
            logbus.error(SRC, f"rollback FAILED: {self.label}", str(exc))
            return [(self.label, False, str(exc))]
        logbus.success(SRC, f"reverted: {self.label}")
        return [(self.label, True, "reverted")]


def _noop() -> None:
    return None


class RollbackLedger:
    """LIFO stack of undoable actions for this session.

    Actions registered inside :meth:`group` are collected into one entry, so a
    multi-step operation (a containment: suspend + isolate + disable +
    quarantine) can be undone as a unit with :meth:`undo` while PANIC still
    reverts everything.
    """

    def __init__(self) -> None:
        self._entries: list[RollbackEntry] = []
        self._lock = threading.Lock()
        self._next_id = 1
        # Groups are per-thread: a containment runs on its own Worker, and an
        # unrelated action on another thread must not be swept into it.
        self._local = threading.local()

    def _new_id(self) -> int:
        with self._lock:
            n = self._next_id
            self._next_id += 1
            return n

    def register(self, label: str, undo: Callable[[], None]) -> int:
        entry = RollbackEntry(label, undo, time.time(), self._new_id())
        stack: list[list[RollbackEntry]] = getattr(self._local, "groups", [])
        if stack:
            stack[-1].append(entry)
        else:
            with self._lock:
                self._entries.append(entry)
        logbus.trace(SRC, f"rollback registered: {label}")
        return entry.id

    @contextmanager
    def group(self, label: str) -> Iterator[GroupHandle]:
        """Collect every undo registered in this block into one entry.

        The group is pushed even if the block raises: whatever was done before
        the failure must stay undoable. An empty group leaves no entry.
        """
        stack = getattr(self._local, "groups", None)
        if stack is None:
            stack = self._local.groups = []
        members: list[RollbackEntry] = []
        stack.append(members)
        handle = GroupHandle(label=label)
        try:
            yield handle
        finally:
            stack.pop()
            if members:
                entry = RollbackEntry(label, _noop, time.time(), self._new_id(),
                                      children=members)
                handle.id = entry.id
                handle.members = [m.label for m in members]
                if stack:                      # nested group: fold into the outer one
                    stack[-1].append(entry)
                else:
                    with self._lock:
                        self._entries.append(entry)
                logbus.trace(SRC, f"rollback group registered: {label} "
                                  f"({len(members)} action(s))")

    def pending(self) -> list[str]:
        with self._lock:
            return [e.label for e in self._entries]

    def has(self, entry_id: int) -> bool:
        with self._lock:
            return any(e.id == entry_id for e in self._entries)

    def undo(self, entry_id: int) -> list[tuple[str, bool, str]]:
        """Undo one entry (or group) by id and drop it from the ledger."""
        with self._lock:
            for i, e in enumerate(self._entries):
                if e.id == entry_id:
                    del self._entries[i]
                    break
            else:
                return [(f"#{entry_id}", False, "nothing to undo (already reverted?)")]
        logbus.action(SRC, f"undo: {e.label}")
        return e.run()

    def panic(self) -> list[tuple[str, bool, str]]:
        """Run every registered undo in reverse. Returns per-entry results."""
        with self._lock:
            entries = list(reversed(self._entries))
            self._entries.clear()
        logbus.action(SRC, f"PANIC: rolling back {len(entries)} action(s)")
        results: list[tuple[str, bool, str]] = []
        for e in entries:
            results += e.run()
        return results


@dataclass
class GroupHandle:
    """Filled in when a :meth:`RollbackLedger.group` block closes."""
    label: str
    id: int = 0
    members: list[str] = field(default_factory=list)


ledger = RollbackLedger()


def create_restore_point(description: str = "Aetheris Quantum Core session") -> tuple[bool, str]:
    """
    Create a System Restore checkpoint. Tries WMI first, then PowerShell.
    Requires elevation and System Protection enabled on the system drive.
    """
    if not W.IS_WINDOWS:
        return False, "restore points only exist on Windows"

    try:
        import win32com.client

        locator = win32com.client.Dispatch("WbemScripting.SWbemLocator")
        svc = locator.ConnectServer(".", r"root\default")
        sr = svc.Get("SystemRestore")
        rc = sr.CreateRestorePoint(description, 0, 100)
        if rc == 0:
            logbus.success(SRC, "System Restore Point created (WMI)")
            return True, "restore point created via WMI"
        return False, f"WMI CreateRestorePoint returned {rc}"
    except Exception as exc:  # noqa: BLE001
        logbus.warn(SRC, "WMI restore point failed, trying PowerShell", str(exc))

    try:
        cmd = [
            "powershell", "-NoProfile", "-NonInteractive", "-Command",
            f"Checkpoint-Computer -Description '{description}' "
            f"-RestorePointType 'MODIFY_SETTINGS'",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if proc.returncode == 0:
            logbus.success(SRC, "System Restore Point created (PowerShell)")
            return True, "restore point created via PowerShell"
        return False, (proc.stderr or proc.stdout or "unknown error").strip()
    except Exception as exc:  # noqa: BLE001
        return False, f"restore point failed: {exc}"


HKEY_CLASSES_ROOT = 0x80000000
HKEY_CURRENT_USER = 0x80000001
HKEY_LOCAL_MACHINE = 0x80000002
HKEY_USERS = 0x80000003

_ROOTS = {
    "HKCR": HKEY_CLASSES_ROOT,
    "HKCU": HKEY_CURRENT_USER,
    "HKLM": HKEY_LOCAL_MACHINE,
    "HKU": HKEY_USERS,
}

KEY_READ = 0x20019
REG_LATEST_FORMAT = 2


def snapshot_registry_key(root: str, subkey: str, out_path: str) -> tuple[bool, str]:
    """
    Save a registry key tree to a hive file using RegSaveKeyEx.
    ``root`` is one of HKCR/HKCU/HKLM/HKU. Requires SeBackupPrivilege.
    """
    if not W.IS_WINDOWS:
        return False, "registry snapshots only exist on Windows"
    root_h = _ROOTS.get(root.upper())
    if root_h is None:
        return False, f"unknown root {root!r}"

    hkey = wintypes.HANDLE()
    rc = W.advapi32.RegOpenKeyExW(
        wintypes.HANDLE(root_h), subkey, 0, KEY_READ, ctypes.byref(hkey)
    )
    if rc != 0:
        return False, f"RegOpenKeyEx failed (code {rc})"
    try:
        if os.path.exists(out_path):
            os.remove(out_path)
        rc = W.advapi32.RegSaveKeyExW(hkey, out_path, None, REG_LATEST_FORMAT)
        if rc != 0:
            return False, f"RegSaveKeyEx failed (code {rc})"
        logbus.action(SRC, f"registry snapshot saved: {root}\\{subkey}", out_path)
        return True, out_path
    finally:
        W.advapi32.RegCloseKey(hkey)


if W.IS_WINDOWS:
    W.advapi32.RegOpenKeyExW.argtypes = [
        wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    W.advapi32.RegOpenKeyExW.restype = wintypes.LONG
    W.advapi32.RegSaveKeyExW.argtypes = [
        wintypes.HANDLE, wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD,
    ]
    W.advapi32.RegSaveKeyExW.restype = wintypes.LONG
    W.advapi32.RegCloseKey.argtypes = [wintypes.HANDLE]
    W.advapi32.RegCloseKey.restype = wintypes.LONG
