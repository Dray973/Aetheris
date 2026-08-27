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
from collections.abc import Callable
from ctypes import wintypes
from dataclasses import dataclass

from . import logbus
from . import winapi as W

SRC = "core.safety"


# --------------------------------------------------------------------------
# Rollback ledger
# --------------------------------------------------------------------------
@dataclass
class RollbackEntry:
    label: str
    undo: Callable[[], None]
    ts: float


class RollbackLedger:
    """LIFO stack of undoable actions for this session."""

    def __init__(self) -> None:
        self._entries: list[RollbackEntry] = []
        self._lock = threading.Lock()

    def register(self, label: str, undo: Callable[[], None]) -> None:
        with self._lock:
            self._entries.append(RollbackEntry(label, undo, time.time()))
        logbus.trace(SRC, f"rollback registered: {label}")

    def pending(self) -> list[str]:
        with self._lock:
            return [e.label for e in self._entries]

    def panic(self) -> list[tuple[str, bool, str]]:
        """Run every registered undo in reverse. Returns per-entry results."""
        with self._lock:
            entries = list(reversed(self._entries))
            self._entries.clear()
        logbus.action(SRC, f"PANIC: rolling back {len(entries)} action(s)")
        results: list[tuple[str, bool, str]] = []
        for e in entries:
            try:
                e.undo()
                results.append((e.label, True, "reverted"))
                logbus.success(SRC, f"reverted: {e.label}")
            except Exception as exc:  # noqa: BLE001
                results.append((e.label, False, str(exc)))
                logbus.error(SRC, f"rollback FAILED: {e.label}", str(exc))
        return results


# Process-wide session ledger.
ledger = RollbackLedger()


# --------------------------------------------------------------------------
# System Restore Point
# --------------------------------------------------------------------------
def create_restore_point(description: str = "Aetheris Quantum Core session") -> tuple[bool, str]:
    """
    Create a System Restore checkpoint. Tries WMI first, then PowerShell.
    Requires elevation and System Protection enabled on the system drive.
    """
    if not W.IS_WINDOWS:
        return False, "restore points only exist on Windows"

    # Preferred: WMI SystemRestore provider via win32com.
    try:
        import win32com.client  # type: ignore

        locator = win32com.client.Dispatch("WbemScripting.SWbemLocator")
        svc = locator.ConnectServer(".", r"root\default")
        sr = svc.Get("SystemRestore")
        # 0 = APPLICATION_INSTALL, 100 = BEGIN_SYSTEM_CHANGE
        rc = sr.CreateRestorePoint(description, 0, 100)
        if rc == 0:
            logbus.success(SRC, "System Restore Point created (WMI)")
            return True, "restore point created via WMI"
        return False, f"WMI CreateRestorePoint returned {rc}"
    except Exception as exc:  # noqa: BLE001
        logbus.warn(SRC, "WMI restore point failed, trying PowerShell", str(exc))

    # Fallback: PowerShell Checkpoint-Computer.
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


# --------------------------------------------------------------------------
# Registry snapshot via RegSaveKeyEx
# --------------------------------------------------------------------------
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
            os.remove(out_path)  # RegSaveKeyEx refuses to overwrite
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
