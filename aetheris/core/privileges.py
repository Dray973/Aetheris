"""
Privilege management.

Standard, auditable elevation model:

  * ``is_elevated()``      — are we running with an elevated admin token?
  * ``relaunch_as_admin`` — re-launch this process via the UAC "runas" verb.
  * ``enable_privilege``  — enable a named privilege (e.g. SeDebugPrivilege) on
                            the *current* process token.
  * ``enable_forensics_privileges`` — enable the small set the inspection
                            features actually require.

Design note: this module deliberately does not clone/duplicate other processes'
tokens to impersonate SYSTEM or TrustedInstaller. Enabling SeDebugPrivilege on
an elevated admin token is sufficient to open, read, and (with explicit user
confirmation elsewhere) write process memory, which is what the forensics
workspace needs. Keeping the trust model at "elevated admin + named
privileges" makes the tool auditable and avoids a hidden-daemon design.
"""
from __future__ import annotations

import ctypes
import os
import sys
from collections.abc import Iterable
from ctypes import wintypes

from . import winapi as W

# Privileges the forensics/memory/storage features rely on.
FORENSICS_PRIVILEGES = (
    "SeDebugPrivilege",            # open other processes for VM read/query
    "SeTakeOwnershipPrivilege",    # claim ownership of locked/protected objects
    "SeBackupPrivilege",           # RegSaveKeyEx snapshots, raw reads
    "SeRestorePrivilege",          # restore snapshot hives (rollback)
    "SeProfileSingleProcessPrivilege",  # memory-list / cache operations
    "SeIncreaseQuotaPrivilege",    # working-set / cache sizing
)


def is_elevated() -> bool:
    """True if the current process holds an elevated (admin) token."""
    if not W.IS_WINDOWS:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(W.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin(extra_args: Iterable[str] | None = None) -> bool:
    """
    Relaunch the current script elevated using ShellExecuteW('runas').
    Returns True if a new elevated process was successfully requested.
    """
    if not W.IS_WINDOWS:
        return False
    args = list(sys.argv[1:]) + list(extra_args or [])
    if getattr(sys, "frozen", False):
        # Frozen exe: sys.executable IS the app; relaunch it directly with the
        # bare args (there is no separate script path to pass).
        target = sys.executable
        params = " ".join(f'"{a}"' for a in args)
    else:
        # Interpreter run: relaunch python with the script path + args.
        target = sys.executable
        params = " ".join(f'"{a}"' for a in ([os.path.abspath(sys.argv[0])] + args))
    try:
        # SW_SHOWNORMAL = 1. Return value > 32 means success.
        rc = W.shell32.ShellExecuteW(None, "runas", target, params, None, 1)
        return int(rc) > 32
    except Exception:
        return False


def _lookup_luid(name: str) -> W.LUID | None:
    luid = W.LUID()
    ok = W.advapi32.LookupPrivilegeValueW(None, name, ctypes.byref(luid))
    return luid if ok else None


def enable_privilege(name: str) -> tuple[bool, str]:
    """
    Enable a named privilege on the current process token.
    Returns (success, human_readable_status).
    """
    if not W.IS_WINDOWS:
        return False, "not supported on this platform"

    hproc = W.kernel32.GetCurrentProcess()
    htok = wintypes.HANDLE()
    if not W.advapi32.OpenProcessToken(
        hproc, W.TOKEN_ADJUST_PRIVILEGES | W.TOKEN_QUERY, ctypes.byref(htok)
    ):
        return False, f"OpenProcessToken failed: {W.last_error_str()}"

    try:
        luid = _lookup_luid(name)
        if luid is None:
            return False, f"LookupPrivilegeValue({name}) failed: {W.last_error_str()}"

        tp = W.TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = W.SE_PRIVILEGE_ENABLED

        if not W.advapi32.AdjustTokenPrivileges(
            htok, False, ctypes.byref(tp), 0, None, None
        ):
            return False, f"AdjustTokenPrivileges failed: {W.last_error_str()}"

        # AdjustTokenPrivileges can "succeed" but not assign all privileges.
        # ERROR_NOT_ALL_ASSIGNED == 1300.
        err = ctypes.get_last_error()
        if err == 1300:
            return False, f"{name}: not held by this token (ERROR_NOT_ALL_ASSIGNED)"
        return True, f"{name}: enabled"
    finally:
        W.kernel32.CloseHandle(htok)


def enable_forensics_privileges() -> list[tuple[str, bool, str]]:
    """Enable each forensics privilege; returns a per-privilege result list."""
    results: list[tuple[str, bool, str]] = []
    for name in FORENSICS_PRIVILEGES:
        ok, msg = enable_privilege(name)
        results.append((name, ok, msg))
    return results


if W.IS_WINDOWS:
    # Argument/restype hints so ctypes marshals 64-bit handles correctly.
    W.advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)
    ]
    W.advapi32.OpenProcessToken.restype = wintypes.BOOL
    W.advapi32.LookupPrivilegeValueW.argtypes = [
        wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(W.LUID)
    ]
    W.advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
    W.advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL
    W.kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    W.shell32.ShellExecuteW.restype = wintypes.HINSTANCE
