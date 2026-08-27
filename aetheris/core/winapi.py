"""
Shared native bindings.

Central place for the ctypes handles to ntdll/kernel32/advapi32/psapi and the
common structures/constants used across the forensics, storage, and memory
modules. Everything here is import-safe on non-Windows platforms (the DLL
handles simply become ``None``) so the codebase remains testable anywhere.
"""
from __future__ import annotations

import sys
import ctypes
from ctypes import wintypes

IS_WINDOWS = sys.platform == "win32"

# --- DLL handles -----------------------------------------------------------
if IS_WINDOWS:
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
else:  # pragma: no cover - non-Windows import guard
    ntdll = kernel32 = advapi32 = psapi = shell32 = None


# --- Common constants ------------------------------------------------------
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_SET_QUOTA = 0x0100
PROCESS_ALL_ACCESS = 0x1FFFFF

TOKEN_QUERY = 0x0008
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_DUPLICATE = 0x0002
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_IMPERSONATE = 0x0004

PROCESS_DUP_HANDLE = 0x0040
DUPLICATE_CLOSE_SOURCE = 0x00000001
DUPLICATE_SAME_ACCESS = 0x00000002

# NtQuerySystemInformation / NtQueryObject classes for handle enumeration.
SYSTEM_EXTENDED_HANDLE_INFORMATION = 64
OBJECT_NAME_INFORMATION = 1
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
# Synchronous file/pipe handles whose name query can block; skip these.
GRANTED_ACCESS_HANG = 0x0012019F

SE_PRIVILEGE_ENABLED = 0x00000002

# NtQuerySystemInformation classes we care about.
SYSTEM_BASIC_INFORMATION = 0
SYSTEM_PROCESS_INFORMATION = 5
SYSTEM_HANDLE_INFORMATION = 16
SYSTEM_MEMORY_LIST_INFORMATION = 0x50  # NtSetSystemInformation, purge standby list

# SystemMemoryListInformation commands.
MEMORY_PURGE_STANDBY_LIST = 4
MEMORY_PURGE_LOW_PRIORITY_STANDBY_LIST = 5
MEMORY_EMPTY_WORKING_SETS = 2


# --- Common structures -----------------------------------------------------
class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", wintypes.DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * 1),
    ]


def last_error_str() -> str:
    """Human-readable string for the last Win32 error on this thread."""
    if not IS_WINDOWS:
        return "n/a (non-Windows)"
    code = ctypes.get_last_error()
    if code == 0:
        return "0 (ERROR_SUCCESS)"
    try:
        msg = ctypes.FormatError(code).strip()
    except Exception:
        msg = "<unknown>"
    return f"{code} ({msg})"
