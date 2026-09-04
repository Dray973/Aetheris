"""
Authenticode signature check (real WinVerifyTrust + catalog fallback).

``is_signed(path)`` returns True when a file carries a valid, trusted signature
-- either an embedded Authenticode signature or a hash entry in a signed system
catalog (how most OS binaries are signed) -- False when it has neither, and None
when undeterminable (non-Windows, missing file, or the call failed). Results are
cached per path; a services / autoruns list re-checks the same binaries often.

Pure ctypes over wintrust.dll + kernel32; no optional dependency.
"""
from __future__ import annotations

import ctypes
import os
import threading
from ctypes import wintypes

from ..native import win as nativewin
from . import logbus
from . import winapi as W

SRC = "core.signing"

_WTD_UI_NONE = 2
_WTD_REVOKE_NONE = 0
_WTD_CHOICE_FILE = 1
_WTD_STATEACTION_VERIFY = 1
_WTD_STATEACTION_CLOSE = 2
_WTD_SAFER_FLAG = 0x100
_ERROR_SUCCESS = 0
_GENERIC_READ = 0x80000000
_FILE_SHARE_READ = 0x00000001
_OPEN_EXISTING = 3
_INVALID_HANDLE = ctypes.c_void_p(-1).value


class _GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]


class _WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD),
                ("pcwszFilePath", wintypes.LPCWSTR),
                ("hFile", wintypes.HANDLE),
                ("pgKnownSubject", ctypes.c_void_p)]


class _WINTRUST_DATA(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD),
                ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p),
                ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD),
                ("dwUnionChoice", wintypes.DWORD),
                ("pFile", ctypes.POINTER(_WINTRUST_FILE_INFO)),
                ("dwStateAction", wintypes.DWORD),
                ("hWVTStateData", wintypes.HANDLE),
                ("pwszURLReference", wintypes.LPCWSTR),
                ("dwProvFlags", wintypes.DWORD),
                ("dwUIContext", wintypes.DWORD),
                ("pSignatureSettings", ctypes.c_void_p)]


_GENERIC_VERIFY_V2 = _GUID(0x00AAC56B, 0xCD44, 0x11D0,
                           (0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))

_wintrust = None
_kernel32 = None
if W.IS_WINDOWS:
    try:
        _wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
        _wintrust.WinVerifyTrust.argtypes = [wintypes.HANDLE, ctypes.POINTER(_GUID),
                                             ctypes.c_void_p]
        _wintrust.WinVerifyTrust.restype = wintypes.LONG
        _wintrust.CryptCATAdminAcquireContext.argtypes = [
            ctypes.POINTER(wintypes.HANDLE), ctypes.c_void_p, wintypes.DWORD]
        _wintrust.CryptCATAdminAcquireContext.restype = wintypes.BOOL
        _wintrust.CryptCATAdminCalcHashFromFileHandle.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, wintypes.DWORD]
        _wintrust.CryptCATAdminCalcHashFromFileHandle.restype = wintypes.BOOL
        _wintrust.CryptCATAdminEnumCatalogFromHash.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
            ctypes.POINTER(wintypes.HANDLE)]
        _wintrust.CryptCATAdminEnumCatalogFromHash.restype = wintypes.HANDLE
        _wintrust.CryptCATAdminReleaseCatalogContext.argtypes = [
            wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD]
        _wintrust.CryptCATAdminReleaseCatalogContext.restype = wintypes.BOOL
        _wintrust.CryptCATAdminReleaseContext.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        _wintrust.CryptCATAdminReleaseContext.restype = wintypes.BOOL

        _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        _kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                          ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                          wintypes.HANDLE]
        _kernel32.CreateFileW.restype = wintypes.HANDLE
        _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        _kernel32.CloseHandle.restype = wintypes.BOOL
    except OSError:  # pragma: no cover
        _wintrust = None
        _kernel32 = None

_cache: dict[str, bool | None] = {}
_lock = threading.Lock()


def is_signed(path: str | None) -> bool | None:
    """True if *path* has a valid embedded **or** catalog signature; False if
    neither; None if undeterminable (non-Windows / no file / call failed)."""
    if not path or _wintrust is None:
        return None
    key = os.path.normcase(os.path.abspath(path))
    with _lock:
        if key in _cache:
            return _cache[key]
    result = _verify(path)
    with _lock:
        _cache[key] = result
    return result


def _verify(path: str) -> bool | None:
    if not os.path.isfile(path):
        return None
    # The native engine does the embedded check and the catalog lookup behind
    # one call, reusing a single catalog admin context across files — the
    # ctypes path below acquires and releases one per file, which dominates a
    # services or autoruns sweep.
    native = nativewin.verify_signature(path)
    if native is not None:
        return native in (nativewin.SIG_EMBEDDED, nativewin.SIG_CATALOG)
    file_info = _WINTRUST_FILE_INFO(cbStruct=ctypes.sizeof(_WINTRUST_FILE_INFO),
                                    pcwszFilePath=path, hFile=None, pgKnownSubject=None)
    data = _WINTRUST_DATA(
        cbStruct=ctypes.sizeof(_WINTRUST_DATA),
        dwUIChoice=_WTD_UI_NONE, fdwRevocationChecks=_WTD_REVOKE_NONE,
        dwUnionChoice=_WTD_CHOICE_FILE, pFile=ctypes.pointer(file_info),
        dwStateAction=_WTD_STATEACTION_VERIFY, dwProvFlags=_WTD_SAFER_FLAG)
    try:
        rc = _wintrust.WinVerifyTrust(None, ctypes.byref(_GENERIC_VERIFY_V2),
                                      ctypes.byref(data))
        data.dwStateAction = _WTD_STATEACTION_CLOSE
        _wintrust.WinVerifyTrust(None, ctypes.byref(_GENERIC_VERIFY_V2),
                                 ctypes.byref(data))
    except OSError as exc:  # pragma: no cover
        logbus.trace(SRC, f"WinVerifyTrust failed for {path}", str(exc))
        return None
    if rc == _ERROR_SUCCESS:
        return True
    return _in_catalog(path)


def _in_catalog(path: str) -> bool:
    """True if the file's hash appears in a system catalog (i.e. catalog-signed)."""
    if _wintrust is None or _kernel32 is None:
        return False
    h = _kernel32.CreateFileW(path, _GENERIC_READ, _FILE_SHARE_READ, None,
                              _OPEN_EXISTING, 0, None)
    if not h or h == _INVALID_HANDLE:
        return False
    try:
        hcat = wintypes.HANDLE()
        if not _wintrust.CryptCATAdminAcquireContext(ctypes.byref(hcat), None, 0):
            return False
        try:
            size = wintypes.DWORD(0)
            _wintrust.CryptCATAdminCalcHashFromFileHandle(h, ctypes.byref(size), None, 0)
            if size.value == 0:
                return False
            buf = (ctypes.c_ubyte * size.value)()
            if not _wintrust.CryptCATAdminCalcHashFromFileHandle(h, ctypes.byref(size), buf, 0):
                return False
            info = _wintrust.CryptCATAdminEnumCatalogFromHash(hcat, buf, size.value, 0, None)
            if info:
                _wintrust.CryptCATAdminReleaseCatalogContext(hcat, info, 0)
                return True
            return False
        finally:
            _wintrust.CryptCATAdminReleaseContext(hcat, 0)
    finally:
        _kernel32.CloseHandle(h)


def label(path: str | None) -> str:
    """UI-friendly one-word status for a binary path."""
    state = is_signed(path)
    return "signed" if state is True else "unsigned" if state is False else "unknown"
