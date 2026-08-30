"""
Service & driver inspector.

Read side: enumerate Windows services (via psutil's SCM view -- live state, start
type, binary path, account) and kernel drivers (from the registry, marked loaded
via the psapi device-driver list), each enriched with Authenticode status. Plus
an **unquoted service path** detector -- a classic local privilege-escalation
misconfiguration where an unquoted ``C:\\Program Files\\...`` path lets an attacker
who can write an earlier path component hijack the service's binary.

The pure helpers (path parsing, start-type mapping, the unquoted-path detector)
carry no OS dependency and are unit-tested off-Windows. Reversible control
(start/stop/start-type) lives in :mod:`aetheris.core.services` write ops.
"""
from __future__ import annotations

import ctypes
import os
import re
import sys
from ctypes import wintypes
from dataclasses import dataclass

from . import logbus, signing

SRC = "core.services"

if sys.platform == "win32":
    import winreg
    _HKLM = winreg.HKEY_LOCAL_MACHINE
else:  # pragma: no cover
    winreg = None  # type: ignore[assignment]
    _HKLM = 0

_SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"
_START_TYPES = {0: "boot", 1: "system", 2: "auto", 3: "manual", 4: "disabled"}
# Service Type bitmask: 0x1 kernel driver, 0x2 fs driver, 0x10/0x20 win32 service.
_DRIVER_TYPES = (0x1, 0x2)


@dataclass
class ServiceInfo:
    name: str
    display_name: str
    image_path: str            # raw ImagePath / binpath
    binary: str                # parsed, resolved executable path
    start_type: str            # boot/system/auto/manual/disabled/unknown
    kind: str                  # "service" | "driver"
    account: str = ""          # ObjectName (LocalSystem, ...)
    state: str = "unknown"     # running/stopped/loaded/... (best effort)
    signed: str = "unknown"    # signed/unsigned/unknown
    unquoted_path: bool = False


# -- pure helpers (no OS dependency) ---------------------------------------
def parse_binary(image_path: str) -> str:
    """Extract the executable path from a raw ImagePath (drops arguments)."""
    p = (image_path or "").strip()
    if not p:
        return ""
    if p.startswith('"'):
        end = p.find('"', 1)
        return p[1:end] if end != -1 else p[1:]
    low = p.lower()
    for ext in (".exe", ".sys"):
        idx = low.find(ext)
        if idx != -1:
            return p[:idx + 4]
    return p.split(" ", 1)[0]


def resolve_path(binary: str) -> str:
    """Normalize a service/driver binary path to an absolute filesystem path."""
    b = (binary or "").strip().strip('"')
    if not b:
        return ""
    low = b.lower()
    root = os.environ.get("SystemRoot", r"C:\Windows")
    if low.startswith("\\systemroot\\"):
        b = os.path.join(root, b[len("\\systemroot\\"):])
    elif low.startswith("\\??\\"):
        b = b[4:]
    elif low.startswith("system32\\") or low.startswith("systemroot\\"):
        b = os.path.join(root, b)
    return os.path.expandvars(b)


def start_type_label(value: int) -> str:
    return _START_TYPES.get(value, "unknown")


def has_unquoted_path_vuln(image_path: str, kind: str) -> bool:
    """True if this is a win32 service whose ImagePath is unquoted and whose
    executable path contains a space -- the classic unquoted-service-path issue.

    (Reports the candidate; it does not check directory ACLs, so treat a hit as
    "worth investigating" rather than "definitely exploitable".)"""
    if kind != "service":
        return False                       # drivers load by a different mechanism
    p = (image_path or "").strip()
    if not p or p.startswith('"'):
        return False                       # quoted path is safe
    low = p.lower()
    idx = low.find(".exe")
    if idx == -1:
        return False
    exe_path = p[:idx + 4]
    if " " not in exe_path:
        return False                       # no space in the executable path
    return bool(re.match(r"^[a-zA-Z]:\\", exe_path))   # a real drive-letter path


# -- enumeration (Windows) --------------------------------------------------
def _loaded_driver_basenames() -> set[str]:
    """Base names of currently-loaded kernel drivers (psapi), best effort."""
    names: set[str] = set()
    try:
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        psapi.EnumDeviceDrivers.argtypes = [ctypes.c_void_p, wintypes.DWORD,
                                            ctypes.POINTER(wintypes.DWORD)]
        psapi.EnumDeviceDrivers.restype = wintypes.BOOL
        psapi.GetDeviceDriverBaseNameW.argtypes = [ctypes.c_void_p, wintypes.LPWSTR,
                                                   wintypes.DWORD]
        psapi.GetDeviceDriverBaseNameW.restype = wintypes.DWORD
        arr = (ctypes.c_void_p * 2048)()
        needed = wintypes.DWORD()
        if not psapi.EnumDeviceDrivers(arr, ctypes.sizeof(arr), ctypes.byref(needed)):
            return names
        count = min(needed.value // ctypes.sizeof(ctypes.c_void_p), 2048)
        buf = ctypes.create_unicode_buffer(260)
        for i in range(count):
            if psapi.GetDeviceDriverBaseNameW(arr[i], buf, 260):
                names.add(buf.value.lower())
    except OSError:  # pragma: no cover
        pass
    return names


def enumerate_services(check_signature: bool = True) -> list[ServiceInfo]:
    """Enumerate win32 services via the SCM (live state, start type, account)."""
    import psutil
    out: list[ServiceInfo] = []
    for svc in psutil.win_service_iter():
        try:
            info = svc.as_dict()
        except Exception:  # noqa: BLE001 - a service can vanish mid-iteration
            continue
        raw = info.get("binpath") or ""
        binary = resolve_path(parse_binary(raw))
        rec = ServiceInfo(
            name=info.get("name", ""), display_name=info.get("display_name", ""),
            image_path=raw, binary=binary,
            start_type=(info.get("start_type") or "unknown"),
            kind="service", account=info.get("username") or "",
            state=(info.get("status") or "unknown"),
            unquoted_path=has_unquoted_path_vuln(raw, "service"))
        if check_signature and binary:
            rec.signed = signing.label(binary)
        out.append(rec)
    logbus.trace(SRC, f"enumerated {len(out)} services")
    return out


def enumerate_drivers(check_signature: bool = True) -> list[ServiceInfo]:
    """Enumerate kernel/fs drivers from the registry, marking loaded ones."""
    if winreg is None:
        return []
    loaded = _loaded_driver_basenames()
    out: list[ServiceInfo] = []
    try:
        root_key = winreg.OpenKey(_HKLM, _SERVICES_KEY)
    except OSError:
        return []
    try:
        i = 0
        while True:
            try:
                name = winreg.EnumKey(root_key, i)
                i += 1
            except OSError:
                break
            vals = _read_service_values(root_key, name)
            if vals is None:
                continue
            stype, start, image, display, account = vals
            if stype not in _DRIVER_TYPES:
                continue
            binary = resolve_path(parse_binary(image))
            base = os.path.basename(binary).lower()
            rec = ServiceInfo(
                name=name, display_name=display or name, image_path=image,
                binary=binary, start_type=start_type_label(start), kind="driver",
                account=account, state=("loaded" if base in loaded else "not loaded"))
            if check_signature and binary:
                rec.signed = signing.label(binary)
            out.append(rec)
    finally:
        winreg.CloseKey(root_key)
    logbus.trace(SRC, f"enumerated {len(out)} drivers")
    return out


def _read_service_values(root_key, name: str):
    """Return (Type, Start, ImagePath, DisplayName, ObjectName) or None."""
    try:
        k = winreg.OpenKey(root_key, name)
    except OSError:
        return None
    try:
        def _val(n, default):
            try:
                return winreg.QueryValueEx(k, n)[0]
            except OSError:
                return default
        stype = int(_val("Type", -1))
        start = int(_val("Start", -1))
        image = str(_val("ImagePath", "") or "")
        display = str(_val("DisplayName", "") or "")
        account = str(_val("ObjectName", "") or "")
        return stype, start, image, display, account
    finally:
        winreg.CloseKey(k)


def unquoted_path_issues(services: list[ServiceInfo]) -> list[ServiceInfo]:
    """Filter a service list to those with the unquoted-service-path issue."""
    return [s for s in services if s.unquoted_path]
