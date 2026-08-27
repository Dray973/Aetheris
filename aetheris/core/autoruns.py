"""
Autoruns manager (Sysinternals-Autoruns style).

Enumerates what launches at logon/boot — the Run / RunOnce registry keys (HKCU
+ HKLM) and the per-user / common Startup folders — and can reversibly disable
or re-enable each entry:

  * registry entries are moved to a backup key
    (HKCU\\Software\\Aetheris\\DisabledAutoruns) and removed from Run; re-enabling
    restores them to their original location;
  * Startup-folder shortcuts are renamed to ``<name>.disabled`` and back.

Every disable registers an undo with the Omega Rollback ledger.
"""
from __future__ import annotations

import os
import sys
import json
from dataclasses import dataclass

from . import logbus
from . import safety

SRC = "core.autoruns"

if sys.platform == "win32":
    import winreg
    HKCU = winreg.HKEY_CURRENT_USER
    HKLM = winreg.HKEY_LOCAL_MACHINE
    _HIVES = {"HKCU": HKCU, "HKLM": HKLM}
else:  # pragma: no cover
    winreg = None
    _HIVES = {}

_RUN_KEYS = [
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
]
_BACKUP_KEY = r"Software\Aetheris\DisabledAutoruns"


@dataclass
class AutorunEntry:
    name: str
    command: str
    location: str          # human-readable source
    kind: str              # "registry" | "folder"
    enabled: bool
    root: str = ""         # registry: HKCU/HKLM
    subkey: str = ""       # registry: original Run subkey
    path: str = ""         # folder: shortcut path


def _startup_dirs() -> list[tuple[str, str]]:
    dirs = []
    appdata = os.environ.get("APPDATA")
    if appdata:
        dirs.append(("user", os.path.join(
            appdata, r"Microsoft\Windows\Start Menu\Programs\Startup")))
    common = os.environ.get("ProgramData")
    if common:
        dirs.append(("common", os.path.join(
            common, r"Microsoft\Windows\Start Menu\Programs\Startup")))
    return dirs


def _read_run_values(root: str, subkey: str) -> list[tuple[str, str]]:
    hive = _HIVES.get(root)
    if hive is None:
        return []
    out = []
    try:
        key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
    except OSError:
        return []
    try:
        i = 0
        while True:
            try:
                name, data, _t = winreg.EnumValue(key, i)
                out.append((name, str(data)))
                i += 1
            except OSError:
                break
    finally:
        winreg.CloseKey(key)
    return out


def _disabled_backups() -> list[AutorunEntry]:
    """Entries we previously disabled (stored in the backup key)."""
    if winreg is None:
        return []
    out = []
    try:
        key = winreg.OpenKey(HKCU, _BACKUP_KEY, 0, winreg.KEY_READ)
    except OSError:
        return []
    try:
        i = 0
        while True:
            try:
                name, data, _t = winreg.EnumValue(key, i)
                meta = json.loads(data)
                out.append(AutorunEntry(
                    name=meta.get("name", name), command=meta.get("command", ""),
                    location=f"{meta.get('root')}\\{meta.get('subkey')} (disabled)",
                    kind="registry", enabled=False,
                    root=meta.get("root", ""), subkey=meta.get("subkey", "")))
                i += 1
            except OSError:
                break
    finally:
        winreg.CloseKey(key)
    return out


def enumerate_entries() -> list[AutorunEntry]:
    """Return all autostart entries (enabled + previously-disabled)."""
    entries: list[AutorunEntry] = []
    for root, subkey in _RUN_KEYS:
        for name, cmd in _read_run_values(root, subkey):
            entries.append(AutorunEntry(name, cmd, f"{root}\\{subkey}",
                                        "registry", True, root=root, subkey=subkey))
    for scope, d in _startup_dirs():
        if not os.path.isdir(d):
            continue
        for fn in os.listdir(d):
            full = os.path.join(d, fn)
            if not os.path.isfile(full):
                continue
            enabled = not fn.lower().endswith(".disabled")
            display = fn[:-9] if not enabled else fn
            entries.append(AutorunEntry(display, full,
                                        f"Startup folder ({scope})", "folder",
                                        enabled, path=full))
    entries += _disabled_backups()
    logbus.trace(SRC, f"enumerated {len(entries)} autorun entries")
    return entries


def disable(entry: AutorunEntry) -> tuple[bool, str]:
    if winreg is None:
        return False, "Windows only"
    if not entry.enabled:
        return False, "already disabled"
    if entry.kind == "folder":
        try:
            new = entry.path + ".disabled"
            os.replace(entry.path, new)
            safety.ledger.register(f"autorun: {entry.name}",
                                   lambda p=entry.path, n=new: os.replace(n, p))
            logbus.action(SRC, f"disabled startup item: {entry.name}")
            return True, f"disabled {entry.name}"
        except OSError as exc:
            return False, str(exc)
    # registry: back up then remove from Run
    try:
        bk = winreg.CreateKeyEx(HKCU, _BACKUP_KEY, 0, winreg.KEY_SET_VALUE)
        meta = json.dumps({"name": entry.name, "command": entry.command,
                           "root": entry.root, "subkey": entry.subkey})
        winreg.SetValueEx(bk, entry.name, 0, winreg.REG_SZ, meta)
        winreg.CloseKey(bk)
        rk = winreg.OpenKey(_HIVES[entry.root], entry.subkey, 0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(rk, entry.name)
        winreg.CloseKey(rk)
        safety.ledger.register(f"autorun: {entry.name}", lambda e=entry: _restore(e))
        logbus.action(SRC, f"disabled autorun: {entry.name}", entry.location)
        return True, f"disabled {entry.name}"
    except OSError as exc:
        return False, str(exc)


def _restore(entry: AutorunEntry) -> None:
    rk = winreg.CreateKeyEx(_HIVES[entry.root], entry.subkey, 0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(rk, entry.name, 0, winreg.REG_SZ, entry.command)
    winreg.CloseKey(rk)
    try:
        bk = winreg.OpenKey(HKCU, _BACKUP_KEY, 0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(bk, entry.name)
        winreg.CloseKey(bk)
    except OSError:
        pass


def enable(entry: AutorunEntry) -> tuple[bool, str]:
    if winreg is None:
        return False, "Windows only"
    if entry.enabled:
        return False, "already enabled"
    if entry.kind == "folder":
        try:
            original = entry.path[:-9] if entry.path.endswith(".disabled") else entry.path
            os.replace(entry.path, original)
            logbus.action(SRC, f"enabled startup item: {entry.name}")
            return True, f"enabled {entry.name}"
        except OSError as exc:
            return False, str(exc)
    try:
        _restore(entry)
        logbus.action(SRC, f"enabled autorun: {entry.name}", entry.location)
        return True, f"enabled {entry.name}"
    except OSError as exc:
        return False, str(exc)
