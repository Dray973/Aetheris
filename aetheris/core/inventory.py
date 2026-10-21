"""
Software inventory: everything installed, and what changed since last time.

Reads the three Windows uninstall locations every tool uses -- the 64-bit and
32-bit ``...\\Uninstall`` keys under HKLM and the per-user one under HKCU -- plus
the publisher signature of each app's install location when it can be found.
The point beyond "what's installed" is the **diff**: save an inventory now,
compare a later one, and see exactly what was added, removed or version-bumped.
That pairs with the hunt baseline idea -- unexpected new software between two
points is worth a look.

The registry-row parsing, dedupe and diff are pure and tested; :func:`collect`
is the impure part that walks the registry (and returns [] off Windows).
"""
from __future__ import annotations

import json
import os
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ADDED, REMOVED, CHANGED = "added", "removed", "changed"


@dataclass(frozen=True)
class InstalledApp:
    name: str
    version: str = ""
    publisher: str = ""
    install_date: str = ""     # YYYYMMDD as Windows records it
    location: str = ""
    source: str = ""           # HKLM / HKLM-WOW6432 / HKCU
    signature: str = "unchecked"

    @property
    def key(self) -> str:
        """Identity for diffing: name + publisher, case-folded."""
        return f"{self.name.strip().lower()}\x00{self.publisher.strip().lower()}"

    def pretty_date(self) -> str:
        d = self.install_date
        if len(d) == 8 and d.isdigit():
            return f"{d[:4]}-{d[4:6]}-{d[6:]}"
        return d


@dataclass
class Change:
    kind: str
    app: InstalledApp
    old_version: str = ""


def parse_row(values: dict[str, object], source: str) -> InstalledApp | None:
    """Turn one uninstall subkey's values into an InstalledApp.

    Returns None for the entries that aren't user-facing apps: no DisplayName,
    or a system component / update (SystemComponent=1, or a ``WindowsInstaller``
    patch), which is what every inventory tool filters out.
    """
    name = str(values.get("DisplayName", "")).strip()
    if not name:
        return None
    if _truthy(values.get("SystemComponent")):
        return None
    if _truthy(values.get("WindowsInstaller")) and not values.get("DisplayVersion"):
        return None  # an MSI patch/component, not a listed program
    if str(values.get("ParentKeyName", "")) or str(values.get("ParentDisplayName", "")):
        return None  # a sub-entry of another product (e.g. an update)
    return InstalledApp(
        name=name,
        version=str(values.get("DisplayVersion", "")).strip(),
        publisher=str(values.get("Publisher", "")).strip(),
        install_date=str(values.get("InstallDate", "")).strip(),
        location=str(values.get("InstallLocation", "")).strip(),
        source=source,
    )


def _truthy(v: object) -> bool:
    return str(v).strip() in ("1", "True", "true")


def dedupe(apps: Iterable[InstalledApp]) -> list[InstalledApp]:
    """Collapse the same app seen under several hives; sort by name.

    Windows lists the same product under both the WOW6432 and native views, and
    a per-machine app can also appear per-user. Keep the first seen (HLKM views
    are walked first) and prefer one that carries a version."""
    best: dict[str, InstalledApp] = {}
    for app in apps:
        cur = best.get(app.key)
        if cur is None or (not cur.version and app.version):
            best[app.key] = app
    return sorted(best.values(), key=lambda a: (a.name.lower(), a.publisher.lower()))


def diff(old: Iterable[InstalledApp], new: Iterable[InstalledApp]) -> list[Change]:
    """What changed from ``old`` to ``new``: added, removed, version-changed."""
    old_by = {a.key: a for a in old}
    new_by = {a.key: a for a in new}
    changes: list[Change] = []
    for key, app in new_by.items():
        if key not in old_by:
            changes.append(Change(ADDED, app))
        elif old_by[key].version != app.version:
            changes.append(Change(CHANGED, app, old_version=old_by[key].version))
    for key, app in old_by.items():
        if key not in new_by:
            changes.append(Change(REMOVED, app))
    changes.sort(key=lambda c: (c.kind, c.app.name.lower()))
    return changes


# --- persistence (for change-over-time) ------------------------------------


def default_path() -> Path:
    from .settings import config_dir
    return config_dir() / "inventory-snapshot.json"


def save(apps: Iterable[InstalledApp], path: str | os.PathLike[str] | None = None) -> None:
    p = Path(path) if path else default_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps([asdict(a) for a in apps], indent=2), encoding="utf-8")
    os.replace(tmp, p)


def load(path: str | os.PathLike[str] | None = None) -> list[InstalledApp]:
    p = Path(path) if path else default_path()
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    out: list[InstalledApp] = []
    for r in raw:
        if isinstance(r, dict) and r.get("name"):
            out.append(InstalledApp(**{k: r[k] for k in r if k in _FIELDS}))
    return out


_FIELDS = {f for f in InstalledApp.__dataclass_fields__}


# --- impure collection -----------------------------------------------------

_UNINSTALL = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
_UNINSTALL_WOW = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
_VALUE_NAMES = ("DisplayName", "DisplayVersion", "Publisher", "InstallDate",
                "InstallLocation", "SystemComponent", "WindowsInstaller",
                "ParentKeyName", "ParentDisplayName")


@dataclass
class Inventory:
    apps: list[InstalledApp] = field(default_factory=list)
    changes: list[Change] = field(default_factory=list)   # vs the saved snapshot


def collect(sign: bool = True) -> list[InstalledApp]:
    """Walk the uninstall keys. Returns [] off Windows."""
    import sys
    if sys.platform != "win32":
        return []
    import winreg

    from . import signing

    hives = [(winreg.HKEY_LOCAL_MACHINE, _UNINSTALL, "HKLM"),
             (winreg.HKEY_LOCAL_MACHINE, _UNINSTALL_WOW, "HKLM-WOW6432"),
             (winreg.HKEY_CURRENT_USER, _UNINSTALL, "HKCU")]
    found: list[InstalledApp] = []
    for hive, path, label in hives:
        found.extend(_walk_uninstall(winreg, hive, path, label))
    apps = dedupe(found)
    if sign:
        apps = [_sign(a, signing) for a in apps]
    return apps


def _walk_uninstall(winreg: Any, hive: int, path: str, label: str) -> list[InstalledApp]:
    out: list[InstalledApp] = []
    try:
        root = winreg.OpenKey(hive, path)
    except OSError:
        return out
    try:
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(root, i)
            except OSError:
                break
            i += 1
            values = _read_values(winreg, hive, path + "\\" + sub)
            app = parse_row(values, label)
            if app is not None:
                out.append(app)
    finally:
        winreg.CloseKey(root)
    return out


def _read_values(winreg: Any, hive: int, path: str) -> dict[str, object]:
    out: dict[str, object] = {}
    try:
        key = winreg.OpenKey(hive, path)
    except OSError:
        return out
    try:
        for name in _VALUE_NAMES:
            try:
                out[name] = winreg.QueryValueEx(key, name)[0]
            except OSError:
                continue
    finally:
        winreg.CloseKey(key)
    return out


def _sign(app: InstalledApp, signing: Any) -> InstalledApp:
    """Fill the publisher-signature of the app's main binary, if locatable."""
    import ntpath
    loc = app.location
    if not loc or not os.path.isdir(loc):
        return app
    exe = next((os.path.join(loc, f) for f in _safe_listdir(loc)
                if f.lower().endswith(".exe") and ntpath.splitext(f)[0].lower()
                in app.name.lower().replace(" ", "")), "")
    if not exe:
        return app
    try:
        from dataclasses import replace
        return replace(app, signature=signing.label(exe))
    except Exception:  # noqa: BLE001
        return app


def _safe_listdir(path: str) -> list[str]:
    try:
        return os.listdir(path)
    except OSError:
        return []
