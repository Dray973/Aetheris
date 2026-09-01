"""
Registry engineering primitives (Module 4 backend).

  * Differential tracker: snapshot_tree() captures a key subtree; diff_trees()
    computes Added / Modified / Removed and renders Markdown — the Regshot-style
    "snapshot → run installer → analyze" workflow.
  * Privacy toggles: each toggle reads and stores the prior value, applies the
    change, and registers an undo with the Omega Rollback ledger so PANIC (or an
    explicit revert) restores the original state.
  * Context-menu editor: read/add/remove HKCR shell handlers.

All writes go through winreg; every mutation is logged to the audit console and
is reversible for the session.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import dryrun, logbus, safety

SRC = "core.registry"

if sys.platform == "win32":
    import winreg
    _HIVES = {
        "HKCR": winreg.HKEY_CLASSES_ROOT,
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKU": winreg.HKEY_USERS,
    }
else:  # pragma: no cover
    winreg = None  # type: ignore
    _HIVES = {}


def snapshot_tree(root: str, subkey: str, max_depth: int = 6) -> dict[str, dict[str, Any]]:
    """
    Recursively capture value state as {key_path: {value_name: (data, type)}}.
    """
    if winreg is None:
        return {}
    hive = _HIVES.get(root.upper())
    if hive is None:
        raise ValueError(f"unknown root {root!r}")
    out: dict[str, dict[str, Any]] = {}

    def walk(path: str, depth: int) -> None:
        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
        except OSError:
            return
        try:
            values: dict[str, Any] = {}
            i = 0
            while True:
                try:
                    name, data, vtype = winreg.EnumValue(key, i)
                    values[name] = (repr(data), vtype)
                    i += 1
                except OSError:
                    break
            out[f"{root}\\{path}"] = values
            if depth < max_depth:
                j = 0
                while True:
                    try:
                        sub = winreg.EnumKey(key, j)
                        walk(f"{path}\\{sub}" if path else sub, depth + 1)
                        j += 1
                    except OSError:
                        break
        finally:
            winreg.CloseKey(key)

    walk(subkey, 0)
    logbus.trace(SRC, f"snapshot {root}\\{subkey}: {len(out)} keys")
    return out


@dataclass
class RegDiff:
    added: dict[str, Any]
    modified: dict[str, tuple[Any, Any]]
    removed: dict[str, Any]

    def to_markdown(self) -> str:
        lines = ["# Registry Differential Report", ""]
        lines.append(f"- **Added:** {len(self.added)}  ")
        lines.append(f"- **Modified:** {len(self.modified)}  ")
        lines.append(f"- **Removed:** {len(self.removed)}")
        lines.append("")
        if self.added:
            lines.append("## Added")
            for k, v in sorted(self.added.items()):
                lines.append(f"- `{k}` = {v}")
            lines.append("")
        if self.modified:
            lines.append("## Modified")
            for k, (before, after) in sorted(self.modified.items()):
                lines.append(f"- `{k}`\n    - before: {before}\n    - after: {after}")
            lines.append("")
        if self.removed:
            lines.append("## Removed")
            for k, v in sorted(self.removed.items()):
                lines.append(f"- `{k}` = {v}")
            lines.append("")
        if not (self.added or self.modified or self.removed):
            lines.append("_No changes detected._")
        return "\n".join(lines)

    def rows(self) -> list[tuple[str, str, str, str]]:
        """Flat (change, key, before, after) rows for a structured viewer."""
        out: list[tuple[str, str, str, str]] = []
        for k, v in sorted(self.added.items()):
            out.append(("Added", k, "", str(v)))
        for k, (b, a) in sorted(self.modified.items()):
            out.append(("Modified", k, str(b), str(a)))
        for k, v in sorted(self.removed.items()):
            out.append(("Removed", k, str(v), ""))
        return out


def diff_trees(before: dict[str, dict[str, Any]],
               after: dict[str, dict[str, Any]]) -> RegDiff:
    """Flatten both snapshots to key\\value granularity and diff."""
    def flatten(tree: dict[str, dict[str, Any]]) -> dict[str, Any]:
        flat: dict[str, Any] = {}
        for key, values in tree.items():
            for vname, vdata in values.items():
                flat[f"{key}::{vname or '(default)'}"] = (
                    tuple(vdata) if isinstance(vdata, list) else vdata)
        return flat

    fb, fa = flatten(before), flatten(after)
    added = {k: fa[k] for k in fa.keys() - fb.keys()}
    removed = {k: fb[k] for k in fb.keys() - fa.keys()}
    modified = {k: (fb[k], fa[k]) for k in fb.keys() & fa.keys() if fb[k] != fa[k]}
    logbus.trace(SRC, f"diff: +{len(added)} ~{len(modified)} -{len(removed)}")
    return RegDiff(added, modified, removed)


def save_snapshot(tree: dict[str, Any], path: str) -> tuple[bool, str]:
    """Persist a snapshot_tree() result to a JSON file for offline diffing."""
    import json
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(tree, fh, indent=2, default=str)
        logbus.action(SRC, f"registry snapshot saved: {path}", f"{len(tree)} keys")
        return True, f"saved {len(tree)} keys to {path}"
    except OSError as exc:
        return False, str(exc)


def load_snapshot(path: str) -> dict[str, Any]:
    """Load a snapshot previously written by save_snapshot()."""
    import json
    with open(path, encoding="utf-8") as fh:
        data: dict[str, Any] = json.load(fh)
        return data


@dataclass
class HistoryEntry:
    path: str
    timestamp: str
    root: str
    subkey: str
    keys: int
    label: str = ""

    def display(self) -> str:
        lbl = f"  [{self.label}]" if self.label else ""
        return f"{self.timestamp}  {self.root}\\{self.subkey}  ({self.keys} keys){lbl}"


def history_dir() -> Path:
    from .settings import config_dir
    return config_dir() / "snapshots"


def save_to_history(root: str, subkey: str, tree: dict[str, Any],
                    label: str = "") -> HistoryEntry:
    """Write a timestamped snapshot into the managed history store."""
    import json
    import re
    import time
    d = history_dir()
    d.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9]+", "-", subkey).strip("-")[:40] or "root"
    path = d / f"{root}_{safe}_{ts}.json"
    meta = {"root": root, "subkey": subkey, "timestamp": ts,
            "keys": len(tree), "label": label}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"meta": meta, "tree": tree}, fh, indent=2, default=str)
    logbus.action(SRC, "snapshot saved to history", str(path))
    return HistoryEntry(str(path), ts, root, subkey, len(tree), label)


def list_history() -> list[HistoryEntry]:
    """Return history entries, newest first."""
    import json
    d = history_dir()
    if not d.is_dir():
        return []
    out: list[HistoryEntry] = []
    for f in sorted(d.glob("*.json"), reverse=True):
        try:
            with open(f, encoding="utf-8") as fh:
                meta = json.load(fh).get("meta", {})
            out.append(HistoryEntry(str(f), meta.get("timestamp", ""),
                                    meta.get("root", ""), meta.get("subkey", ""),
                                    int(meta.get("keys", 0)), meta.get("label", "")))
        except Exception:
            continue
    return out


def load_history(path: str) -> dict[str, Any]:
    """Return the snapshot tree from a history entry file."""
    import json
    with open(path, encoding="utf-8") as fh:
        tree: dict[str, Any] = json.load(fh).get("tree", {})
        return tree


def _read_value(root: str, subkey: str, name: str) -> Any:
    hive = _HIVES[root.upper()]
    try:
        key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
        try:
            return winreg.QueryValueEx(key, name)
        finally:
            winreg.CloseKey(key)
    except OSError:
        return None


def set_value(root: str, subkey: str, name: str, data: Any,
              vtype: int | None = None) -> tuple[bool, str]:
    """Set a value, recording the prior state for rollback."""
    if winreg is None:
        return False, "Windows only"
    if dryrun.skip(SRC, f"set {root}\\{subkey}\\{name} = {data}"):
        return True, "[dry-run] not applied"
    hive = _HIVES[root.upper()]
    vtype = vtype or winreg.REG_DWORD
    prior = _read_value(root, subkey, name)
    try:
        key = winreg.CreateKeyEx(hive, subkey, 0, winreg.KEY_SET_VALUE)
        try:
            winreg.SetValueEx(key, name, 0, vtype, data)
        finally:
            winreg.CloseKey(key)
    except OSError as exc:
        return False, str(exc)

    def undo(prior: Any = prior, root: str = root, subkey: str = subkey,
             name: str = name) -> None:
        if prior is None:
            try:
                key = winreg.OpenKey(_HIVES[root.upper()], subkey, 0, winreg.KEY_SET_VALUE)
                winreg.DeleteValue(key, name)
                winreg.CloseKey(key)
            except OSError:
                pass
        else:
            set_value(root, subkey, name, prior[0], prior[1])

    safety.ledger.register(f"registry {root}\\{subkey}\\{name}", undo)
    logbus.action(SRC, f"set {root}\\{subkey}\\{name} = {data}")
    return True, "value set"


PRIVACY_TOGGLES = {
    "telemetry": ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
                  "AllowTelemetry", 0, "Disable Windows telemetry (AllowTelemetry=0)"),
    "bing_search": ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Search",
                    "BingSearchEnabled", 0, "Disable Start-menu web/Bing search"),
    "cortana": ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\Windows Search",
                "AllowCortana", 0, "Disable Cortana"),
    "advertising_id": ("HKLM",
                       r"SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo",
                       "DisabledByGroupPolicy", 1, "Disable advertising ID"),
}


def apply_privacy_toggle(key: str) -> tuple[bool, str]:
    if key not in PRIVACY_TOGGLES:
        return False, f"unknown toggle {key!r}"
    root, subkey, name, data, label = PRIVACY_TOGGLES[key]
    ok, msg = set_value(root, subkey, name, data, winreg.REG_DWORD)
    return ok, f"{label}: {msg}"


def disable_diagtrack_service() -> tuple[bool, str]:
    """Stop + disable the DiagTrack (Connected User Experiences) service."""
    if dryrun.skip(SRC, "stop + disable the DiagTrack service"):
        return True, "[dry-run] would stop + disable DiagTrack"
    import subprocess
    try:
        subprocess.run(["sc", "stop", "DiagTrack"], capture_output=True, text=True, timeout=30)
        r = subprocess.run(["sc", "config", "DiagTrack", "start=", "disabled"],
                           capture_output=True, text=True, timeout=30)
        ok = r.returncode == 0
        if ok:
            logbus.action(SRC, "DiagTrack service disabled")

            def _reenable() -> None:
                subprocess.run(["sc", "config", "DiagTrack", "start=", "auto"],
                               capture_output=True, text=True)

            safety.ledger.register("DiagTrack service", _reenable)
        return ok, (r.stdout or r.stderr).strip()
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def read_context_handlers(scope: str = r"*\shellex\ContextMenuHandlers") -> list[str]:
    if winreg is None:
        return []
    handlers: list[str] = []
    try:
        key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, scope, 0, winreg.KEY_READ)
        i = 0
        while True:
            try:
                handlers.append(winreg.EnumKey(key, i))
                i += 1
            except OSError:
                break
        winreg.CloseKey(key)
    except OSError:
        pass
    return handlers


def add_context_command(label: str, command: str,
                        target: str = r"Directory\Background") -> tuple[bool, str]:
    """
    Add a right-click command under HKCR\\<target>\\shell\\<label>.
    Registers rollback so the whole key is removed on PANIC/revert.
    """
    if winreg is None:
        return False, "Windows only"
    if dryrun.skip(SRC, f"add context command {label!r} under {target}", command):
        return True, f"[dry-run] would add context command {label!r}"
    base = fr"{target}\shell\{label}"
    try:
        k = winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, base)
        winreg.SetValue(k, "command", winreg.REG_SZ, command)
        winreg.CloseKey(k)
        logbus.action(SRC, fr"added context command HKCR\{base}", command)

        def undo(base: str = base) -> None:
            try:
                winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, base + r"\command")
                winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, base)
            except OSError:
                pass

        safety.ledger.register(fr"context menu: {label}", undo)
        return True, f"added '{label}' to {target} context menu"
    except OSError as exc:
        return False, str(exc)


@dataclass
class MenuItem:
    label: str
    command: str | None = None
    children: list[MenuItem] = field(default_factory=list)

    @property
    def is_branch(self) -> bool:
        return bool(self.children)


def parse_menu_spec(text: str) -> list[MenuItem]:
    """
    Parse an indented plain-text menu spec into a MenuItem tree (pure; testable).

    Two-space indentation marks nesting; ``label | command`` is a leaf, a bare
    ``label`` with indented children is a submenu::

        Tools
          Open PowerShell here | powershell.exe -NoExit -Command "cd '%V'"
          Hashing
            SHA-256 this file | powershell.exe -Command "Get-FileHash '%1'"
    """
    roots: list[MenuItem] = []
    stack: list[tuple[int, MenuItem]] = []
    for raw in text.splitlines():
        if not raw.strip():
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        depth = indent // 2
        label, _, command = raw.strip().partition("|")
        item = MenuItem(label.strip(), command.strip() or None)
        while stack and stack[-1][0] >= depth:
            stack.pop()
        if stack:
            stack[-1][1].children.append(item)
        else:
            roots.append(item)
        stack.append((depth, item))
    return roots


def _sanitize(name: str) -> str:
    return "".join(c for c in name if c.isalnum() or c in "._-") or "Menu"


def _delete_tree(hive: Any, path: str) -> None:
    """Recursively delete a registry key and all its subkeys."""
    try:
        k = winreg.OpenKey(hive, path, 0, winreg.KEY_ALL_ACCESS)
    except OSError:
        return
    try:
        while True:
            try:
                sub = winreg.EnumKey(k, 0)
            except OSError:
                break
            _delete_tree(hive, path + "\\" + sub)
    finally:
        winreg.CloseKey(k)
    try:
        winreg.DeleteKey(hive, path)
    except OSError:
        pass


def add_cascading_menu(top_label: str, items: list[MenuItem],
                       target: str = r"Directory\Background",
                       key_name: str | None = None) -> tuple[bool, str]:
    """
    Build a multi-level cascading submenu under ``target`` using the shell's
    ExtendedSubCommandsKey mechanism (per-user, no admin). Registers rollback so
    PANIC removes the whole tree.
    """
    if winreg is None:
        return False, "Windows only"
    if not items:
        return False, "no menu items"
    if dryrun.skip(SRC, f"add cascading menu {top_label!r} ({len(items)} items) under {target}"):
        return True, f"[dry-run] would add cascading menu {top_label!r}"
    key_name = _sanitize(key_name or ("Aetheris." + top_label))
    store_roots: list[str] = [key_name]

    def mk(subpath: str, values: dict[str, str]) -> None:
        full = r"Software\Classes\\" + subpath
        k = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, full, 0, winreg.KEY_SET_VALUE)
        try:
            for name, data in values.items():
                winreg.SetValueEx(k, name, 0, winreg.REG_SZ, data)
        finally:
            winreg.CloseKey(k)

    def build(store: str, nodes: list[MenuItem]) -> None:
        for idx, node in enumerate(nodes):
            base = fr"{store}\shell\{idx:02d}"
            if node.is_branch:
                child_store = f"{store}.{idx:02d}"
                store_roots.append(child_store)
                mk(base, {"MUIVerb": node.label, "ExtendedSubCommandsKey": child_store})
                build(child_store, node.children)
            else:
                mk(base, {"MUIVerb": node.label})
                mk(fr"{base}\command", {"": node.command or ""})

    top_sub = fr"{target}\shell\{key_name}"
    try:
        mk(top_sub, {"MUIVerb": top_label, "ExtendedSubCommandsKey": key_name})
        build(key_name, items)
    except OSError as exc:
        return False, str(exc)

    def undo(top_sub: str = top_sub, roots: list[str] = list(store_roots)) -> None:
        _delete_tree(winreg.HKEY_CURRENT_USER, r"Software\Classes\\" + top_sub)
        for r in roots:
            _delete_tree(winreg.HKEY_CURRENT_USER, r"Software\Classes\\" + r)

    safety.ledger.register(f"cascading menu: {top_label}", undo)
    logbus.action(SRC, f"added cascading menu '{top_label}' to {target}",
                  f"{len(items)} top-level item(s)")
    return True, f"added cascading menu '{top_label}' ({len(store_roots)} keys)"
