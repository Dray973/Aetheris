"""
Plugin / extension API.

A minimal, safe surface for custom tools. A plugin is a text-producing command:
given a ``PluginContext`` (live process/connection snapshots + the report and
log helpers), it returns a string. That makes the same plugin usable from the
GUI "Plugins" tab and from the headless CLI, and trivially unit-testable.

Plugins are discovered from two places:
  * built-in — modules under ``aetheris/plugins/`` (imported normally, so they
    work in a frozen exe too);
  * user — ``*.py`` files dropped in ``%APPDATA%\\AetherisQuantumCore\\plugins``
    (loaded by file path).

Each module exposes ``PLUGIN`` (a Plugin) or ``PLUGINS`` (a list). The
``@plugin(name, description)`` decorator turns a ``def fn(ctx) -> str`` into one.

**v2 -- disclosure & provenance (not a sandbox).** A module may declare
``PERMISSIONS`` (a list of scope strings, e.g. ``["reads-processes",
"network"]``) so the gallery can show what a plugin claims to do *before* you run
it. User (file) plugins also carry a ``trust`` status from a hash trust-list:
``untrusted`` until you trust it, then ``trusted`` while the file is unchanged
and ``modified`` if it changes afterwards (tamper-evident). Built-ins are
``built-in``. This is honest disclosure and change-detection -- Python can't
truly sandbox a plugin, so an untrusted plugin is gated behind a confirm, not
prevented from doing what its code does.
"""
from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import os
import pkgutil
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import logbus
from .settings import config_dir

SRC = "core.plugins"

KNOWN_SCOPES = ("reads-processes", "reads-connections", "reads-registry",
                "runs-powershell", "writes-registry", "network", "filesystem")


@dataclass
class PluginContext:
    """Services a plugin may use. Cheap to construct; snapshots are on demand."""
    args: dict[str, Any] = field(default_factory=dict)

    def processes(self) -> list[Any]:
        from ..forensics import processes
        return processes.snapshot()

    def connections(self, resolve_geo: bool = True) -> list[Any]:
        from ..network import connections
        return connections.snapshot(resolve_geo=resolve_geo)

    @property
    def report(self) -> Any:
        from . import report
        return report

    @property
    def log(self) -> Any:
        return logbus


@dataclass
class Plugin:
    name: str
    description: str
    run: Callable[[PluginContext], str] | None = None
    widget: Callable[[], object] | None = None
    source: str = ""
    permissions: list[str] = field(default_factory=list)
    trust: str = "unknown"

    @property
    def kind(self) -> str:
        return "widget" if self.widget else "text"


def plugin(name: str, description: str = "") -> Callable[[Callable[..., Any]], Plugin]:
    """Decorator: wrap ``def fn(ctx) -> str`` as a text Plugin."""
    def deco(fn: Callable[[PluginContext], str]) -> Plugin:
        return Plugin(name=name, description=description, run=fn)
    return deco


def widget_plugin(name: str, description: str = "") -> Callable[[Callable[..., Any]], Plugin]:
    """
    Decorator: wrap ``def factory() -> QWidget`` as a GUI Plugin. Import PySide6
    *inside* the factory (lazily) so the headless CLI can still discover the
    plugin without pulling in Qt.
    """
    def deco(factory: Callable[[], object]) -> Plugin:
        return Plugin(name=name, description=description, widget=factory)
    return deco


def user_dir() -> Path:
    return config_dir() / "plugins"


def _extract(module: Any, source: str, trust: str) -> list[Plugin]:
    perms = getattr(module, "PERMISSIONS", None)
    perms = [str(s) for s in perms] if isinstance(perms, (list, tuple)) else []
    obj = getattr(module, "PLUGIN", None)
    if obj is None:
        obj = getattr(module, "PLUGINS", None)
    items = obj if isinstance(obj, (list, tuple)) else ([obj] if obj else [])
    out = []
    for p in items:
        if isinstance(p, Plugin) and (callable(p.run) or callable(p.widget)):
            p.source = source
            p.trust = trust
            if not p.permissions:
                p.permissions = list(perms)
            out.append(p)
    return out


def _trust_path() -> Path:
    return user_dir() / "trusted.json"


def trusted_hashes() -> dict[str, str]:
    try:
        data = json.loads(_trust_path().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _file_sha256(path: str) -> str:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return ""


def trust_status(source: str) -> str:
    """built-in | trusted | modified | untrusted for a plugin's source."""
    if source.startswith("builtin:"):
        return "built-in"
    name = os.path.basename(source)
    recorded = trusted_hashes().get(name)
    if not recorded:
        return "untrusted"
    return "trusted" if recorded == _file_sha256(source) else "modified"


def trust_file(path: str) -> bool:
    """Record a user plugin's current hash so it verifies as 'trusted'."""
    h = _file_sha256(path)
    if not h:
        return False
    store = trusted_hashes()
    store[os.path.basename(path)] = h
    try:
        _trust_path().parent.mkdir(parents=True, exist_ok=True)
        _trust_path().write_text(json.dumps(store, indent=2), encoding="utf-8")
        logbus.action(SRC, f"trusted plugin {os.path.basename(path)}")
        return True
    except OSError:
        return False


_BUILTIN_FALLBACK = ["top_memory", "public_connections",
                     "listening_ports", "system_gauges"]


def _discover_builtin() -> list[Plugin]:
    out: list[Plugin] = []
    try:
        import aetheris.plugins as pkg
    except Exception:
        return out
    names = [m.name for m in pkgutil.iter_modules(pkg.__path__)
             if not m.name.startswith("_")]
    if not names:
        names = _BUILTIN_FALLBACK
    for name in names:
        try:
            mod = importlib.import_module(f"aetheris.plugins.{name}")
            out += _extract(mod, f"builtin:{name}", "built-in")
        except Exception as exc:  # noqa: BLE001
            logbus.warn(SRC, f"failed to load builtin plugin {name}", str(exc))
    return out


def _discover_user(extra_dirs: list[str] | None = None) -> list[Plugin]:
    out: list[Plugin] = []
    dirs = [user_dir()] + [Path(d) for d in (extra_dirs or [])]
    for d in dirs:
        if not d or not d.is_dir():
            continue
        for f in sorted(d.glob("*.py")):
            if f.name.startswith("_"):
                continue
            try:
                spec = importlib.util.spec_from_file_location(
                    f"aetheris_userplugin_{f.stem}", f)
                if spec is None or spec.loader is None:
                    continue
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                out += _extract(mod, str(f), trust_status(str(f)))
            except Exception as exc:  # noqa: BLE001
                logbus.warn(SRC, f"failed to load plugin {f.name}", str(exc))
    return out


def discover(extra_dirs: list[str] | None = None) -> list[Plugin]:
    """Return all plugins (built-in first, then user; first name wins)."""
    plugins: list[Plugin] = []
    seen: set[str] = set()
    for p in _discover_builtin() + _discover_user(extra_dirs):
        if p.name in seen:
            continue
        seen.add(p.name)
        plugins.append(p)
    logbus.trace(SRC, f"discovered {len(plugins)} plugin(s)")
    return plugins


def run_plugin(name: str, ctx: PluginContext | None = None) -> tuple[bool, str]:
    ctx = ctx or PluginContext()
    for p in discover():
        if p.name == name:
            if p.run is None:
                return False, (f"plugin {name!r} is GUI-only — open it in the "
                               "Plugins tab")
            try:
                return True, p.run(ctx)
            except Exception as exc:  # noqa: BLE001
                return False, f"plugin {name!r} error: {exc}"
    return False, f"no plugin named {name!r}"
