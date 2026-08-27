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
"""
from __future__ import annotations

import importlib
import importlib.util
import pkgutil
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from . import logbus
from .settings import config_dir

SRC = "core.plugins"


@dataclass
class PluginContext:
    """Services a plugin may use. Cheap to construct; snapshots are on demand."""
    args: dict = field(default_factory=dict)

    def processes(self):
        from ..forensics import processes
        return processes.snapshot()

    def connections(self, resolve_geo: bool = True):
        from ..network import connections
        return connections.snapshot(resolve_geo=resolve_geo)

    @property
    def report(self):
        from . import report
        return report

    @property
    def log(self):
        return logbus


@dataclass
class Plugin:
    name: str
    description: str
    run: Callable[[PluginContext], str] | None = None   # text tool (headless-safe)
    widget: Callable[[], object] | None = None          # GUI tool (returns a QWidget)
    source: str = ""

    @property
    def kind(self) -> str:
        return "widget" if self.widget else "text"


def plugin(name: str, description: str = "") -> Callable[[Callable], Plugin]:
    """Decorator: wrap ``def fn(ctx) -> str`` as a text Plugin."""
    def deco(fn: Callable[[PluginContext], str]) -> Plugin:
        return Plugin(name=name, description=description, run=fn)
    return deco


def widget_plugin(name: str, description: str = "") -> Callable[[Callable], Plugin]:
    """
    Decorator: wrap ``def factory() -> QWidget`` as a GUI Plugin. Import PyQt6
    *inside* the factory (lazily) so the headless CLI can still discover the
    plugin without pulling in Qt.
    """
    def deco(factory: Callable[[], object]) -> Plugin:
        return Plugin(name=name, description=description, widget=factory)
    return deco


def user_dir() -> Path:
    return config_dir() / "plugins"


def _extract(module, source: str) -> list[Plugin]:
    obj = getattr(module, "PLUGIN", None)
    if obj is None:
        obj = getattr(module, "PLUGINS", None)
    items = obj if isinstance(obj, (list, tuple)) else ([obj] if obj else [])
    out = []
    for p in items:
        if isinstance(p, Plugin) and (callable(p.run) or callable(p.widget)):
            p.source = source
            out.append(p)
    return out


# Static fallback so built-ins still load in a frozen exe, where
# pkgutil.iter_modules over a package can come back empty.
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
        names = _BUILTIN_FALLBACK          # frozen-exe fallback
    for name in names:
        try:
            mod = importlib.import_module(f"aetheris.plugins.{name}")
            out += _extract(mod, f"builtin:{name}")
        except Exception as exc:  # noqa: BLE001
            logbus.warn(SRC, f"failed to load builtin plugin {name}", str(exc))
    return out


def _discover_user(extra_dirs=None) -> list[Plugin]:
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
                out += _extract(mod, str(f))
            except Exception as exc:  # noqa: BLE001
                logbus.warn(SRC, f"failed to load plugin {f.name}", str(exc))
    return out


def discover(extra_dirs=None) -> list[Plugin]:
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
