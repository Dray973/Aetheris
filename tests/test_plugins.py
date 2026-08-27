"""Plugin discovery + execution API."""
from aetheris.core import plugins
from aetheris.core.plugins import plugin, Plugin, PluginContext


def test_builtin_plugins_discovered():
    names = {p.name for p in plugins.discover()}
    assert {"top-memory", "public-connections", "listening-ports"} <= names


def test_plugin_decorator_wraps_function():
    p = plugin("x", "desc")(lambda ctx: "hello")
    assert isinstance(p, Plugin)
    assert p.name == "x" and p.description == "desc"
    assert p.run(PluginContext()) == "hello"


def test_run_plugin_returns_text():
    ok, out = plugins.run_plugin("top-memory")
    assert ok and "Top processes by memory" in out


def test_run_unknown_plugin_is_graceful():
    ok, out = plugins.run_plugin("does-not-exist")
    assert not ok and "no plugin" in out


def test_run_plugin_catches_errors(monkeypatch):
    boom = Plugin("boom", "raises", lambda ctx: (_ for _ in ()).throw(ValueError("x")))
    monkeypatch.setattr(plugins, "discover", lambda extra_dirs=None: [boom])
    ok, out = plugins.run_plugin("boom")
    assert not ok and "error" in out


def test_widget_plugin_discovered_with_kind():
    ps = {p.name: p for p in plugins.discover()}
    assert "system-gauges" in ps
    assert ps["system-gauges"].kind == "widget"
    assert ps["system-gauges"].run is None      # GUI-only


def test_gui_only_plugin_run_is_graceful():
    ok, out = plugins.run_plugin("system-gauges")
    assert not ok and "GUI-only" in out


def test_widget_plugin_decorator():
    from aetheris.core.plugins import widget_plugin
    p = widget_plugin("w", "d")(lambda: object())
    assert p.kind == "widget" and p.run is None and callable(p.widget)
