"""Shell Engineer sub-panels: worker lifecycle and confirm gates.

Runs on any platform: every native/registry call is monkeypatched, so these
exercise only the panel plumbing (aetheris.ui.tabs.shell).
"""
import os
import threading

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QMessageBox  # noqa: E402

from aetheris.core import autoruns, registry, services  # noqa: E402
from aetheris.core.services import ServiceInfo  # noqa: E402
from aetheris.ui.tabs.shell import (  # noqa: E402
    AutorunsPanel,
    PrivacyPanel,
    RegistryDiffPanel,
    ServicesPanel,
)

YES = QMessageBox.StandardButton.Yes
NO = QMessageBox.StandardButton.No


def _answer(monkeypatch, button):
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: button)


def _drain(qtbot, panel, timeout=5000):
    qtbot.waitUntil(lambda: not panel._busy, timeout=timeout)
    if panel._worker is not None:
        panel._worker.wait(timeout)


def _services_panel(qtbot, monkeypatch):
    monkeypatch.setattr(services, "enumerate_services", lambda: [])
    monkeypatch.setattr(services, "enumerate_drivers", lambda: [])
    panel = ServicesPanel()
    qtbot.addWidget(panel)
    panel._services = [ServiceInfo("Spooler", "Print Spooler", "", "", "auto", "service")]
    panel._apply_svc_filter()
    panel.svc_table.selectRow(0)
    return panel


def test_refresh_after_successful_control_is_not_refused(qtbot, monkeypatch):
    # Regression: `done` fires from inside the worker thread, so the result
    # slot's refresh used to see its own still-"running" worker and refuse.
    panel = _services_panel(qtbot, monkeypatch)
    _answer(monkeypatch, YES)
    refreshed = threading.Event()
    monkeypatch.setattr(services, "start_service", lambda name: (True, "started"))
    monkeypatch.setattr(services, "enumerate_services",
                        lambda: refreshed.set() or [])
    errors: list[str] = []
    monkeypatch.setattr(panel, "_toast",
                        lambda ok, msg: None if ok else errors.append(msg))

    panel._svc_control("start")
    qtbot.waitUntil(refreshed.is_set, timeout=5000)
    _drain(qtbot, panel)
    assert not any("already running" in e for e in errors)


def test_second_job_is_refused_without_replacing_worker(qtbot, monkeypatch):
    panel = _services_panel(qtbot, monkeypatch)
    release = threading.Event()
    panel._run(lambda: release.wait(5), lambda _r: None)
    first = panel._worker
    try:
        assert panel._run(lambda: None, lambda _r: None) is False
        assert panel._worker is first
    finally:
        release.set()
        _drain(qtbot, panel)


def test_failure_clears_busy_and_status(qtbot, monkeypatch):
    panel = _services_panel(qtbot, monkeypatch)

    def boom():
        raise OSError("access denied")

    monkeypatch.setattr(services, "enumerate_services", boom)
    panel._refresh_services()
    qtbot.waitUntil(lambda: not panel._busy, timeout=5000)
    assert "failed" in panel.svc_count.text()
    assert panel._run(lambda: None, lambda _r: None) is True
    _drain(qtbot, panel)


def test_privacy_toggle_is_confirm_gated(qtbot, monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(registry, "apply_privacy_toggle",
                        lambda key: calls.append(key) or (True, "ok"))
    panel = PrivacyPanel()
    qtbot.addWidget(panel)
    key = next(iter(registry.PRIVACY_TOGGLES))

    _answer(monkeypatch, NO)
    panel._apply_toggle(key)
    assert calls == [] and not panel._busy

    _answer(monkeypatch, YES)
    panel._apply_toggle(key)
    _drain(qtbot, panel)
    assert calls == [key]


def test_autorun_toggle_is_confirm_gated_and_offloaded(qtbot, monkeypatch):
    entry = autoruns.AutorunEntry("Updater", r"C:\Temp\u.exe", "HKCU Run", "run", True)
    monkeypatch.setattr(autoruns, "enumerate_entries", lambda: [])
    panel = AutorunsPanel()
    qtbot.addWidget(panel)
    _drain(qtbot, panel)
    panel._autoruns = [entry]
    panel.autoruns_table.setRowCount(1)
    panel.autoruns_table.setCurrentCell(0, 0)

    seen: dict[str, str] = {}

    def fake_disable(e):
        seen["thread"] = threading.current_thread().name
        return True, "disabled"

    monkeypatch.setattr(autoruns, "disable", fake_disable)

    _answer(monkeypatch, NO)
    panel._toggle_autorun(False)
    assert "thread" not in seen

    _answer(monkeypatch, YES)
    panel._toggle_autorun(False)
    _drain(qtbot, panel)
    assert seen["thread"] != threading.current_thread().name


def test_toggle_before_enumeration_does_not_crash(qtbot, monkeypatch):
    # Regression: _autoruns was only set by the first refresh callback.
    release = threading.Event()
    monkeypatch.setattr(autoruns, "enumerate_entries",
                        lambda: release.wait(5) and [])
    panel = AutorunsPanel()
    qtbot.addWidget(panel)
    try:
        panel._toggle_autorun(False)  # must not raise AttributeError
    finally:
        release.set()
        _drain(qtbot, panel)


def test_snapshot_history_records_scope_at_capture_time(qtbot, monkeypatch):
    release = threading.Event()
    saved: list[tuple[str, str]] = []
    monkeypatch.setattr(registry, "list_history", lambda: [])
    monkeypatch.setattr(registry, "snapshot_tree",
                        lambda root, sub: release.wait(5) and {"k": {}})
    monkeypatch.setattr(registry, "save_to_history",
                        lambda root, sub, tree: saved.append((root, sub)))
    panel = RegistryDiffPanel()
    qtbot.addWidget(panel)
    panel.root_box.setCurrentText("HKLM")
    panel.subkey.setText("SOFTWARE\\Vendor")
    panel._take_snapshot()
    # The user edits the scope while the snapshot is still running.
    panel.subkey.setText("SYSTEM")
    release.set()
    _drain(qtbot, panel)
    assert saved == [("HKLM", "SOFTWARE\\Vendor")]
    assert panel._before == {"k": {}}
