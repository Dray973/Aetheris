"""GUI-thread offloading: destructive/slow native calls must run on a Worker,
not block the event loop.

Each test monkeypatches the native call to an Event-gated blocker, fires the
slot, and asserts (a) the slot returns while the native call is still blocked,
(b) the native call ran on a *worker* thread (not the GUI thread), and (c) the
result is delivered via the Worker's ``done`` signal. Windows-only because the
tabs import the native (ctypes) layers at construction.
"""
import os
import sys
import threading

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")   # headless, before any Qt import

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="native tabs are Windows-only")


def _assert_offloaded(qtbot, tab, fire, patch_target, attr, monkeypatch, result):
    """Patch <patch_target>.<attr> to a blocker, fire the slot, and prove the
    call was pushed onto a Worker instead of running on the GUI thread."""
    entered = threading.Event()
    release = threading.Event()
    seen: dict[str, str] = {}

    def blocker(*_a, **_k):
        seen["thread"] = threading.current_thread().name
        entered.set()
        release.wait(timeout=5)          # hold the "native" call open
        return result

    monkeypatch.setattr(patch_target, attr, blocker)
    gui_thread = threading.current_thread().name

    # Fully drain any construction-time refresh worker before firing: the tabs
    # share one _worker slot, so a slow initial refresh (MemoryTab signs every
    # process on load) would make the slot under test bail with "a task is
    # already running". Poll to completion rather than a single fixed wait.
    waited = 0
    while tab._worker is not None and tab._worker.isRunning() and waited < 60000:
        tab._worker.wait(1000)
        waited += 1000
    fire()                               # the slot under test -- must return at once
    worker = tab._worker                 # the Worker the slot just started (captured now)
    try:
        # Generous budget: this only bounds QThread start-up latency (which can
        # spike under load). The real proof of offloading is the thread check
        # below -- an inline (un-offloaded) call would run on the GUI thread.
        assert entered.wait(5.0), "native call never started on a worker"
        assert seen["thread"] != gui_thread, "native call ran on the GUI thread"
        # The slot must have pushed the work onto a fresh Worker (not run inline
        # nor reused a finished one). isRunning() is deliberately not asserted:
        # it races the blocker and adds nothing the thread check hasn't proven.
        assert worker is not None and worker is tab._worker
        with qtbot.waitSignal(worker.done, timeout=5000):
            release.set()                # release inside the wait so we don't miss done
    finally:
        release.set()
        if tab._worker is not None:
            tab._worker.wait(6000)       # let the thread finish before teardown


def test_strip_handles_offloaded(qtbot, monkeypatch, tmp_path):
    from PyQt6.QtWidgets import QMessageBox

    from aetheris.storage import unlock
    from aetheris.ui.tabs.storage_tab import StorageTab

    f = tmp_path / "target.bin"
    f.write_bytes(b"x")
    tab = StorageTab()
    qtbot.addWidget(tab)
    tab.oblit_path.setText(str(f))
    monkeypatch.setattr(QMessageBox, "warning",
                        lambda *a, **k: QMessageBox.StandardButton.Yes)

    _assert_offloaded(qtbot, tab, tab._strip_handles, unlock, "strip_handles",
                      monkeypatch, result=[(4321, 0xABCD, True, "closed")])


def test_disable_diagtrack_offloaded(qtbot, monkeypatch):
    from PyQt6.QtWidgets import QMessageBox

    from aetheris.core import registry
    from aetheris.ui.tabs.shell_tab import ShellTab

    tab = ShellTab()
    qtbot.addWidget(tab)
    monkeypatch.setattr(QMessageBox, "question",
                        lambda *a, **k: QMessageBox.StandardButton.Yes)

    _assert_offloaded(qtbot, tab, tab._disable_diagtrack, registry,
                      "disable_diagtrack_service", monkeypatch, result=(True, "disabled"))


def test_trim_working_sets_offloaded(qtbot, monkeypatch):
    from PyQt6.QtWidgets import QMessageBox

    from aetheris.forensics import memory
    from aetheris.ui.tabs.memory_tab import MemoryTab

    tab = MemoryTab()
    qtbot.addWidget(tab)
    tab._timer.stop()                    # no 4 s auto-refresh during the test
    tab._tele_timer.stop()
    monkeypatch.setattr(QMessageBox, "question",
                        lambda *a, **k: QMessageBox.StandardButton.Yes)

    _assert_offloaded(qtbot, tab, tab._trim_all, memory, "empty_all_working_sets",
                      monkeypatch, result=(3, 5))


def test_service_control_offloaded(qtbot, monkeypatch):
    from PyQt6.QtWidgets import QMessageBox

    from aetheris.core import services
    from aetheris.core.services import ServiceInfo
    from aetheris.ui.tabs.shell_tab import ShellTab

    tab = ShellTab()
    qtbot.addWidget(tab)
    tab._services = [ServiceInfo("Spooler", "Print Spooler", "", "", "auto", "service")]
    tab._apply_svc_filter()
    tab.svc_table.selectRow(0)
    monkeypatch.setattr(QMessageBox, "question",
                        lambda *a, **k: QMessageBox.StandardButton.Yes)

    _assert_offloaded(qtbot, tab, lambda: tab._svc_control("start"), services,
                      "start_service", monkeypatch, result=(True, "started"))


def test_task_control_offloaded(qtbot, monkeypatch):
    from PyQt6.QtWidgets import QMessageBox

    from aetheris.core import taskaudit
    from aetheris.core.taskaudit import TaskInfo
    from aetheris.ui.tabs.shell_tab import ShellTab

    tab = ShellTab()
    qtbot.addWidget(tab)
    tab._tasks = [TaskInfo(r"\Evil", "Evil", "", "", True, False,
                           ["logon"], ["x.exe"], ["x.exe"])]
    tab._apply_task_filter()
    tab.task_table.selectRow(0)
    monkeypatch.setattr(QMessageBox, "question",
                        lambda *a, **k: QMessageBox.StandardButton.Yes)

    _assert_offloaded(qtbot, tab, lambda: tab._task_control(False), taskaudit,
                      "disable_task", monkeypatch, result=(True, "disabled"))


def test_persistence_control_offloaded(qtbot, monkeypatch):
    from PyQt6.QtWidgets import QMessageBox

    from aetheris.core import persistence
    from aetheris.core.persistence import PersistenceEntry
    from aetheris.ui.tabs.shell_tab import ShellTab

    tab = ShellTab()
    qtbot.addWidget(tab)
    tab._pm = [PersistenceEntry("Service", "Spooler", "svc", "Service (auto)", ref="Spooler")]
    tab._apply_pm_filter()
    tab.pm_table.selectRow(0)
    monkeypatch.setattr(QMessageBox, "question",
                        lambda *a, **k: QMessageBox.StandardButton.Yes)

    _assert_offloaded(qtbot, tab, lambda: tab._pm_control(False), persistence,
                      "set_enabled", monkeypatch, result=(True, "disabled"))


def test_timeline_capture_offloaded(qtbot, monkeypatch):
    from aetheris.core import timeline
    from aetheris.ui.tabs.timeline_tab import TimelineTab

    tab = TimelineTab()
    qtbot.addWidget(tab)
    _assert_offloaded(qtbot, tab, tab._capture, timeline, "capture",
                      monkeypatch, result=timeline.Snapshot(seq=0, ts=0.0))


def test_untrusted_plugin_run_is_gated(qtbot, monkeypatch):
    from PyQt6.QtWidgets import QMessageBox

    from aetheris.core.plugins import Plugin
    from aetheris.ui.tabs.plugins_tab import PluginsTab

    tab = PluginsTab()
    qtbot.addWidget(tab)
    tab._plugins = [Plugin(name="evil", description="d", run=lambda ctx: "x",
                           source="C:/x/evil.py", trust="untrusted",
                           permissions=["writes-registry"])]
    tab.list.clear()
    tab.list.addItem("evil")
    tab.list.setCurrentRow(0)
    monkeypatch.setattr(QMessageBox, "warning",
                        lambda *a, **k: QMessageBox.StandardButton.No)   # decline
    tab._run()
    assert tab._worker is None or not tab._worker.isRunning()   # never started
