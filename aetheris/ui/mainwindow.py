"""
Aetheris main window.

Assembles the five module workspaces as tabs, docks the live audit console at
the bottom, and wires the master PANIC control (toolbar button + Ctrl+Shift+Esc
hotkey) to the Omega Rollback ledger.
"""
from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import Qt, QByteArray
from PyQt6.QtGui import QKeySequence, QShortcut, QAction, QIcon
from PyQt6.QtWidgets import (
    QMainWindow, QTabWidget, QDockWidget, QToolBar, QLabel, QMessageBox,
    QWidget, QPlainTextEdit, QVBoxLayout, QFileDialog,
)

ICON_PATH = Path(__file__).resolve().parent / "assets" / "aetheris.ico"

from .. import __version__
from ..core import safety, logbus, privileges, report
from ..core.settings import settings
from .logdrawer import LogDrawer
from .theme import QSS
from .tabs.memory_tab import MemoryTab
from .tabs.storage_tab import StorageTab
from .tabs.network_tab import NetworkTab
from .tabs.shell_tab import ShellTab
from .tabs.autoshell_tab import AutoShellTab
from .tabs.plugins_tab import PluginsTab


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Aetheris Quantum Core — Advanced Systems Instrumentation Suite")
        self.resize(1400, 900)
        if ICON_PATH.exists():
            self.setWindowIcon(QIcon(str(ICON_PATH)))
        self.setStyleSheet(QSS)
        self._build_toolbar()
        self._build_tabs()
        self._build_logdrawer()
        self._install_panic_hotkey()
        self._announce_environment()
        self._restore_settings()
        self._auto_check_updates()

    # -- persistence --------------------------------------------------------
    def _restore_settings(self) -> None:
        s = settings()
        geo = s.get("window_geometry")
        if geo:
            try:
                self.restoreGeometry(QByteArray.fromBase64(geo.encode("ascii")))
            except Exception:
                pass
        idx = s.get("active_tab", 0)
        if isinstance(idx, int) and 0 <= idx < self.tabs.count():
            self.tabs.setCurrentIndex(idx)

    def closeEvent(self, event) -> None:
        s = settings()
        try:
            s.set("window_geometry",
                  bytes(self.saveGeometry().toBase64()).decode("ascii"))
            s.set("active_tab", self.tabs.currentIndex())
            s.save()
        except Exception:
            pass
        # Stop the ETW/EStats bandwidth sampler cleanly.
        try:
            sampler = getattr(self.tabs.widget(2), "_ppbw", None)
            if sampler and hasattr(sampler, "stop"):
                sampler.stop()
        except Exception:
            pass
        super().closeEvent(event)

    def _build_toolbar(self) -> None:
        tb = QToolBar("Main")
        tb.setMovable(False)
        self.addToolBar(tb)

        self.env_lbl = QLabel("  Aetheris Quantum Core   ")
        self.env_lbl.setObjectName("title")
        tb.addWidget(self.env_lbl)

        spacer = QWidget()
        spacer.setSizePolicy(spacer.sizePolicy().horizontalPolicy().Expanding,
                             spacer.sizePolicy().verticalPolicy().Preferred)
        tb.addWidget(spacer)

        self.pending_lbl = QLabel("rollback queue: 0  ")
        self.pending_lbl.setObjectName("subtle")
        tb.addWidget(self.pending_lbl)

        report_action = QAction("⭳  Export report", self)
        report_action.triggered.connect(self.export_session_report)
        tb.addAction(report_action)

        schedule_action = QAction("⏱  Schedule…", self)
        schedule_action.triggered.connect(self.open_schedule_dialog)
        tb.addAction(schedule_action)

        updates_action = QAction("⟳  Updates", self)
        updates_action.triggered.connect(self.check_for_updates)
        tb.addAction(updates_action)

        panic_action = QAction("⛔  PANIC / UNDO", self)
        panic_action.triggered.connect(self.trigger_panic)
        tb.addAction(panic_action)
        # Style the generated button as the red panic control.
        for w in tb.findChildren(QWidget):
            if w.__class__.__name__ == "QToolButton" and "PANIC" in w.text():
                w.setObjectName("panic")

    def open_schedule_dialog(self) -> None:
        from .schedule_dialog import ScheduleDialog
        ScheduleDialog(self).exec()

    # -- auto-update --------------------------------------------------------
    def _auto_check_updates(self) -> None:
        """Background check on startup; stages a newer version if configured."""
        from ..core import updater
        from .workers import Worker
        if updater.has_pending():
            logbus.log("ui.main",
                       f"update {updater.pending_version()} staged — applies on "
                       "next launch", logbus.Level.SUCCESS)
            return
        if not (settings().get("update_auto_check", True)
                and updater.effective_update_url()):
            return
        self._upd_worker = Worker(updater.check_and_stage)
        self._upd_worker.done.connect(lambda r: logbus.log(
            "ui.main", r[1], logbus.Level.SUCCESS if r[0] else logbus.Level.TRACE))
        self._upd_worker.start()

    def check_for_updates(self) -> None:
        from ..core import updater
        url = updater.effective_update_url()
        if not url:
            from PyQt6.QtWidgets import QInputDialog
            url, ok = QInputDialog.getText(
                self, "Update source",
                "Update source (github:owner/repo, or a version.json https:// / file:// URL):")
            if not ok or not url.strip():
                return
            settings().set("update_url", url.strip())
            settings().save()
            url = url.strip()
        if updater.has_pending():
            QMessageBox.information(
                self, "Updates",
                f"Update {updater.pending_version()} is staged and will be "
                "applied the next time you launch Aetheris.")
            return
        info = updater.check(url)
        if info is None:
            QMessageBox.information(self, "Updates",
                                    f"You're up to date (v{__version__}).")
            return
        detail = f"\n\n{info.notes}" if info.notes else ""
        if QMessageBox.question(
            self, "Update available",
            f"Version {info.version} is available (you have {__version__})."
            f"{detail}\n\nDownload it now? It will be applied on next launch.",
        ) != QMessageBox.StandardButton.Yes:
            return
        ok, msg = updater.stage(info)
        (QMessageBox.information if ok else QMessageBox.warning)(self, "Updates", msg)

    # -- session report -----------------------------------------------------
    def export_session_report(self) -> None:
        from ..forensics import processes
        from ..network import connections
        path, _ = QFileDialog.getSaveFileName(
            self, "Export session report", "aetheris-session-report.html",
            "HTML (*.html);;Markdown (*.md)")
        if not path:
            return
        procs = processes.snapshot()
        conns = connections.snapshot(resolve_geo=True)
        try:
            if path.lower().endswith(".md"):
                content = report.session_markdown(procs, conns)
            else:
                content = report.session_html(procs, conns)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
            logbus.success("ui.main", f"session report exported: {path}")
        except Exception as exc:  # noqa: BLE001
            logbus.error("ui.main", f"report export failed: {exc}")

    def _build_tabs(self) -> None:
        self.tabs = QTabWidget()
        self.tabs.addTab(MemoryTab(), "①  Memory / Process Autopsy")
        self.tabs.addTab(StorageTab(), "②  Storage Surgery / MFT")
        self.tabs.addTab(NetworkTab(), "③  Network / Firewall")
        self.tabs.addTab(ShellTab(), "④  Shell Engineer / Registry")
        self.tabs.addTab(AutoShellTab(), "⑤  Auto-Shell (NL)")
        self.tabs.addTab(PluginsTab(), "⚙  Plugins")
        self.setCentralWidget(self.tabs)

    def _build_logdrawer(self) -> None:
        dock = QDockWidget("Live API Audit Console", self)
        dock.setAllowedAreas(Qt.DockWidgetArea.BottomDockWidgetArea)
        dock.setFeatures(QDockWidget.DockWidgetFeature.DockWidgetMovable |
                         QDockWidget.DockWidgetFeature.DockWidgetFloatable)
        dock.setWidget(LogDrawer())
        dock.setMinimumHeight(190)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, dock)

        # Keep the toolbar rollback-queue counter live.
        logbus.subscribe(lambda _ev: self.pending_lbl.setText(
            f"rollback queue: {len(safety.ledger.pending())}  "))

    def _install_panic_hotkey(self) -> None:
        sc = QShortcut(QKeySequence("Ctrl+Shift+Esc"), self)
        sc.activated.connect(self.trigger_panic)

    def _announce_environment(self) -> None:
        elevated = privileges.is_elevated()
        self.env_lbl.setText(
            f"  Aetheris Quantum Core   [{'ELEVATED' if elevated else 'standard rights'}]  ")
        logbus.log("ui.main",
                   f"Session started ({'elevated' if elevated else 'not elevated'}).",
                   logbus.Level.INFO)
        if elevated:
            for name, ok, msg in privileges.enable_forensics_privileges():
                logbus.log("core.privileges", msg,
                           logbus.Level.SUCCESS if ok else logbus.Level.WARN)
        else:
            logbus.warn("ui.main",
                        "Not elevated — memory, MFT, and firewall features are limited.")

    # -- panic --------------------------------------------------------------
    def trigger_panic(self) -> None:
        pending = safety.ledger.pending()
        if not pending:
            logbus.log("ui.main", "PANIC pressed — rollback queue already empty.")
            QMessageBox.information(self, "PANIC / UNDO",
                                    "Nothing to roll back — the session made no tracked changes.")
            return
        if QMessageBox.critical(
            self, "PANIC / UNDO",
            f"Roll back {len(pending)} tracked change(s) now?\n\n- "
            + "\n- ".join(pending[:20])
            + ("\n…" if len(pending) > 20 else ""),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        results = safety.ledger.panic()
        ok = sum(1 for _l, good, _m in results if good)
        self._show_panic_report(results)
        logbus.log("ui.main", f"PANIC complete: {ok}/{len(results)} reverted",
                   logbus.Level.SUCCESS if ok == len(results) else logbus.Level.WARN)

    def _show_panic_report(self, results) -> None:
        dlg = QDockWidget  # noqa: F841  (placeholder to keep import obvious)
        box = QWidget()
        v = QVBoxLayout(box)
        v.addWidget(QLabel("PANIC rollback report", objectName="title"))
        out = QPlainTextEdit(readOnly=True)
        out.setPlainText("\n".join(
            f"[{'OK ' if good else 'FAIL'}] {label}: {msg}" for label, good, msg in results))
        v.addWidget(out)
        box.setWindowTitle("PANIC rollback report")
        box.resize(640, 360)
        box.setStyleSheet(QSS)
        box.show()
        self._panic_report = box  # keep a reference so it isn't GC'd
