"""
API Monitor — inject an agent to observe a process's Win32 calls.

Injects the native agent DLL (``forensics/apimonitor.py`` + ``agent/``) into a
user-chosen, non-critical process and streams the calls it observes
(CreateFileW, LoadLibraryW, VirtualAlloc, WriteProcessMemory) into a live table.
Attach is confirmed, audited, dry-run-aware, and refuses system-critical
processes; the agent only observes (it forwards every call unchanged). Events
cross from the pipe-reader thread to the GUI via a queued signal. Authorized use
only.
"""
from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...core import dryrun, logbus
from ...forensics import apimonitor, processes
from ..workers import Worker

SRC = "ui.apimonitor"
MAX_ROWS = 5000

# API → row tint, so injection-/spawn-/network-relevant calls stand out.
_API_COLOR = {
    "WriteProcessMemory": "#ff8a80",
    "CreateProcessW": "#ff8a80",
    "VirtualAlloc": "#e0b341",
    "connect": "#5ee0a0",
    "LoadLibraryW": "#7dd3fc",
    "CreateFileW": "#9fb0e0",
}


class ApiMonitorTab(QWidget):
    _event = Signal(object)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._session: apimonitor.AgentSession | None = None
        self._worker: Worker | None = None
        self._count = 0
        self._filter = ""
        self._build()
        self._event.connect(self._on_event)
        self._refresh_processes()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.addWidget(QLabel("API Monitor — Observe a Process's Win32 Calls",
                              objectName="title"))
        root.addWidget(QLabel(
            "Inject an in-process agent to watch a target's API calls (file, "
            "library, memory). The agent only observes — it never alters a call. "
            "Authorized use only.", objectName="subtle"))

        bar = QHBoxLayout()
        self.proc = QComboBox()
        self.proc.setMinimumWidth(360)
        bar.addWidget(self.proc, 1)
        refresh = QPushButton("↻")
        refresh.setMaximumWidth(36)
        refresh.clicked.connect(self._refresh_processes)
        bar.addWidget(refresh)
        self.attach_btn = QPushButton("Attach")
        self.attach_btn.clicked.connect(self._attach)
        bar.addWidget(self.attach_btn)
        self.detach_btn = QPushButton("Detach")
        self.detach_btn.clicked.connect(self._detach)
        self.detach_btn.setEnabled(False)
        bar.addWidget(self.detach_btn)
        root.addLayout(bar)

        self.status = QLabel("Not attached.", objectName="subtle")
        root.addWidget(self.status)

        tools = QHBoxLayout()
        tools.addWidget(QLabel("Filter:"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("substring of API or details…")
        self.filter_edit.setMaximumWidth(280)
        self.filter_edit.textChanged.connect(self._on_filter)
        tools.addWidget(self.filter_edit)
        tools.addStretch(1)
        self.counter = QLabel("0 events", objectName="subtle")
        tools.addWidget(self.counter)
        clear = QPushButton("Clear")
        clear.clicked.connect(self._clear)
        tools.addWidget(clear)
        root.addLayout(tools)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["#", "Thread", "API", "Details"])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        root.addWidget(self.table, 1)

        self._update_enabled()

    # -- helpers ------------------------------------------------------------
    def _busy(self) -> bool:
        return bool(self._worker and self._worker.isRunning())

    def _attached(self) -> bool:
        return self._session is not None

    def _update_enabled(self) -> None:
        att = self._attached()
        self.attach_btn.setEnabled(not att and not self._busy())
        self.detach_btn.setEnabled(att)
        self.proc.setEnabled(not att)

    def _refresh_processes(self) -> None:
        if self._busy() or self._attached():
            return
        self._worker = Worker(processes.snapshot)
        self._worker.done.connect(self._fill_processes)
        self._worker.start()

    def _fill_processes(self, procs) -> None:
        cur = self.proc.currentData()
        self.proc.clear()
        for p in sorted(procs, key=lambda p: (p.name or "").lower()):
            ok, _ = apimonitor.can_monitor(p.name or "")
            if not ok:
                continue
            self.proc.addItem(f"{p.pid:>6}  {p.name}", p.pid)
        idx = self.proc.findData(cur)
        if idx >= 0:
            self.proc.setCurrentIndex(idx)

    # -- attach / detach ----------------------------------------------------
    def _attach(self) -> None:
        if self._attached() or self._busy():
            return
        pid = self.proc.currentData()
        if pid is None:
            return
        parts = self.proc.currentText().split(None, 1)
        name = parts[1].strip() if len(parts) > 1 else str(pid)
        rehearse = dryrun.enabled()
        prefix = "[DRY-RUN] " if rehearse else ""
        if QMessageBox.warning(
            self, "Attach API monitor",
            f"{prefix}Inject the monitoring agent into {name} (pid {pid})?\n\n"
            "The agent observes the target's API calls and streams them here; it "
            "does not alter any call. Detach un-hooks it. Only monitor a process "
            "you're authorized to inspect."
            + ("\n\nDry-run is ON: the agent will not be injected."
               if rehearse else "\n\nThis action is audited."),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        self._session = apimonitor.AgentSession(pid, name)
        self.status.setText(f"attaching to {name} (pid {pid})…")
        self._update_enabled()
        self._worker = Worker(self._session.start, self._event.emit, rehearse)
        self._worker.done.connect(self._on_attached)
        self._worker.failed.connect(lambda e: self._on_attached((False, str(e))))
        self._worker.start()

    def _on_attached(self, result) -> None:
        ok, msg = result
        self.status.setText(msg)
        if not ok:
            self._session = None
        self._update_enabled()

    def _detach(self) -> None:
        if not self._session:
            return
        sess, self._session = self._session, None
        self.status.setText("detaching…")
        self._update_enabled()
        self._worker = Worker(sess.stop)
        self._worker.done.connect(lambda _: self.status.setText("detached."))
        self._worker.start()

    # -- events -------------------------------------------------------------
    def _on_filter(self, text: str) -> None:
        self._filter = text.strip().lower()
        for r in range(self.table.rowCount()):
            self.table.setRowHidden(r, not self._row_matches(r))

    def _row_matches(self, row: int) -> bool:
        if not self._filter:
            return True
        api = self.table.item(row, 2)
        det = self.table.item(row, 3)
        hay = f"{api.text() if api else ''} {det.text() if det else ''}".lower()
        return self._filter in hay

    def _clear(self) -> None:
        self.table.setRowCount(0)
        self._count = 0
        self.counter.setText("0 events")

    def _on_event(self, ev) -> None:
        if ev.api == "__ready__":
            self.status.setText(f"monitoring {self._session.name if self._session else ''} — "
                                f"{ev.fields.get('hooks', 0)} hook(s) installed")
            logbus.action(SRC, f"API monitor ready ({ev.fields.get('hooks', 0)} hooks)")
            return
        if ev.api == "__closed__":
            self.status.setText("target exited — monitor stopped")
            self._session = None
            self._update_enabled()
            return

        self._count += 1
        self.counter.setText(f"{self._count} events")
        at_bottom = self.table.verticalScrollBar().value() >= \
            self.table.verticalScrollBar().maximum() - 4

        details = ev.describe()
        if details.startswith(ev.api):
            details = details[len(ev.api):].strip()
        vals = [str(self._count), str(ev.tid), ev.api, details]
        color = _API_COLOR.get(ev.api)
        row = self.table.rowCount()
        self.table.insertRow(row)
        for c, text in enumerate(vals):
            item = QTableWidgetItem(text)
            if c == 2 and color:
                item.setForeground(QColor(color))
            self.table.setItem(row, c, item)
        if self._filter:
            self.table.setRowHidden(row, not self._row_matches(row))

        if self.table.rowCount() > MAX_ROWS:
            self.table.removeRow(0)
        if at_bottom:
            self.table.scrollToBottom()
