"""
Module 1 — Live Memory Forensics & Process Autopsy.

Process table (psutil-backed, auto-refresh), the System RAM Matrix release
controls, and an Assembly Studio panel that reads a process's memory and
disassembles it with Capstone. Every action routes through the confirmation
dialogs and the audit log.
"""
from __future__ import annotations

import psutil
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ...core import logbus, report
from ...forensics import disasm, memory, processes
from ..telemetry import TelemetryChart
from ..workers import Worker
from .memvirt_tab import MemVirtWidget


def _fmt_mb(b: int) -> str:
    return f"{b / (1024*1024):,.1f}"


class MemoryTab(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._rows: list[processes.ProcessInfo] = []
        self._worker: Worker | None = None
        self._build()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh)
        self._timer.start(4000)
        # Telemetry sampled on its own faster cadence; the chart renders smoothly
        # between samples while psutil is polled cheaply (non-blocking).
        self._tele_timer = QTimer(self)
        self._tele_timer.timeout.connect(self._sample_telemetry)
        self._tele_timer.start(500)
        psutil.cpu_percent(interval=None)   # prime the first (0.0) reading
        self.refresh()

    def _sample_telemetry(self) -> None:
        self.telemetry.push({
            "cpu": psutil.cpu_percent(interval=None),
            "ram": psutil.virtual_memory().percent,
        })

    # -- layout -------------------------------------------------------------
    def _build(self) -> None:
        outer = QVBoxLayout(self)
        outer.addWidget(QLabel("Live Memory Forensics & Process Autopsy", objectName="title"))
        sub = QTabWidget()
        sub.addTab(self._autopsy_page(), "Process Autopsy & Assembly Studio")
        sub.addTab(MemVirtWidget(), "Virtual Memory Scanner")
        outer.addWidget(sub)

    def _autopsy_page(self) -> QWidget:
        page = QWidget()
        root = QVBoxLayout(page)

        self.telemetry = TelemetryChart(
            series=[("cpu", "CPU %", "#7dd3fc"), ("ram", "RAM %", "#5ee0a0")],
            window=240, y_label="%", y_range=(0, 100),
        )
        self.telemetry.setMaximumHeight(140)
        root.addWidget(self.telemetry)

        matrix = QHBoxLayout()
        matrix.addWidget(QLabel("System RAM Matrix:", objectName="subtle"))
        for label, slot in (
            ("Trim all working sets", self._trim_all),
            ("Purge standby list", self._purge_standby),
            ("Flush file cache", self._flush_cache),
        ):
            b = QPushButton(label)
            b.clicked.connect(slot)
            matrix.addWidget(b)
        matrix.addStretch(1)
        self.filter = QLineEdit(placeholderText="filter by name…")
        self.filter.textChanged.connect(self._apply_filter)
        matrix.addWidget(self.filter)
        root.addLayout(matrix)

        split = QSplitter(Qt.Orientation.Vertical)

        self.table = QTableWidget(0, 9)
        self.table.setHorizontalHeaderLabels(
            ["PID", "Name", "User", "CPU %", "Mem (MB)", "Threads", "Status",
             "Signed", "Exe"]
        )
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setSectionResizeMode(8, QHeaderView.ResizeMode.Stretch)
        self.table.doubleClicked.connect(self._open_autopsy)
        split.addWidget(self.table)

        autopsy = QWidget()
        av = QVBoxLayout(autopsy)
        row = QHBoxLayout()
        row.addWidget(QLabel("Assembly Studio — read @"))
        self.addr = QLineEdit("0x", maximumWidth=180)
        row.addWidget(self.addr)
        row.addWidget(QLabel("bytes"))
        self.nbytes = QSpinBox()
        self.nbytes.setRange(16, 4096)
        self.nbytes.setValue(128)
        row.addWidget(self.nbytes)
        dbtn = QPushButton("Disassemble selected process")
        dbtn.clicked.connect(self._disassemble)
        row.addWidget(dbtn)
        pbtn = QPushButton("Patch memory…")
        pbtn.clicked.connect(self._patch)
        row.addWidget(pbtn)
        row.addStretch(1)
        av.addLayout(row)
        self.disasm_view = QPlainTextEdit(readOnly=True)
        self.disasm_view.setPlaceholderText(
            "Double-click a process, enter a hex address, and disassemble.\n"
            + ("Capstone available." if disasm.engines_available()["capstone"]
               else "Install 'capstone' to enable disassembly.")
        )
        av.addWidget(self.disasm_view)
        split.addWidget(autopsy)
        split.setSizes([500, 220])
        root.addWidget(split)

        actions = QHBoxLayout()
        for label, slot in (
            ("Refresh", self.refresh),
            ("Terminate", self._terminate),
            ("Set affinity…", self._affinity),
            ("Export…", self._export),
        ):
            b = QPushButton(label)
            b.clicked.connect(slot)
            actions.addWidget(b)
        actions.addStretch(1)
        self.count_lbl = QLabel("", objectName="subtle")
        actions.addWidget(self.count_lbl)
        root.addLayout(actions)
        return page

    # -- data ---------------------------------------------------------------
    def refresh(self) -> None:
        if self._worker and self._worker.isRunning():
            return
        self._worker = Worker(processes.snapshot, sign=True)
        self._worker.done.connect(self._populate)
        self._worker.start()

    def _populate(self, rows) -> None:
        self._rows = sorted(rows, key=lambda r: r.mem_rss, reverse=True)
        self._apply_filter()

    def _apply_filter(self) -> None:
        needle = self.filter.text().lower().strip()
        shown = [r for r in self._rows if needle in r.name.lower()] if needle else self._rows
        self.table.setRowCount(len(shown))
        for i, r in enumerate(shown):
            vals = [str(r.pid), r.name, r.username, f"{r.cpu_percent:.1f}",
                    _fmt_mb(r.mem_rss), str(r.num_threads), r.status, r.signature, r.exe]
            for c, v in enumerate(vals):
                item = QTableWidgetItem(v)
                if c in (0, 3, 4, 5):
                    item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                if c == 7 and r.signature == "unsigned":       # flag unsigned images
                    item.setForeground(QColor("#e0b341"))
                self.table.setItem(i, c, item)
        self.count_lbl.setText(f"{len(shown)} / {len(self._rows)} processes")

    def _selected_pid(self) -> int | None:
        row = self.table.currentRow()
        if row < 0 or self.table.item(row, 0) is None:
            return None
        return int(self.table.item(row, 0).text())

    # -- process actions ----------------------------------------------------
    def _terminate(self) -> None:
        pid = self._selected_pid()
        if pid is None:
            return
        name = self.table.item(self.table.currentRow(), 1).text()
        if QMessageBox.question(self, "Terminate", f"Terminate {name} (pid {pid})?") \
                != QMessageBox.StandardButton.Yes:
            return
        ok, msg = processes.kill(pid)
        self._toast(ok, msg)
        self.refresh()

    def _affinity(self) -> None:
        pid = self._selected_pid()
        if pid is None:
            return
        text, ok = QInputDialog.getText(self, "CPU Affinity",
                                        "Comma-separated core indices (e.g. 4,5,6):")
        if not ok or not text.strip():
            return
        try:
            cores = [int(x) for x in text.replace(" ", "").split(",") if x != ""]
        except ValueError:
            self._toast(False, "invalid core list")
            return
        good, msg = processes.set_affinity(pid, cores)
        self._toast(good, msg)

    def _open_autopsy(self) -> None:
        pid = self._selected_pid()
        if pid is not None:
            self.addr.setFocus()
            logbus.trace("ui.memory", f"autopsy opened for pid {pid}")

    # -- RAM matrix ---------------------------------------------------------
    def _confirm(self, title: str, text: str) -> bool:
        return QMessageBox.question(self, title, text) == QMessageBox.StandardButton.Yes

    def _trim_all(self) -> None:
        if not self._confirm("Trim working sets",
                             "Trim EVERY accessible process working set? "
                             "(reversible; causes a brief latency spike)"):
            return
        self._run(memory.empty_all_working_sets, self._show_trim)   # walks all procs

    def _show_trim(self, res) -> None:
        ok, attempted = res
        self._toast(True, f"trimmed {ok}/{attempted} processes")

    def _purge_standby(self) -> None:
        if not self._confirm("Purge standby list",
                             "Purge the system-wide standby page list?"):
            return
        ok, msg = memory.purge_standby_list()
        self._toast(ok, msg)

    def _flush_cache(self) -> None:
        if not self._confirm("Flush file cache", "Flush the system file cache?"):
            return
        ok, msg = memory.flush_file_cache()
        self._toast(ok, msg)

    # -- assembly studio ----------------------------------------------------
    def _parse_addr(self) -> int | None:
        try:
            return int(self.addr.text().strip(), 16)
        except ValueError:
            self._toast(False, "address must be hex, e.g. 0x7ff6abcd0000")
            return None

    def _run(self, fn, on_done, *args) -> None:
        """Run a blocking native call on the shared Worker (keeps the UI live)."""
        if self._worker and self._worker.isRunning():
            self._toast(False, "a task is already running")
            return
        self._worker = Worker(fn, *args)
        self._worker.done.connect(on_done)
        self._worker.failed.connect(lambda e: self._toast(False, e))
        self._worker.start()

    def _disassemble(self) -> None:
        pid = self._selected_pid()
        addr = self._parse_addr()
        if pid is None or addr is None:
            return
        self.disasm_view.setPlainText("disassembling…")
        self._run(disasm.disassemble_process, self._show_disasm,
                  pid, addr, self.nbytes.value())

    def _show_disasm(self, lines) -> None:
        self.disasm_view.setPlainText("\n".join(lines))

    def _patch(self) -> None:
        pid = self._selected_pid()
        addr = self._parse_addr()
        if pid is None or addr is None:
            return
        asm, ok = QInputDialog.getText(self, "Patch memory (assembly)",
                                       "Enter x64 assembly (e.g. 'nop; nop; ret'):")
        if not ok or not asm.strip():
            return
        code, status = disasm.assemble(asm)
        if code is None:
            self._toast(False, status)
            return
        if QMessageBox.warning(
            self, "Confirm memory patch",
            f"Write {len(code)} bytes ({code.hex(' ')}) to pid {pid} @ 0x{addr:x}?\n\n"
            "This modifies a live process and can crash it.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        good, msg = disasm.patch_memory(pid, addr, code)
        self._toast(good, msg)

    def _export(self) -> None:
        if not self._rows:
            self._toast(False, "nothing to export yet")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export process list", "aetheris-processes.csv",
            "CSV (*.csv);;JSON (*.json)")
        if not path:
            return
        rows = report.process_rows(self._rows)
        try:
            if path.lower().endswith(".json"):
                content = report.rows_to_json(rows)
            else:
                headers = list(rows[0].keys())
                content = report.rows_to_csv(
                    headers, [[r[h] for h in headers] for r in rows])
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(content)
            self._toast(True, f"exported {len(rows)} processes -> {path}")
        except Exception as exc:  # noqa: BLE001
            self._toast(False, str(exc))

    def _toast(self, ok: bool, msg: str) -> None:
        (logbus.success if ok else logbus.error)("ui.memory", msg)
