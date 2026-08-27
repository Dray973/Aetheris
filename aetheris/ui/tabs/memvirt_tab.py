"""
Module 1 — Virtual Memory Scanner view.

Backend-driven (MemProcFS when available, else the live Win32 backend): a
process list, the selected process's memory region map (address space), and a
hex viewer that reads a region or an arbitrary address. When a physical backend
is active, a physical-address hex reader is exposed too.
"""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTableWidget, QTableWidgetItem,
    QPushButton, QLabel, QLineEdit, QSpinBox, QPlainTextEdit, QHeaderView,
    QCheckBox,
)
from PyQt6.QtGui import QFont

from ...forensics import memvirt
from ...core import logbus
from ..workers import Worker


def _human(n: int) -> str:
    f = float(n)
    for u in ("B", "KB", "MB", "GB"):
        if f < 1024 or u == "GB":
            return f"{f:,.0f} {u}" if u == "B" else f"{f:,.1f} {u}"
        f /= 1024
    return f"{f} B"


class MemVirtWidget(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._backend = memvirt.get_backend()
        self._procs: list[memvirt.MemoryProcess] = []
        self._regions: list[memvirt.MemoryRegion] = []
        self._worker: Worker | None = None
        self._build()
        self.rescan()

    def _build(self) -> None:
        root = QVBoxLayout(self)

        bar = QHBoxLayout()
        cap = self._backend.capabilities
        badge = "PHYSICAL" if cap.physical else "process-scoped"
        self.status = QLabel(f"Backend: {self._backend.name}   [{badge}]", objectName="subtle")
        bar.addWidget(self.status)
        bar.addStretch(1)
        self.filter = QLineEdit(placeholderText="filter processes…", maximumWidth=220)
        self.filter.textChanged.connect(self._apply_filter)
        bar.addWidget(self.filter)
        rescan = QPushButton("Rescan")
        rescan.clicked.connect(self.rescan)
        bar.addWidget(rescan)
        root.addLayout(bar)

        split = QSplitter(Qt.Orientation.Horizontal)

        # -- process list --
        self.proc_table = QTableWidget(0, 5)
        self.proc_table.setHorizontalHeaderLabels(["PID", "Name", "PPID", "Hidden", "Path"])
        self.proc_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.proc_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.proc_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.proc_table.itemSelectionChanged.connect(self._load_map)
        split.addWidget(self.proc_table)

        # -- right side: region map + hex --
        right = QSplitter(Qt.Orientation.Vertical)
        self.region_table = QTableWidget(0, 5)
        self.region_table.setHorizontalHeaderLabels(["Base", "Size", "State", "Protect", "Type"])
        self.region_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.region_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.region_table.doubleClicked.connect(self._region_dblclick)
        right.addWidget(self.region_table)

        hexbox = QWidget()
        hv = QVBoxLayout(hexbox)
        row = QHBoxLayout()
        row.addWidget(QLabel("Read @"))
        self.addr = QLineEdit("0x", maximumWidth=180)
        row.addWidget(self.addr)
        row.addWidget(QLabel("size"))
        self.size = QSpinBox()
        self.size.setRange(16, 65536)
        self.size.setValue(256)
        self.size.setSingleStep(16)
        row.addWidget(self.size)
        read = QPushButton("Read (virtual)")
        read.clicked.connect(self._read_virtual)
        row.addWidget(read)
        self.phys_cb = QCheckBox("physical address")
        self.phys_cb.setEnabled(self._backend.capabilities.physical)
        self.phys_cb.setToolTip("Requires a physical backend (MemProcFS).")
        row.addWidget(self.phys_cb)
        row.addStretch(1)
        hv.addLayout(row)
        self.hexview = QPlainTextEdit(readOnly=True)
        self.hexview.setFont(QFont("Cascadia Code", 10))
        self.hexview.setPlaceholderText(
            "Select a process, double-click a region (or type an address) and Read.")
        hv.addWidget(self.hexview)
        right.addWidget(hexbox)
        right.setSizes([260, 320])
        split.addWidget(right)
        split.setSizes([520, 620])
        root.addWidget(split)

        self.count = QLabel("", objectName="subtle")
        root.addWidget(self.count)

    # -- process list -------------------------------------------------------
    def rescan(self) -> None:
        self._run(self._backend.list_processes, self._show_procs)

    def _show_procs(self, procs) -> None:
        self._procs = sorted(procs, key=lambda p: p.pid)
        self._apply_filter()
        hidden = sum(1 for p in self._procs if p.hidden)
        self.count.setText(f"{len(self._procs)} processes"
                           + (f"  ({hidden} flagged hidden)" if hidden else ""))

    def _apply_filter(self) -> None:
        needle = self.filter.text().lower().strip()
        shown = [p for p in self._procs if needle in p.name.lower()] if needle else self._procs
        self._shown = shown
        self.proc_table.setRowCount(len(shown))
        for i, p in enumerate(shown):
            for c, v in enumerate([str(p.pid), p.name, str(p.ppid),
                                   "⚠" if p.hidden else "", p.path]):
                item = QTableWidgetItem(v)
                if p.hidden:
                    item.setForeground(Qt.GlobalColor.red)
                self.proc_table.setItem(i, c, item)

    def _selected_pid(self) -> int | None:
        row = self.proc_table.currentRow()
        if row < 0 or self.proc_table.item(row, 0) is None:
            return None
        return int(self.proc_table.item(row, 0).text())

    # -- region map ---------------------------------------------------------
    def _load_map(self) -> None:
        pid = self._selected_pid()
        if pid is None:
            return
        self._run(lambda: self._backend.memory_map(pid), self._show_map)

    def _show_map(self, regions) -> None:
        self._regions = regions
        self.region_table.setRowCount(len(regions))
        total = 0
        for i, r in enumerate(regions):
            total += r.size
            for c, v in enumerate([f"0x{r.base:012x}", _human(r.size),
                                   r.state, r.protect, r.type]):
                item = QTableWidgetItem(v)
                if "x" in r.protect:                       # executable → highlight
                    item.setForeground(Qt.GlobalColor.cyan)
                self.region_table.setItem(i, c, item)
        logbus.trace("ui.memvirt", f"{len(regions)} regions, {_human(total)} mapped")

    def _region_dblclick(self, index) -> None:
        row = index.row()
        if 0 <= row < len(self._regions):
            r = self._regions[row]
            self.addr.setText(f"0x{r.base:x}")
            self.size.setValue(min(r.size, 4096) if r.size else 256)
            self._read_virtual()

    # -- hex read -----------------------------------------------------------
    def _parse_addr(self) -> int | None:
        try:
            return int(self.addr.text().strip(), 16)
        except ValueError:
            self.hexview.setPlainText("address must be hex, e.g. 0x7ff6abcd0000")
            return None

    def _read_virtual(self) -> None:
        addr = self._parse_addr()
        if addr is None:
            return
        n = self.size.value()
        if self.phys_cb.isChecked():
            data = self._backend.physical_read(addr, n)
            src = "physical"
        else:
            pid = self._selected_pid()
            if pid is None:
                self.hexview.setPlainText("select a process first")
                return
            data = self._backend.read(pid, addr, n)
            src = f"pid {pid}"
        if data is None:
            self.hexview.setPlainText(f"<could not read 0x{addr:x} ({src})>")
            return
        self.hexview.setPlainText(memvirt.format_hex(data, addr))

    # -- helpers ------------------------------------------------------------
    def _run(self, fn, on_done) -> None:
        if self._worker and self._worker.isRunning():
            return
        self._worker = Worker(fn)
        self._worker.done.connect(on_done)
        self._worker.failed.connect(lambda e: logbus.error("ui.memvirt", e))
        self._worker.start()
