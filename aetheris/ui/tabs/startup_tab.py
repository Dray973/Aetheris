"""
Startup Impact -- what runs at boot and how much each one costs.

Lists autoruns + auto-start services, ranked by the boot-slowdown Windows
itself recorded (Diagnostics-Performance log). Where no measurement exists the
item is still shown, just without a number. Read-only -- this tab reports; the
Shell tab's Autoruns panel is where things are actually disabled.
"""
from __future__ import annotations

import shiboken6
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...core import startup
from ..workers import Worker

_IMPACT_COLOR = {startup.HIGH: "#ff5d6c", startup.MEDIUM: "#e0b341",
                 startup.LOW: "#5ee0a0", startup.NONE: "#7a7f8a"}
_IMPACT_TEXT = {startup.HIGH: "High", startup.MEDIUM: "Medium",
                startup.LOW: "Low", startup.NONE: "—"}


class StartupTab(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._worker: Worker | None = None
        self._build()
        self._refresh()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.addWidget(QLabel("Startup Impact", objectName="title"))
        root.addWidget(QLabel(
            "Everything that launches at boot, ranked by how much it slowed the "
            "last boot (from Windows' own boot-performance log). Disable items "
            "from the Shell tab's Autoruns panel.", objectName="subtle"))

        bar = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self._refresh)
        bar.addWidget(self.refresh_btn)
        bar.addStretch(1)
        self.summary = QLabel("", objectName="subtle")
        bar.addWidget(self.summary)
        root.addLayout(bar)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["Impact", "Added", "Name", "Kind", "Where"])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        root.addWidget(self.table, 1)

    def closeEvent(self, event) -> None:  # noqa: N802
        if self._worker is not None:
            self._worker.wait()
        super().closeEvent(event)

    def _refresh(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            return
        if self._worker is not None:
            self._worker.wait()
        self.refresh_btn.setEnabled(False)
        self.summary.setText("reading…")
        self._worker = Worker(startup.collect)
        self._worker.done.connect(self._populate)
        self._worker.failed.connect(self._on_failed)
        self._worker.start()

    def _on_failed(self, err: str) -> None:
        if not shiboken6.isValid(self):
            return
        self.refresh_btn.setEnabled(True)
        self.summary.setText(f"failed: {err}")

    def _populate(self, report: startup.StartupReport) -> None:
        if not shiboken6.isValid(self):
            return
        self.refresh_btn.setEnabled(True)
        items = report.ranked()
        self.table.setRowCount(len(items))
        for row, it in enumerate(items):
            impact = QTableWidgetItem(_IMPACT_TEXT.get(it.impact, "—"))
            impact.setForeground(QColor(_IMPACT_COLOR.get(it.impact, "#c8d3f5")))
            added = f"{it.impact_ms / 1000:.1f} s" if it.impact_ms is not None else ""
            name = it.name + ("" if it.enabled else "  (disabled)")
            cells = [impact, QTableWidgetItem(added), QTableWidgetItem(name),
                     QTableWidgetItem(it.kind), QTableWidgetItem(it.source)]
            for col, item in enumerate(cells):
                if not it.enabled:
                    item.setForeground(QColor("#7a7f8a"))
                self.table.setItem(row, col, item)
        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)

        measured = sum(1 for it in items if it.impact_ms is not None)
        parts = [f"{len(items)} startup item(s)"]
        if report.last_boot_ms:
            parts.append(f"last boot {report.last_boot_ms / 1000:.0f} s")
        parts.append(f"{measured} measured" if report.measured
                     else "no boot-timing data (needs Windows + elevation)")
        self.summary.setText("  ·  ".join(parts))
