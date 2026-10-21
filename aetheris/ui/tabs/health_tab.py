"""
System Health -- a plain "is my PC okay" dashboard.

Runs :func:`core.health.collect` on a Worker and shows a single score plus one
row per check, worst first, each with a recommendation when something is off.
Read-only: this tab never changes the machine.
"""
from __future__ import annotations

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

from ...core import health
from ..workers import Worker

_STATUS_COLOR = {health.OK: "#5ee0a0", health.WARN: "#e0b341",
                 health.CRITICAL: "#ff5d6c", health.UNKNOWN: "#7a7f8a"}
_STATUS_TEXT = {health.OK: "OK", health.WARN: "CHECK",
                health.CRITICAL: "ACTION", health.UNKNOWN: "—"}


class HealthTab(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._worker: Worker | None = None
        self._build()
        self._refresh()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.addWidget(QLabel("System Health", objectName="title"))
        root.addWidget(QLabel(
            "A quick read on disks, memory, battery, uptime and temperature. "
            "Read-only — nothing here changes your machine.", objectName="subtle"))

        bar = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self._refresh)
        bar.addWidget(self.refresh_btn)
        self.score_label = QLabel("", objectName="title")
        bar.addWidget(self.score_label)
        bar.addStretch(1)
        self.summary = QLabel("", objectName="subtle")
        bar.addWidget(self.summary)
        root.addLayout(bar)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["", "Check", "Reading", "What to do"])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        root.addWidget(self.table, 1)

    def _refresh(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            return
        self.refresh_btn.setEnabled(False)
        self.summary.setText("checking…")
        self._worker = Worker(health.collect)
        self._worker.done.connect(self._populate)
        self._worker.failed.connect(self._on_failed)
        self._worker.start()

    def _on_failed(self, err: str) -> None:
        self.refresh_btn.setEnabled(True)
        self.summary.setText(f"health check failed: {err}")

    def _populate(self, report: health.HealthReport) -> None:
        self.refresh_btn.setEnabled(True)
        metrics = report.worst_first()
        self.score_label.setText(f"{report.score}/100")
        self.score_label.setStyleSheet(
            f"color: {_STATUS_COLOR.get(report.overall, '#c8d3f5')}")
        counts = {s: sum(1 for m in metrics if m.status == s)
                  for s in (health.CRITICAL, health.WARN, health.OK)}
        self.summary.setText(
            f"{counts[health.CRITICAL]} need action, {counts[health.WARN]} to check, "
            f"{counts[health.OK]} OK")

        self.table.setRowCount(len(metrics))
        for row, mtr in enumerate(metrics):
            badge = QTableWidgetItem(_STATUS_TEXT.get(mtr.status, "—"))
            badge.setForeground(QColor(_STATUS_COLOR.get(mtr.status, "#c8d3f5")))
            detail = mtr.value + (f"  ({mtr.detail})" if mtr.detail else "")
            cells = [badge, QTableWidgetItem(mtr.label),
                     QTableWidgetItem(detail), QTableWidgetItem(mtr.recommendation)]
            for col, item in enumerate(cells):
                self.table.setItem(row, col, item)
        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
