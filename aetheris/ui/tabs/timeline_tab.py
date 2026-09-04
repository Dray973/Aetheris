"""
Module 6 -- Session Timeline & State Diff.

Snapshots volatile system state (processes, listening ports, connections,
autoruns) over the session and diffs any two points. The capture runs on a
Worker so the UI never blocks; the diff reuses the registry-diff colour scheme.
"""
from __future__ import annotations

from PySide6.QtCore import QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...core import timeline
from ..workers import Worker

_CHANGE_COLORS = {"Added": "#5ee0a0", "Removed": "#ff5d6c"}


class TimelineTab(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._timeline = timeline.Timeline()
        self._worker: Worker | None = None
        self._build()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._capture)

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.addWidget(QLabel("Session Timeline & State Diff", objectName="title"))
        root.addWidget(QLabel(
            "Snapshot processes, listening ports, connections, and autoruns over "
            "the session, then diff any two points. Pairs with the audit log.",
            objectName="subtle"))

        bar = QHBoxLayout()
        cap = QPushButton("Capture now")
        cap.clicked.connect(self._capture)
        bar.addWidget(cap)
        self.auto_cb = QCheckBox("Auto every 30s")
        self.auto_cb.toggled.connect(self._toggle_auto)
        bar.addWidget(self.auto_cb)
        bar.addStretch(1)
        self.status = QLabel("0 snapshots", objectName="subtle")
        bar.addWidget(self.status)
        root.addLayout(bar)

        pick = QHBoxLayout()
        pick.addWidget(QLabel("A:"))
        self.combo_a = QComboBox()
        pick.addWidget(self.combo_a, 1)
        pick.addWidget(QLabel("B:"))
        self.combo_b = QComboBox()
        pick.addWidget(self.combo_b, 1)
        diff = QPushButton("Diff A → B")
        diff.clicked.connect(self._diff)
        pick.addWidget(diff)
        root.addLayout(pick)

        self.diff_table = QTableWidget(0, 3)
        self.diff_table.setHorizontalHeaderLabels(["Change", "Category", "Detail"])
        self.diff_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.diff_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch)
        root.addWidget(self.diff_table)
        self.diff_summary = QLabel("", objectName="subtle")
        root.addWidget(self.diff_summary)

    def _toggle_auto(self, on: bool) -> None:
        if on:
            self._timer.start(30000)
            self._capture()
        else:
            self._timer.stop()

    def _capture(self) -> None:
        if self._worker and self._worker.isRunning():
            return
        seq = self._timeline.next_seq()
        self.status.setText("capturing…")
        self._worker = Worker(timeline.capture, seq)
        self._worker.done.connect(self._on_captured)
        self._worker.failed.connect(lambda e: self.status.setText(f"capture failed: {e}"))
        self._worker.start()

    def _on_captured(self, snap) -> None:
        self._timeline.add(snap)
        self._refresh_pickers()

    def _refresh_pickers(self) -> None:
        snaps = self._timeline.snapshots()
        self.status.setText(f"{len(snaps)} snapshots")
        prev_a, prev_b = self.combo_a.currentIndex(), self.combo_b.currentIndex()
        self.combo_a.clear()
        self.combo_b.clear()
        for s in snaps:
            text = f"#{s.seq}  {s.label}  ({s.counts()})"
            self.combo_a.addItem(text)
            self.combo_b.addItem(text)
        if snaps:
            self.combo_a.setCurrentIndex(prev_a if 0 <= prev_a < len(snaps) else 0)
            self.combo_b.setCurrentIndex(prev_b if 0 <= prev_b < len(snaps) else len(snaps) - 1)

    def _diff(self) -> None:
        snaps = self._timeline.snapshots()
        ia, ib = self.combo_a.currentIndex(), self.combo_b.currentIndex()
        if not (0 <= ia < len(snaps) and 0 <= ib < len(snaps)):
            self.diff_summary.setText("capture at least two snapshots first")
            return
        d = timeline.diff_snapshots(snaps[ia], snaps[ib])
        rows = timeline.diff_rows(d)
        self.diff_table.setRowCount(len(rows))
        for i, (change, cat, detail) in enumerate(rows):
            for c, val in enumerate((change, cat, detail)):
                item = QTableWidgetItem(val)
                col = _CHANGE_COLORS.get(change)
                if col:
                    item.setForeground(QColor(col))
                self.diff_table.setItem(i, c, item)
        self.diff_summary.setText(
            "no changes between the two snapshots" if d.is_empty() else d.summary())
