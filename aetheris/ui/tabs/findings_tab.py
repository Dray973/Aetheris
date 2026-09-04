"""
Threat Hunt -- correlated findings across every module.

Runs the findings engine (``analysis/findings.py``) on a Worker: it gathers
processes (+ Authenticode), connections (+ GeoIP), the persistence map, tasks,
services, and a memory-injection scan of suspicious processes, then correlates
them into a ranked list. The same binary showing up as unsigned + running from
temp + talking to a public host + persisting collapses into one critical finding,
tagged with a MITRE ATT&CK technique and the reversible responses to apply.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...analysis import findings as F
from ..workers import Worker

_SEV_COLOR = {"critical": "#ff5d6c", "high": "#ff9f43",
              "medium": "#feca57", "low": "#7d8aa0"}


class FindingsTab(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._worker: Worker | None = None
        self._findings: list[F.Finding] = []
        self._build()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.addWidget(QLabel("Threat Hunt — Correlated Findings", objectName="title"))
        root.addWidget(QLabel(
            "Correlate processes, network, persistence, tasks, services, and memory "
            "injection into ranked, ATT&CK-tagged findings. Authorized use only.",
            objectName="subtle"))

        bar = QHBoxLayout()
        self.run_btn = QPushButton("Run hunt")
        self.run_btn.clicked.connect(self._run)
        bar.addWidget(self.run_btn)
        self.inj_cb = QCheckBox("Scan memory for injection (slower)")
        self.inj_cb.setChecked(True)
        bar.addWidget(self.inj_cb)
        self.yara_cb = QCheckBox("Scan with YARA")
        self.yara_cb.setToolTip("Match built-in + user rules against suspect process memory "
                                "(needs yara-python)")
        bar.addWidget(self.yara_cb)
        bar.addStretch(1)
        self.summary = QLabel("", objectName="subtle")
        bar.addWidget(self.summary)
        root.addLayout(bar)

        split = QSplitter(Qt.Orientation.Vertical)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["Severity", "Score", "ATT&CK", "Subject", "Finding"])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.itemSelectionChanged.connect(self._show_detail)
        split.addWidget(self.table)

        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setPlaceholderText("Select a finding to see evidence and suggested responses.")
        split.addWidget(self.detail)
        split.setSizes([500, 260])
        root.addWidget(split, 1)

    def _run(self) -> None:
        if self._worker and self._worker.isRunning():
            return
        self.run_btn.setEnabled(False)
        self.summary.setText("hunting…")
        self._worker = Worker(F.gather, self.inj_cb.isChecked(), self.yara_cb.isChecked())
        self._worker.done.connect(self._populate)
        self._worker.failed.connect(self._on_failed)
        self._worker.start()

    def _on_failed(self, err: str) -> None:
        self.run_btn.setEnabled(True)
        self.summary.setText(f"hunt failed: {err}")

    def _populate(self, findings: list[F.Finding]) -> None:
        self.run_btn.setEnabled(True)
        self._findings = findings
        self.table.setRowCount(len(findings))
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for row, f in enumerate(findings):
            counts[f.severity] = counts.get(f.severity, 0) + 1
            cells = [f.severity.upper(), str(f.score), f.technique, f.subject, f.title]
            for col, val in enumerate(cells):
                item = QTableWidgetItem(val)
                if col == 0:
                    item.setForeground(QColor(_SEV_COLOR.get(f.severity, "#c8d3f5")))
                self.table.setItem(row, col, item)
        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.summary.setText(
            f"{len(findings)} finding(s) — "
            f"{counts['critical']} critical, {counts['high']} high, "
            f"{counts['medium']} medium, {counts['low']} low")
        if not findings:
            self.detail.setPlainText("No findings — nothing correlated as suspicious.")

    def _show_detail(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        idx = rows[0].row()
        if not (0 <= idx < len(self._findings)):
            return
        f = self._findings[idx]
        lines = [f"{f.severity.upper()}  (score {f.score})",
                 f"{f.title}",
                 f"Subject:   {f.subject}",
                 f"ATT&CK:    {f.technique}  {f.technique_name}",
                 "", "Evidence:"]
        lines += [f"  {e}" for e in f.evidence]
        if f.actions:
            lines += ["", "Suggested responses (reversible, audited):"]
            lines += [f"  • {a}" for a in f.actions]
        self.detail.setPlainText("\n".join(lines))
