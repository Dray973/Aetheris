"""
Threat Hunt -- correlated findings across every module.

Runs the findings engine (``analysis/findings.py``) on a Worker: it gathers
processes (+ Authenticode), connections (+ GeoIP), the persistence map, tasks,
services, and a memory-injection scan of suspicious processes, then correlates
them into a ranked list. The same binary showing up as unsigned + running from
temp + talking to a public host + persisting collapses into one critical finding,
tagged with a MITRE ATT&CK technique and the reversible responses to apply.

A saved **baseline** (``analysis/baseline.py``) tags each finding new /
escalated / known, so repeat hunts surface change instead of the same accepted
noise.
"""
from __future__ import annotations

import time

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ... import __version__
from ...analysis import baseline as BL
from ...analysis import export
from ...analysis import findings as F
from ...core import logbus
from ..workers import Worker

SRC = "ui.findings"

_SEV_COLOR = {"critical": "#ff5d6c", "high": "#ff9f43",
              "medium": "#feca57", "low": "#7d8aa0"}
_STATUS_COLOR = {BL.NEW: "#ff9f43", BL.ESCALATED: "#ff5d6c", BL.KNOWN: "#7a7f8a"}

_COLS = ["Severity", "Score", "ATT&CK", "Baseline", "Subject", "Finding"]
_STRETCH = 5


class FindingsTab(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._worker: Worker | None = None
        self._all: list[F.Finding] = []        # everything the last hunt found
        self._findings: list[F.Finding] = []   # what the table shows
        self._baseline: BL.Baseline | None = BL.load_default()
        self._baseline_path = BL.default_path()
        self._build()
        self._update_baseline_label()

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
        self.export_btn = QPushButton("Export…")
        self.export_btn.setToolTip("Save findings as SARIF 2.1.0 (GitHub code scanning, "
                                   "VS Code SARIF viewer, SIEM import), JSON or Markdown")
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self._export)
        bar.addWidget(self.export_btn)
        bar.addStretch(1)
        self.summary = QLabel("", objectName="subtle")
        bar.addWidget(self.summary)
        root.addLayout(bar)

        base = QHBoxLayout()
        self.baseline_label = QLabel("", objectName="subtle")
        base.addWidget(self.baseline_label)
        base.addStretch(1)
        self.new_only_cb = QCheckBox("Show new / escalated only")
        self.new_only_cb.toggled.connect(self._refilter)
        base.addWidget(self.new_only_cb)
        self.accept_sel_btn = QPushButton("Accept selected")
        self.accept_sel_btn.setToolTip("Mark the selected finding as known-good")
        self.accept_sel_btn.clicked.connect(self._accept_selected)
        base.addWidget(self.accept_sel_btn)
        self.accept_all_btn = QPushButton("Set baseline from this hunt")
        self.accept_all_btn.setToolTip("Accept every current finding as this "
                                       "machine's known-good state")
        self.accept_all_btn.clicked.connect(self._accept_all)
        base.addWidget(self.accept_all_btn)
        self.clear_btn = QPushButton("Clear baseline")
        self.clear_btn.clicked.connect(self._clear_baseline)
        base.addWidget(self.clear_btn)
        root.addLayout(base)

        split = QSplitter(Qt.Orientation.Vertical)
        self.table = QTableWidget(0, len(_COLS))
        self.table.setHorizontalHeaderLabels(_COLS)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(
            _STRETCH, QHeaderView.ResizeMode.Stretch)
        self.table.itemSelectionChanged.connect(self._show_detail)
        split.addWidget(self.table)

        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setPlaceholderText("Select a finding to see evidence and suggested responses.")
        split.addWidget(self.detail)
        split.setSizes([500, 260])
        root.addWidget(split, 1)
        self._sync_buttons()

    # -- hunting ------------------------------------------------------------
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
        self._all = list(findings)
        self._refilter()

    # -- display ------------------------------------------------------------
    def _status(self, f: F.Finding) -> str:
        return self._baseline.status(f) if self._baseline is not None else ""

    def _refilter(self) -> None:
        shown = self._all
        if self.new_only_cb.isChecked() and self._baseline is not None:
            shown = [f for f in shown if self._baseline.status(f) != BL.KNOWN]
        self._findings = shown
        self.table.setRowCount(len(shown))
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for row, f in enumerate(shown):
            counts[f.severity] = counts.get(f.severity, 0) + 1
            status = self._status(f)
            cells = [f.severity.upper(), str(f.score), f.technique, status,
                     f.subject, f.title]
            for col, val in enumerate(cells):
                item = QTableWidgetItem(val)
                if col == 0:
                    item.setForeground(QColor(_SEV_COLOR.get(f.severity, "#c8d3f5")))
                elif col == 3 and status:
                    item.setForeground(QColor(_STATUS_COLOR[status]))
                self.table.setItem(row, col, item)
        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setSectionResizeMode(
            _STRETCH, QHeaderView.ResizeMode.Stretch)
        text = (f"{len(shown)} finding(s) — "
                f"{counts['critical']} critical, {counts['high']} high, "
                f"{counts['medium']} medium, {counts['low']} low")
        if self._baseline is not None and self._all:
            s = BL.summarize(self._baseline, self._all)
            text += (f"  ·  {s[BL.NEW]} new, {s[BL.ESCALATED]} escalated, "
                     f"{s[BL.KNOWN]} known, {s['resolved']} resolved")
        self.summary.setText(text)
        if not shown:
            self.detail.setPlainText(
                "No new findings since the baseline." if self._all
                else "No findings — nothing correlated as suspicious.")
        self._sync_buttons()

    def _sync_buttons(self) -> None:
        has = bool(self._all)
        self.export_btn.setEnabled(has)
        self.accept_all_btn.setEnabled(has)
        self.accept_sel_btn.setEnabled(has)
        self.clear_btn.setEnabled(self._baseline is not None)
        self.new_only_cb.setEnabled(self._baseline is not None)

    def _selected(self) -> F.Finding | None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        idx = rows[0].row()
        return self._findings[idx] if 0 <= idx < len(self._findings) else None

    def _show_detail(self) -> None:
        f = self._selected()
        if f is None:
            return
        lines = [f"{f.severity.upper()}  (score {f.score})",
                 f"{f.title}",
                 f"Subject:   {f.subject}",
                 f"ATT&CK:    {f.technique}  {f.technique_name}"]
        if self._baseline is not None:
            status = self._baseline.status(f)
            lines.append(f"Baseline:  {status}")
            if status == BL.ESCALATED:
                lines.append("           new behaviour: "
                             + ", ".join(self._baseline.new_techniques(f)))
        lines += ["", "Evidence:"]
        lines += [f"  {e}" for e in f.evidence]
        if f.actions:
            lines += ["", "Suggested responses (reversible, audited):"]
            lines += [f"  • {a}" for a in f.actions]
        self.detail.setPlainText("\n".join(lines))

    # -- baseline -----------------------------------------------------------
    def _update_baseline_label(self) -> None:
        if self._baseline is None:
            self.baseline_label.setText(
                "No baseline — run a hunt on a known-clean state, then "
                "“Set baseline” to see only what changes.")
        else:
            import datetime
            when = datetime.datetime.fromtimestamp(self._baseline.created_at)
            self.baseline_label.setText(
                f"Baseline: {len(self._baseline.entries)} accepted subject(s), "
                f"set {when:%Y-%m-%d %H:%M}")

    def _save_baseline(self) -> bool:
        assert self._baseline is not None
        try:
            self._baseline.save(self._baseline_path)
        except OSError as exc:
            logbus.error(SRC, f"could not save baseline: {exc}")
            return False
        return True

    def _accept_all(self) -> None:
        if not self._all:
            return
        if self._baseline is not None and not self._confirm(
                "Replace baseline",
                f"Replace the current baseline with these {len(self._all)} finding(s)?"):
            return
        import platform
        self._baseline = BL.Baseline.from_findings(self._all, host=platform.node())
        if self._save_baseline():
            logbus.success(SRC, f"baseline set: {len(self._all)} finding(s) accepted")
        self._update_baseline_label()
        self._refilter()

    def _accept_selected(self) -> None:
        f = self._selected()
        if f is None:
            logbus.error(SRC, "select a finding first")
            return
        if self._baseline is None:
            import platform
            self._baseline = BL.Baseline(host=platform.node(),
                                         created_at=time.time())
        self._baseline.accept(f)
        if self._save_baseline():
            logbus.success(SRC, f"accepted as known-good: {f.subject}")
        self._update_baseline_label()
        self._refilter()

    def _clear_baseline(self) -> None:
        if self._baseline is None or not self._confirm(
                "Clear baseline", "Forget every accepted finding?"):
            return
        self._baseline = None
        try:
            self._baseline_path.unlink(missing_ok=True)
        except OSError as exc:
            logbus.error(SRC, f"could not remove baseline file: {exc}")
        self.new_only_cb.setChecked(False)
        self._update_baseline_label()
        self._refilter()

    def _confirm(self, title: str, text: str) -> bool:
        return QMessageBox.question(
            self, title, text,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        ) == QMessageBox.StandardButton.Yes

    # -- export -------------------------------------------------------------
    _EXPORT_FILTERS = "SARIF 2.1.0 (*.sarif);;JSON (*.json);;Markdown (*.md)"

    def _export(self) -> None:
        path, chosen = QFileDialog.getSaveFileName(
            self, "Export hunt findings", "hunt.sarif", self._EXPORT_FILTERS)
        if not path:
            return
        try:
            content = self._render_export(path, chosen)
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(content)
        except OSError as exc:
            logbus.error(SRC, f"export failed: {exc}")
            return
        logbus.success(SRC, f"{len(self._findings)} finding(s) exported -> {path}")

    def _render_export(self, path: str, chosen_filter: str = "") -> str:
        """Pick the format from the extension, else from the chosen filter.
        Exports what the table shows, tagged against the baseline if one is set."""
        import platform
        low = path.lower()
        base = self._baseline
        if low.endswith(".json") or (not low.endswith((".sarif", ".md"))
                                     and chosen_filter.startswith("JSON")):
            return export.render_json(self._findings, base)
        if low.endswith(".md") or (not low.endswith(".sarif")
                                   and chosen_filter.startswith("Markdown")):
            return export.render_markdown(self._findings, baseline=base)
        return export.render_sarif(self._findings, __version__, platform.node(), base)
