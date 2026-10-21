"""
Certificate & Trust -- what your machine trusts, with the odd ones first.

Reads the machine + user Root and Intermediate stores and flags new (vs a saved
snapshot), expired, not-yet-valid, and uncommon roots. The headline case is a
rogue root CA quietly added to enable TLS interception. Read-only -- removing a
certificate is left to the OS; this tab shows you what to look at.
"""
from __future__ import annotations

import shiboken6
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...core import certstore, logbus
from ..workers import Worker

_FLAG_COLOR = {certstore.F_NEW: "#ff5d6c", certstore.F_UNCOMMON: "#e0b341",
               certstore.F_EXPIRED: "#ff9f43", certstore.F_FUTURE: "#e0b341"}
_FLAG_LABEL = {certstore.F_NEW: "NEW", certstore.F_UNCOMMON: "uncommon root",
               certstore.F_EXPIRED: "expired", certstore.F_FUTURE: "not yet valid"}


class CertTab(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._worker: Worker | None = None
        self._report: certstore.CertReport | None = None
        self._build()
        self._refresh()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.addWidget(QLabel("Certificate & Trust", objectName="title"))
        root.addWidget(QLabel(
            "Certificates your machine trusts. Watch for a root CA you don't "
            "recognise or didn't add — that's how TLS interception is set up. "
            "Save a snapshot to be told what appears later. Read-only.",
            objectName="subtle"))

        bar = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self._refresh)
        bar.addWidget(self.refresh_btn)
        self.filter = QLineEdit(placeholderText="filter by subject/issuer…")
        self.filter.textChanged.connect(self._apply_filter)
        bar.addWidget(self.filter, 1)
        self.flagged_only = QCheckBox("Flagged only")
        self.flagged_only.toggled.connect(self._apply_filter)
        bar.addWidget(self.flagged_only)
        self.save_btn = QPushButton("Save snapshot")
        self.save_btn.setToolTip("Record the current set; new certs are flagged later")
        self.save_btn.clicked.connect(self._save_snapshot)
        bar.addWidget(self.save_btn)
        root.addLayout(bar)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["Flags", "Subject", "Issuer", "Expires", "Store"])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        root.addWidget(self.table, 1)
        self.summary = QLabel("", objectName="subtle")
        root.addWidget(self.summary)

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
        self.summary.setText("reading certificate stores…")
        self._worker = Worker(self._collect_and_build)
        self._worker.done.connect(self._loaded)
        self._worker.failed.connect(self._on_failed)
        self._worker.start()

    @staticmethod
    def _collect_and_build() -> certstore.CertReport:
        certs = certstore.collect()
        return certstore.build_report(certs, certstore.load_thumbprints())

    def _on_failed(self, err: str) -> None:
        if not shiboken6.isValid(self):
            return
        self.refresh_btn.setEnabled(True)
        self.summary.setText(f"failed: {err}")

    def _loaded(self, report: certstore.CertReport) -> None:
        if not shiboken6.isValid(self):
            return
        self.refresh_btn.setEnabled(True)
        self._report = report
        self._apply_filter()

    def _apply_filter(self) -> None:
        if self._report is None:
            return
        needle = self.filter.text().lower().strip()
        rows = self._report.certs
        if self.flagged_only.isChecked():
            rows = [c for c in rows if self._report.flags.get(c.thumbprint)]
        rows = sorted(rows, key=lambda c: (not self._report.flags.get(c.thumbprint),
                                           c.common_name.lower()))
        if needle:
            rows = [c for c in rows
                    if needle in c.subject.lower() or needle in c.issuer.lower()]
        self.table.setRowCount(len(rows))
        for i, c in enumerate(rows):
            cflags = self._report.flags.get(c.thumbprint, [])
            badge = QTableWidgetItem(", ".join(_FLAG_LABEL.get(f, f) for f in cflags))
            if cflags:
                badge.setForeground(QColor(_FLAG_COLOR.get(cflags[0], "#c8d3f5")))
            cells = [badge, QTableWidgetItem(c.common_name),
                     QTableWidgetItem(certstore._cn(c.issuer) or c.issuer),
                     QTableWidgetItem(_date(c.not_after)), QTableWidgetItem(c.store)]
            for col, item in enumerate(cells):
                self.table.setItem(i, col, item)
        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        flagged = sum(1 for c in self._report.certs if self._report.flags.get(c.thumbprint))
        base = "" if certstore.load_thumbprints() is not None else \
            "  ·  no snapshot yet (save one to catch new certs)"
        self.summary.setText(
            f"{len(rows)} shown / {len(self._report.certs)} trusted  ·  "
            f"{flagged} flagged{base}")

    def _save_snapshot(self) -> None:
        if self._report is None or not self._report.certs:
            return
        try:
            certstore.save(self._report.certs)
        except OSError as exc:
            logbus.error("ui.cert", f"could not save snapshot: {exc}")
            return
        logbus.success("ui.cert", f"certificate snapshot saved "
                                  f"({len(self._report.certs)} certs)")
        # Re-flag against the snapshot just saved (clears 'new').
        self._report = certstore.build_report(self._report.certs,
                                               certstore.load_thumbprints())
        self._apply_filter()


def _date(epoch: float) -> str:
    if not epoch:
        return ""
    import datetime
    return datetime.datetime.fromtimestamp(epoch).strftime("%Y-%m-%d")
