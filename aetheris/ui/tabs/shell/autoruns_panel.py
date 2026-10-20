"""Autoruns: Run/RunOnce keys + Startup folders, with reversible enable/disable."""
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

from ._base import PanelBase


class AutorunsPanel(PanelBase):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._autoruns: list = []
        v = QVBoxLayout(self)
        v.addWidget(QLabel(
            "Everything that launches at logon/boot (Run/RunOnce keys + Startup "
            "folders). Disable is reversible (PANIC restores it).",
            objectName="subtle"))
        self.autoruns_table = QTableWidget(0, 4)
        self.autoruns_table.setHorizontalHeaderLabels(
            ["Name", "Command", "Location", "Enabled"])
        self.autoruns_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self.autoruns_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.autoruns_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch)
        v.addWidget(self.autoruns_table)
        row = QHBoxLayout()
        for label, slot in (("Refresh", self._refresh_autoruns),
                            ("Disable", lambda: self._toggle_autorun(False)),
                            ("Enable", lambda: self._toggle_autorun(True))):
            b = QPushButton(label)
            b.clicked.connect(slot)
            row.addWidget(b)
        row.addStretch(1)
        self.autoruns_count = QLabel("", objectName="subtle")
        self._status = self.autoruns_count
        row.addWidget(self.autoruns_count)
        v.addLayout(row)
        self._refresh_autoruns()

    def _refresh_autoruns(self) -> None:
        from ....core import autoruns
        if self._run(autoruns.enumerate_entries, self._show_autoruns):
            self.autoruns_count.setText("enumerating…")

    def _show_autoruns(self, entries) -> None:
        self._autoruns = entries
        t = self.autoruns_table
        t.setRowCount(len(entries))
        for i, e in enumerate(entries):
            for c, val in enumerate([e.name, e.command, e.location,
                                     "yes" if e.enabled else "DISABLED"]):
                item = QTableWidgetItem(val)
                if not e.enabled:
                    item.setForeground(QColor("#ff5d6c"))
                t.setItem(i, c, item)
        n_off = sum(1 for e in entries if not e.enabled)
        self.autoruns_count.setText(f"{len(entries)} entries ({n_off} disabled)")

    def _toggle_autorun(self, enable: bool) -> None:
        from ....core import autoruns
        row = self.autoruns_table.currentRow()
        if not (0 <= row < len(self._autoruns)):
            self._toast(False, "select an entry first")
            return
        e = self._autoruns[row]
        if enable == e.enabled:
            self._toast(False, f"already {'enabled' if enable else 'disabled'}")
            return
        verb = "enable" if enable else "disable"
        # Every write is confirm-gated, like the other persistence controls.
        if not self._confirm("Autorun", f"{verb}:\n\n{e.name}\n\n(Reversible via PANIC.)"):
            return
        fn = autoruns.enable if enable else autoruns.disable
        self._run(fn, self._show_result_then(self._refresh_autoruns), e)
