"""Persistence Map: Run keys, Startup, auto/boot services and logon/boot tasks."""
from __future__ import annotations

from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QComboBox,
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

from ._base import PanelBase


class PersistencePanel(PanelBase):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._pm: list = []
        self._filtered_pm: list = []
        v = QVBoxLayout(self)
        v.addWidget(QLabel(
            "Everything that runs at boot/logon in one place: Run keys, Startup "
            "folders, auto/boot services, and logon/boot tasks. Unsigned = amber, "
            "disabled = grey. Enable/Disable is reversible (PANIC restores).",
            objectName="subtle"))
        bar = QHBoxLayout()
        self.pm_filter = QLineEdit(placeholderText="filter by name/command…")
        self.pm_filter.textChanged.connect(self._apply_pm_filter)
        bar.addWidget(self.pm_filter)
        self.pm_scope = QComboBox()
        self.pm_scope.addItems(["All", "Run/Startup", "Services", "Tasks",
                                "Unsigned only"])
        self.pm_scope.currentIndexChanged.connect(self._apply_pm_filter)
        bar.addWidget(self.pm_scope)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self._refresh_pm)
        bar.addWidget(refresh)
        v.addLayout(bar)

        self.pm_table = QTableWidget(0, 6)
        self.pm_table.setHorizontalHeaderLabels(
            ["Source", "Name", "Enabled", "Signed", "Location", "Command"])
        self.pm_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.pm_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.pm_table.horizontalHeader().setSectionResizeMode(
            5, QHeaderView.ResizeMode.Stretch)
        v.addWidget(self.pm_table)

        ctl = QHBoxLayout()
        for label, en in (("Disable", False), ("Enable", True)):
            b = QPushButton(label)
            b.clicked.connect(lambda _=False, e=en: self._pm_control(e))
            ctl.addWidget(b)
        ctl.addStretch(1)
        self.pm_count = QLabel("Click Refresh to build the persistence map.",
                               objectName="subtle")
        self._status = self.pm_count
        ctl.addWidget(self.pm_count)
        v.addLayout(ctl)

    def _refresh_pm(self) -> None:
        from ....core import persistence
        if self._run(persistence.enumerate_all, self._show_pm):
            self.pm_count.setText("scanning…")

    def _show_pm(self, rows) -> None:
        self._pm = rows
        self._apply_pm_filter()

    def _apply_pm_filter(self) -> None:
        needle = self.pm_filter.text().lower().strip()
        scope = self.pm_scope.currentText()
        rows = self._pm
        if scope == "Run/Startup":
            rows = [r for r in rows if r.source in ("Run", "Startup")]
        elif scope == "Services":
            rows = [r for r in rows if r.source == "Service"]
        elif scope == "Tasks":
            rows = [r for r in rows if r.source == "Task"]
        elif scope == "Unsigned only":
            rows = [r for r in rows if r.signed == "unsigned"]
        if needle:
            rows = [r for r in rows
                    if needle in r.name.lower() or needle in r.detail.lower()]
        self._filtered_pm = rows
        tb = self.pm_table
        tb.setRowCount(len(rows))
        for i, r in enumerate(rows):
            vals = [r.source, r.name, "yes" if r.enabled else "no",
                    r.signed, r.location, r.detail]
            for c, val in enumerate(vals):
                item = QTableWidgetItem(str(val))
                if r.signed == "unsigned":
                    item.setForeground(QColor("#e0b341"))
                elif not r.enabled:
                    item.setForeground(QColor("#7a7f8a"))
                tb.setItem(i, c, item)
        n_unsigned = sum(1 for r in self._pm if r.signed == "unsigned")
        self.pm_count.setText(
            f"{len(rows)} shown / {len(self._pm)} total  ·  {n_unsigned} unsigned")

    def _selected_pm(self):
        row = self.pm_table.currentRow()
        if 0 <= row < len(self._filtered_pm):
            return self._filtered_pm[row]
        return None

    def _pm_control(self, enable: bool) -> None:
        from ....core import persistence
        entry = self._selected_pm()
        if entry is None:
            self._toast(False, "select an entry first")
            return
        verb = "enable" if enable else "disable"
        if not self._confirm(
                "Persistence control",
                f"{verb}:\n\n[{entry.source}] {entry.name}\n\n(Reversible via PANIC.)"):
            return
        self._run(persistence.set_enabled, self._show_result_then(self._refresh_pm),
                  entry, enable)
