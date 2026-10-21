"""
Software Inventory -- everything installed, and what changed since last save.

Lists installed programs (version, publisher, date, signature). "Save
snapshot" records the current list; a later refresh shows what was added,
removed or updated against it -- the software equivalent of a hunt baseline.
Read-only: this tab never installs or removes anything.
"""
from __future__ import annotations

import shiboken6
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
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

from ...core import inventory, logbus
from ..workers import Worker

_CHANGE_COLOR = {inventory.ADDED: "#5ee0a0", inventory.REMOVED: "#ff5d6c",
                 inventory.CHANGED: "#e0b341"}


class InventoryTab(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._worker: Worker | None = None
        self._apps: list[inventory.InstalledApp] = []
        self._changes: list[inventory.Change] = []
        self._build()
        self._refresh()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.addWidget(QLabel("Software Inventory", objectName="title"))
        root.addWidget(QLabel(
            "Everything installed, with version, publisher and signature. Save a "
            "snapshot, then refresh later to see what changed. Read-only.",
            objectName="subtle"))

        bar = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self._refresh)
        bar.addWidget(self.refresh_btn)
        self.filter = QLineEdit(placeholderText="filter by name/publisher…")
        self.filter.textChanged.connect(self._apply_filter)
        bar.addWidget(self.filter, 1)
        self.save_btn = QPushButton("Save snapshot")
        self.save_btn.setToolTip("Record the current list as the comparison point")
        self.save_btn.clicked.connect(self._save_snapshot)
        bar.addWidget(self.save_btn)
        root.addLayout(bar)

        self.changes_label = QLabel("", objectName="subtle")
        root.addWidget(self.changes_label)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["", "Name", "Version", "Publisher", "Installed", "Signed"])
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
        self.summary.setText("reading installed software…")
        self._worker = Worker(inventory.collect)
        self._worker.done.connect(self._loaded)
        self._worker.failed.connect(self._on_failed)
        self._worker.start()

    def _on_failed(self, err: str) -> None:
        if not shiboken6.isValid(self):
            return
        self.refresh_btn.setEnabled(True)
        self.summary.setText(f"failed: {err}")

    def _loaded(self, apps: list[inventory.InstalledApp]) -> None:
        if not shiboken6.isValid(self):
            return
        self.refresh_btn.setEnabled(True)
        self._apps = apps
        previous = inventory.load()
        self._changes = inventory.diff(previous, apps) if previous else []
        self._render_changes()
        self._apply_filter()

    def _render_changes(self) -> None:
        if not self._changes:
            self.changes_label.setText("No saved snapshot to compare — click "
                                       "“Save snapshot” to start tracking changes."
                                       if not inventory.load() else
                                       "No changes since the saved snapshot.")
            return
        n = {k: sum(1 for c in self._changes if c.kind == k)
             for k in (inventory.ADDED, inventory.REMOVED, inventory.CHANGED)}
        self.changes_label.setText(
            f"Since snapshot: {n[inventory.ADDED]} added, "
            f"{n[inventory.REMOVED]} removed, {n[inventory.CHANGED]} updated")

    def _apply_filter(self) -> None:
        needle = self.filter.text().lower().strip()
        rows = [a for a in self._apps
                if not needle or needle in a.name.lower()
                or needle in a.publisher.lower()]
        changed_keys = {c.app.key: c for c in self._changes
                        if c.kind != inventory.REMOVED}
        self.table.setRowCount(len(rows))
        for i, a in enumerate(rows):
            change = changed_keys.get(a.key)
            badge = QTableWidgetItem("" if change is None else change.kind[:3].upper())
            if change is not None:
                badge.setForeground(QColor(_CHANGE_COLOR[change.kind]))
            cells = [badge, QTableWidgetItem(a.name), QTableWidgetItem(a.version),
                     QTableWidgetItem(a.publisher), QTableWidgetItem(a.pretty_date()),
                     QTableWidgetItem("" if a.signature == "unchecked" else a.signature)]
            if a.signature == "unsigned":
                cells[5].setForeground(QColor("#e0b341"))
            for col, item in enumerate(cells):
                self.table.setItem(i, col, item)
        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.summary.setText(f"{len(rows)} shown / {len(self._apps)} installed")

    def _save_snapshot(self) -> None:
        if not self._apps:
            return
        try:
            inventory.save(self._apps)
        except OSError as exc:
            logbus.error("ui.inventory", f"could not save snapshot: {exc}")
            return
        logbus.success("ui.inventory", f"inventory snapshot saved ({len(self._apps)} apps)")
        self._changes = []
        self._render_changes()
        self._apply_filter()
