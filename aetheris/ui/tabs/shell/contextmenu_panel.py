"""Context-menu editor: list shell handlers, add commands and cascading menus."""
from __future__ import annotations

from PySide6.QtWidgets import (
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ....core import registry
from ._base import PanelBase

_CASCADE_SAMPLE = (
    "Aetheris Tools | \n"
    "  Open PowerShell here | powershell.exe -NoExit -Command \"cd '%V'\"\n"
    "  Hashing\n"
    "    SHA-256 this file | powershell.exe -Command \"Get-FileHash '%1'\"\n"
    "    MD5 this file | powershell.exe -Command \"Get-FileHash -Algorithm MD5 '%1'\""
)


class ContextMenuPanel(PanelBase):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        v = QVBoxLayout(self)
        v.addWidget(QLabel(r"Handlers under HKCR\*\shellex\ContextMenuHandlers:",
                           objectName="subtle"))
        self.ctx_list = QListWidget()
        v.addWidget(self.ctx_list)
        row = QHBoxLayout()
        add = QPushButton("Add background command…")
        add.clicked.connect(self._add_ctx)
        row.addWidget(add)
        cascade = QPushButton("Add cascading submenu…")
        cascade.clicked.connect(self._add_cascading)
        row.addWidget(cascade)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self._refresh)
        row.addWidget(refresh)
        row.addStretch(1)
        v.addLayout(row)
        self._refresh()

    def _refresh(self) -> None:
        self.ctx_list.clear()
        for h in registry.read_context_handlers():
            self.ctx_list.addItem(QListWidgetItem(h))

    def _add_ctx(self) -> None:
        label, ok = QInputDialog.getText(self, "Context command", "Menu label:")
        if not ok or not label.strip():
            return
        cmd, ok = QInputDialog.getText(self, "Context command",
                                       "Command (e.g. cmd.exe /k cd %V):")
        if not ok or not cmd.strip():
            return
        good, msg = registry.add_context_command(label.strip(), cmd.strip())
        self._toast(good, msg)

    def _add_cascading(self) -> None:
        top, ok = QInputDialog.getText(
            self, "Cascading submenu", "Top-level menu label:", text="Aetheris Tools")
        if not ok or not top.strip():
            return
        spec, ok = QInputDialog.getMultiLineText(
            self, "Cascading submenu",
            "Items — 2-space indent = nesting, 'label | command' = leaf:",
            _CASCADE_SAMPLE)
        if not ok or not spec.strip():
            return
        items = registry.parse_menu_spec(spec)
        if len(items) == 1 and items[0].children:
            items = items[0].children
        good, msg = registry.add_cascading_menu(top.strip(), items)
        self._toast(good, msg)
