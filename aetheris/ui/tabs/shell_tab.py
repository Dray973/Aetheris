"""
Module 4 — Windows Shell Engineer & Registry Snapshot Diff Suite.

Regshot-style differential tracker (snapshot → run installer → analyze), the
privacy/telemetry toggles (each reversible via the rollback ledger), a
context-menu editor, and the autoruns / services / scheduled-task /
persistence auditors. Each sub-panel lives in its own module under
``aetheris.ui.tabs.shell`` and owns its own background worker.
"""
from __future__ import annotations

from PySide6.QtWidgets import QLabel, QTabWidget, QVBoxLayout, QWidget

from .shell import (
    AutorunsPanel,
    ContextMenuPanel,
    PersistencePanel,
    PrivacyPanel,
    RegistryDiffPanel,
    ServicesPanel,
    TasksPanel,
)


class ShellTab(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.addWidget(QLabel("Windows Shell Engineer & Registry Diff", objectName="title"))
        self.regdiff = RegistryDiffPanel()
        self.privacy = PrivacyPanel()
        self.ctxmenu = ContextMenuPanel()
        self.autoruns = AutorunsPanel()
        self.services = ServicesPanel()
        self.tasks = TasksPanel()
        self.persistence = PersistencePanel()
        tabs = QTabWidget()
        tabs.addTab(self.regdiff, "Registry Diff")
        tabs.addTab(self.privacy, "Privacy Exterminator")
        tabs.addTab(self.ctxmenu, "Context Menu")
        tabs.addTab(self.autoruns, "Autoruns")
        tabs.addTab(self.services, "Services & Drivers")
        tabs.addTab(self.tasks, "Scheduled Tasks")
        tabs.addTab(self.persistence, "Persistence Map")
        root.addWidget(tabs)
