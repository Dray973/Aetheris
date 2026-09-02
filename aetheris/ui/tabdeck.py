"""
A compact module navigator — a dropdown over a stacked page area.

With a dozen modules a tab strip gets cluttered, so the top-level navigation is a
single **dropdown** instead. ``TabDeck`` is a drop-in for the small slice of the
``QTabWidget`` API the app uses (``addTab`` / ``count`` / ``widget`` /
``currentWidget`` / ``currentIndex`` / ``setCurrentIndex`` / ``tabText`` /
``currentChanged``), so the main window, screenshot generator and demo driver
keep working unchanged. Inner per-tab sub-panels stay real ``QTabWidget``s.
"""
from __future__ import annotations

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)


class TabDeck(QWidget):
    currentChanged = pyqtSignal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._combo = QComboBox()
        self._combo.setObjectName("nav")
        self._combo.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToContents)
        self._stack = QStackedWidget()

        bar = QHBoxLayout()
        bar.setContentsMargins(10, 8, 10, 8)
        bar.setSpacing(10)
        bar.addWidget(QLabel("Module", objectName="subtle"))
        bar.addWidget(self._combo)
        bar.addStretch(1)
        navbar = QWidget()
        navbar.setObjectName("navbar")
        navbar.setLayout(bar)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(navbar)
        root.addWidget(self._stack, 1)

        self._combo.currentIndexChanged.connect(self._stack.setCurrentIndex)
        self._combo.currentIndexChanged.connect(self.currentChanged)

    # -- QTabWidget-compatible subset --------------------------------------
    def addTab(self, widget: QWidget, label: str) -> int:
        self._stack.addWidget(widget)
        self._combo.addItem(label)
        return self._stack.count() - 1

    def count(self) -> int:
        return self._stack.count()

    def widget(self, index: int) -> QWidget | None:
        return self._stack.widget(index)

    def currentWidget(self) -> QWidget | None:
        return self._stack.currentWidget()

    def currentIndex(self) -> int:
        return self._combo.currentIndex()

    def setCurrentIndex(self, index: int) -> None:
        self._combo.setCurrentIndex(index)

    def tabText(self, index: int) -> str:
        return self._combo.itemText(index)
