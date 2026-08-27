"""
Live API log drawer — the scrolling audit console docked at the bottom.

Subscribes to the core log bus. Because the bus is Qt-signal based, events
emitted from any worker thread are marshalled onto the GUI thread automatically,
so appends here are always thread-safe.
"""
from __future__ import annotations

import time

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPlainTextEdit, QComboBox, QLabel,
    QPushButton, QCheckBox,
)
from PyQt6.QtGui import QTextCharFormat, QColor, QTextCursor, QFont

from ..core import logbus
from ..core.logbus import Level, LogEvent
from .theme import LEVEL_COLORS

_ORDER = [Level.TRACE, Level.INFO, Level.SUCCESS, Level.ACTION, Level.WARN, Level.ERROR]


class LogDrawer(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._min_level = Level.TRACE
        self._autoscroll = True
        self._build()
        logbus.subscribe(self._on_event)
        logbus.log("ui.logdrawer", "Audit console online.", Level.SUCCESS)

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(6, 4, 6, 6)

        bar = QHBoxLayout()
        bar.addWidget(QLabel("Live API Audit Stream", objectName="subtle"))
        bar.addStretch(1)
        bar.addWidget(QLabel("min level:"))
        self.level_box = QComboBox()
        for lv in _ORDER:
            self.level_box.addItem(lv.value, lv)
        # Restore persisted verbosity + autoscroll.
        from ..core.settings import settings
        self._settings = settings()
        saved_level = self._settings.get("log_min_level", Level.TRACE.value)
        for i, lv in enumerate(_ORDER):
            if lv.value == saved_level:
                self.level_box.setCurrentIndex(i)
                self._min_level = lv
                break
        self.level_box.currentIndexChanged.connect(self._set_level)
        bar.addWidget(self.level_box)
        self.autoscroll_cb = QCheckBox("autoscroll")
        self._autoscroll = bool(self._settings.get("log_autoscroll", True))
        self.autoscroll_cb.setChecked(self._autoscroll)
        self.autoscroll_cb.toggled.connect(self._set_autoscroll)
        bar.addWidget(self.autoscroll_cb)
        clear = QPushButton("Clear")
        clear.clicked.connect(lambda: self.view.clear())
        bar.addWidget(clear)
        root.addLayout(bar)

        self.view = QPlainTextEdit()
        self.view.setReadOnly(True)
        self.view.setMaximumBlockCount(5000)  # ring buffer
        self.view.setFont(QFont("Cascadia Code", 10))
        root.addWidget(self.view)

    def _set_level(self, idx: int) -> None:
        self._min_level = self.level_box.itemData(idx)
        self._settings.set("log_min_level", self._min_level.value)

    def _set_autoscroll(self, v: bool) -> None:
        self._autoscroll = v
        self._settings.set("log_autoscroll", v)

    def _on_event(self, ev: LogEvent) -> None:
        if _ORDER.index(ev.level) < _ORDER.index(self._min_level):
            return
        ts = time.strftime("%H:%M:%S", time.localtime(ev.ts))
        color = QColor(LEVEL_COLORS.get(ev.level, "#c8d3f5"))
        fmt = QTextCharFormat()
        fmt.setForeground(color)
        cursor = self.view.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        detail = f"  «{ev.detail}»" if ev.detail else ""
        cursor.insertText(
            f"{ts}  {ev.level.value:<7} {ev.source:<22} {ev.message}{detail}\n", fmt
        )
        if self._autoscroll:
            self.view.verticalScrollBar().setValue(
                self.view.verticalScrollBar().maximum()
            )
