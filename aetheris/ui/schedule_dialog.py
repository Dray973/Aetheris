"""
Scheduled-capture dialog — register/remove a Windows scheduled task that runs
``aetheris-cli`` to write a session report on an interval.
"""
from __future__ import annotations

import os

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QSpinBox, QComboBox,
    QPushButton, QFileDialog, QPlainTextEdit,
)

from ..core import scheduler, logbus
from .theme import QSS


class ScheduleDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Schedule automatic capture")
        self.setStyleSheet(QSS)
        self.resize(640, 460)
        self._build()
        self._refresh_status()

    def _build(self) -> None:
        v = QVBoxLayout(self)
        v.addWidget(QLabel("Automatic Forensic Capture", objectName="title"))
        v.addWidget(QLabel(
            "Registers a Windows scheduled task that runs the headless CLI to "
            "write a session report on an interval (per-user; no admin needed).",
            objectName="subtle"))

        row = QHBoxLayout()
        row.addWidget(QLabel("Report file:"))
        default_out = os.path.join(os.path.expanduser("~"), "aetheris-report.html")
        self.out = QLineEdit(default_out)
        row.addWidget(self.out)
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse)
        row.addWidget(browse)
        v.addLayout(row)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Every"))
        self.minutes = QSpinBox()
        self.minutes.setRange(1, 10080)
        self.minutes.setValue(60)
        self.minutes.setSuffix(" min")
        row2.addWidget(self.minutes)
        row2.addWidget(QLabel("Format:"))
        self.fmt = QComboBox()
        self.fmt.addItems(["html", "md"])
        row2.addWidget(self.fmt)
        row2.addStretch(1)
        v.addLayout(row2)

        btns = QHBoxLayout()
        create = QPushButton("Create / Update task")
        create.clicked.connect(self._create)
        btns.addWidget(create)
        remove = QPushButton("Remove task")
        remove.clicked.connect(self._remove)
        btns.addWidget(remove)
        btns.addStretch(1)
        v.addLayout(btns)

        self.status = QPlainTextEdit(readOnly=True)
        v.addWidget(self.status)

    def _browse(self) -> None:
        f, _ = QFileDialog.getSaveFileName(self, "Report file", self.out.text(),
                                           "HTML (*.html);;Markdown (*.md)")
        if f:
            self.out.setText(f)

    def _refresh_status(self) -> None:
        if scheduler.task_exists():
            self.status.setPlainText("Task ACTIVE:\n\n" + (scheduler.task_info() or ""))
        else:
            self.status.setPlainText("No scheduled capture task is currently registered.\n"
                                     "\nCommand that would run:\n  "
                                     + scheduler.capture_command(self.out.text(),
                                                                 self.fmt.currentText()))

    def _create(self) -> None:
        ok, msg = scheduler.create_capture_task(
            self.out.text().strip(), self.minutes.value(), fmt=self.fmt.currentText())
        (logbus.success if ok else logbus.error)("ui.schedule", msg)
        self._refresh_status()

    def _remove(self) -> None:
        ok, msg = scheduler.delete_task()
        (logbus.success if ok else logbus.error)("ui.schedule", msg)
        self._refresh_status()
