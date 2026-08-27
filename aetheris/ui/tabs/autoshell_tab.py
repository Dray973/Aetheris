"""
Module 5 — Natural Language Autonomous Control Shell.

Type an instruction, the deterministic router compiles it to PowerShell, the
generated script + explanation + risk are shown, and nothing runs until the
user explicitly clicks Execute.
"""
from __future__ import annotations

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QPlainTextEdit, QMessageBox,
)
from PyQt6.QtGui import QFont

from ...automation import nlshell
from ...core import logbus
from ..workers import Worker

_EXAMPLES = (
    "Find every zip archive created this morning on drive E and move them to my desktop.",
    "Terminate all background processes utilizing more than 350MB of system memory right now.",
    "Isolate my web browser execution context exclusively to CPU cores 4, 5, and 6.",
)


class AutoShellTab(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._compiled: nlshell.CompiledCommand | None = None
        self._worker: Worker | None = None
        self._build()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.addWidget(QLabel("Natural Language Autonomous Control Shell", objectName="title"))
        root.addWidget(QLabel(
            "Plain-English → reviewed PowerShell. Nothing runs without your confirmation.",
            objectName="subtle"))

        bar = QHBoxLayout()
        self.input = QLineEdit(placeholderText="e.g. " + _EXAMPLES[1])
        self.input.returnPressed.connect(self._compile)
        bar.addWidget(self.input)
        comp = QPushButton("Compile")
        comp.clicked.connect(self._compile)
        bar.addWidget(comp)
        root.addLayout(bar)

        ex = QHBoxLayout()
        ex.addWidget(QLabel("examples:", objectName="subtle"))
        for i, e in enumerate(_EXAMPLES):
            b = QPushButton(f"#{i+1}")
            b.setToolTip(e)
            b.clicked.connect(lambda _=False, s=e: self.input.setText(s))
            ex.addWidget(b)
        ex.addStretch(1)
        root.addLayout(ex)

        self.explain = QLabel("", objectName="subtle")
        self.explain.setWordWrap(True)
        root.addWidget(self.explain)

        self.script_view = QPlainTextEdit(readOnly=True)
        self.script_view.setFont(QFont("Cascadia Code", 10))
        self.script_view.setPlaceholderText("Compiled PowerShell will appear here.")
        root.addWidget(self.script_view)

        run_bar = QHBoxLayout()
        self.risk_lbl = QLabel("", objectName="subtle")
        run_bar.addWidget(self.risk_lbl)
        run_bar.addStretch(1)
        self.exec_btn = QPushButton("Execute (requires confirmation)")
        self.exec_btn.setEnabled(False)
        self.exec_btn.clicked.connect(self._execute)
        run_bar.addWidget(self.exec_btn)
        root.addLayout(run_bar)

        self.output = QPlainTextEdit(readOnly=True)
        self.output.setPlaceholderText("Execution output…")
        root.addWidget(self.output)

    def _compile(self) -> None:
        text = self.input.text().strip()
        if not text:
            return
        cmd = nlshell.compile(text)
        self._compiled = cmd
        self.explain.setText(cmd.explanation)
        self.script_view.setPlainText(cmd.script or "# (no script generated)")
        warn = ("  ⚠ " + "; ".join(cmd.warnings)) if cmd.warnings else ""
        self.risk_lbl.setText(f"intent: {cmd.intent}   risk: {cmd.risk.upper()}{warn}")
        self.exec_btn.setEnabled(cmd.matched and bool(cmd.script))

    def _execute(self) -> None:
        cmd = self._compiled
        if not cmd or not cmd.matched:
            return
        if QMessageBox.warning(
            self, "Confirm execution",
            f"Run this {cmd.risk.upper()}-risk command?\n\n{cmd.script}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        self.output.setPlainText("running…")
        self.exec_btn.setEnabled(False)
        self._worker = Worker(nlshell.run, cmd)
        self._worker.done.connect(self._show_output)
        self._worker.failed.connect(lambda e: self._show_output((False, e)))
        self._worker.start()

    def _show_output(self, result) -> None:
        ok, out = result
        self.output.setPlainText(out)
        self.exec_btn.setEnabled(True)
        (logbus.success if ok else logbus.error)("ui.autoshell",
                                                 "command finished" if ok else "command failed")
