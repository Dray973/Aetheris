"""
Plugins tab — run custom/extension tools and view their output.

Lists every discovered plugin (built-in + user), runs the selected one on a
worker thread, and shows/export its text output. Same plugins are runnable
headlessly via ``aetheris-cli run <name>``.
"""
from __future__ import annotations

import os

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QListWidget, QListWidgetItem, QLabel,
    QPushButton, QPlainTextEdit, QSplitter, QFileDialog, QStackedWidget,
)
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt

from ...core import plugins, logbus
from ..workers import Worker


class PluginsTab(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._plugins: list[plugins.Plugin] = []
        self._worker: Worker | None = None
        self._build()
        self.reload()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.addWidget(QLabel("Plugins & Extensions", objectName="title"))
        root.addWidget(QLabel(
            f"Drop custom *.py tools in  {plugins.user_dir()}  — or run any of "
            "these headlessly with  aetheris-cli run <name>.", objectName="subtle"))

        split = QSplitter(Qt.Orientation.Horizontal)
        self.list = QListWidget()
        self.list.itemSelectionChanged.connect(self._on_select)
        self.list.itemDoubleClicked.connect(lambda _i: self._run())
        split.addWidget(self.list)

        right = QWidget()
        rv = QVBoxLayout(right)
        self.desc = QLabel("", objectName="subtle")
        self.desc.setWordWrap(True)
        rv.addWidget(self.desc)
        # Page 0: text output. Page 1: host for GUI (widget) plugins.
        self.stack = QStackedWidget()
        self.output = QPlainTextEdit(readOnly=True)
        self.output.setFont(QFont("Cascadia Code", 10))
        self.output.setPlaceholderText("Select a plugin and Run.")
        self.stack.addWidget(self.output)
        self.widget_host = QWidget()
        self._host_layout = QVBoxLayout(self.widget_host)
        self._host_layout.setContentsMargins(0, 0, 0, 0)
        self.stack.addWidget(self.widget_host)
        rv.addWidget(self.stack)
        split.addWidget(right)
        split.setSizes([320, 900])
        root.addWidget(split)

        bar = QHBoxLayout()
        run = QPushButton("Run")
        run.clicked.connect(self._run)
        bar.addWidget(run)
        reload = QPushButton("Reload")
        reload.clicked.connect(self.reload)
        bar.addWidget(reload)
        export = QPushButton("Export output…")
        export.clicked.connect(self._export)
        bar.addWidget(export)
        bar.addStretch(1)
        self.count_lbl = QLabel("", objectName="subtle")
        bar.addWidget(self.count_lbl)
        root.addLayout(bar)

    def reload(self) -> None:
        self._plugins = plugins.discover()
        self.list.clear()
        for p in self._plugins:
            self.list.addItem(QListWidgetItem(p.name))
        self.count_lbl.setText(f"{len(self._plugins)} plugin(s)")
        logbus.trace("ui.plugins", f"listed {len(self._plugins)} plugins")

    def _selected(self) -> plugins.Plugin | None:
        row = self.list.currentRow()
        if 0 <= row < len(self._plugins):
            return self._plugins[row]
        return None

    def _on_select(self) -> None:
        p = self._selected()
        kind = f"  ·  {p.kind} plugin" if p else ""
        self.desc.setText(f"{p.name} — {p.description}{kind}   [{p.source}]" if p else "")

    def _clear_host(self) -> None:
        while self._host_layout.count():
            item = self._host_layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()

    def _run(self) -> None:
        p = self._selected()
        if p is None:
            return
        if p.kind == "widget":
            # GUI plugin: build and embed its widget (runs on the UI thread).
            self._clear_host()
            try:
                self._host_layout.addWidget(p.widget())
                self.stack.setCurrentWidget(self.widget_host)
                logbus.success("ui.plugins", f"opened widget plugin: {p.name}")
            except Exception as exc:  # noqa: BLE001
                self.stack.setCurrentWidget(self.output)
                self.output.setPlainText(f"widget plugin error: {exc}")
                logbus.error("ui.plugins", f"widget plugin {p.name} failed: {exc}")
            return
        if self._worker and self._worker.isRunning():
            return
        self.stack.setCurrentWidget(self.output)
        self.output.setPlainText(f"running {p.name}…")
        self._worker = Worker(plugins.run_plugin, p.name)
        self._worker.done.connect(self._show)
        self._worker.failed.connect(lambda e: self.output.setPlainText(e))
        self._worker.start()

    def _show(self, result) -> None:
        ok, text = result
        self.output.setPlainText(text)
        (logbus.success if ok else logbus.error)(
            "ui.plugins", "plugin finished" if ok else "plugin failed")

    def _export(self) -> None:
        text = self.output.toPlainText()
        if not text.strip():
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export plugin output", "plugin-output.txt", "Text (*.txt);;Markdown (*.md)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            logbus.success("ui.plugins", f"output exported -> {path}")
        except Exception as exc:  # noqa: BLE001
            logbus.error("ui.plugins", str(exc))
