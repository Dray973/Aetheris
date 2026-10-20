"""Scheduled-task auditor: suspicious actions, signatures, reversible toggles."""
from __future__ import annotations

from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
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


class TasksPanel(PanelBase):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._tasks: list = []
        self._filtered_tasks: list = []
        v = QVBoxLayout(self)
        v.addWidget(QLabel(
            "Every scheduled task, flagged for temp-dir actions, unsigned "
            "binaries, encoded shell commands, and logon/boot persistence "
            "(suspicious = red). Enable/Disable is reversible (PANIC restores).",
            objectName="subtle"))
        bar = QHBoxLayout()
        self.task_filter = QLineEdit(placeholderText="filter by name/path…")
        self.task_filter.textChanged.connect(self._apply_task_filter)
        bar.addWidget(self.task_filter)
        self.task_scope = QComboBox()
        self.task_scope.addItems(["All", "Suspicious only", "Enabled only"])
        self.task_scope.currentIndexChanged.connect(self._apply_task_filter)
        bar.addWidget(self.task_scope)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self._refresh_tasks)
        bar.addWidget(refresh)
        v.addLayout(bar)

        self.task_table = QTableWidget(0, 6)
        self.task_table.setHorizontalHeaderLabels(
            ["Task", "Enabled", "Triggers", "Signed", "Flags", "Action"])
        self.task_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.task_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.task_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch)
        v.addWidget(self.task_table)

        ctl = QHBoxLayout()
        for label, en in (("Disable", False), ("Enable", True)):
            b = QPushButton(label)
            b.clicked.connect(lambda _=False, e=en: self._task_control(e))
            ctl.addWidget(b)
        export = QPushButton("Export audit…")
        export.clicked.connect(self._export_tasks)
        ctl.addWidget(export)
        ctl.addStretch(1)
        self.task_count = QLabel("Click Refresh to audit scheduled tasks.",
                                 objectName="subtle")
        self._status = self.task_count
        ctl.addWidget(self.task_count)
        v.addLayout(ctl)

    def _refresh_tasks(self) -> None:
        from ....core import taskaudit
        if self._run(taskaudit.enumerate_tasks, self._show_tasks):
            self.task_count.setText("auditing…")

    def _show_tasks(self, rows) -> None:
        self._tasks = rows
        self._apply_task_filter()

    def _apply_task_filter(self) -> None:
        from ....core import taskaudit
        needle = self.task_filter.text().lower().strip()
        scope = self.task_scope.currentText()
        rows = self._tasks
        if scope == "Suspicious only":
            rows = [t for t in rows if taskaudit.is_suspicious(t)]
        elif scope == "Enabled only":
            rows = [t for t in rows if t.enabled]
        if needle:
            rows = [t for t in rows
                    if needle in t.path.lower() or needle in t.name.lower()]
        self._filtered_tasks = rows
        tb = self.task_table
        tb.setRowCount(len(rows))
        for i, t in enumerate(rows):
            action = t.actions[0] if t.actions else ""
            vals = [t.path, "yes" if t.enabled else "no", ", ".join(t.triggers),
                    t.signed, "; ".join(t.flags), action]
            suspicious = taskaudit.is_suspicious(t)
            for c, val in enumerate(vals):
                item = QTableWidgetItem(str(val))
                if suspicious:
                    item.setForeground(QColor("#ff5d6c"))
                elif not t.enabled:
                    item.setForeground(QColor("#7a7f8a"))
                tb.setItem(i, c, item)
        n_susp = sum(1 for t in self._tasks if taskaudit.is_suspicious(t))
        self.task_count.setText(
            f"{len(rows)} shown / {len(self._tasks)} total  ·  {n_susp} suspicious")

    def _selected_task(self):
        row = self.task_table.currentRow()
        if 0 <= row < len(self._filtered_tasks):
            return self._filtered_tasks[row]
        return None

    def _task_control(self, enable: bool) -> None:
        from ....core import taskaudit
        t = self._selected_task()
        if t is None:
            self._toast(False, "select a task first")
            return
        verb = "enable" if enable else "disable"
        if not self._confirm("Task control",
                             f"{verb} task:\n\n{t.path}\n\n(Reversible via PANIC.)"):
            return
        fn = taskaudit.enable_task if enable else taskaudit.disable_task
        self._run(fn, self._show_result_then(self._refresh_tasks), t.path)

    def _export_tasks(self) -> None:
        from ....core import taskaudit
        if not self._tasks:
            self._toast(False, "refresh first")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export task audit",
                                              "task-audit.md", "Markdown (*.md)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(taskaudit.render_markdown(self._tasks, only_suspicious=False))
            self._toast(True, f"wrote {path}")
        except OSError as exc:
            self._toast(False, str(exc))
