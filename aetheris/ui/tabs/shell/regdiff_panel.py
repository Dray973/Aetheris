"""Regshot-style registry differential: snapshot A → run installer → analyze."""
from __future__ import annotations

from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ....core import logbus, registry, report
from ._base import SRC, PanelBase

_CHANGE_COLORS = {"Added": "#5ee0a0", "Modified": "#e0b341", "Removed": "#ff5d6c"}


class RegistryDiffPanel(PanelBase):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._before: dict | None = None
        self._history: list = []
        self._last_diff_md = ""
        self._last_diff_rows: list = []
        v = QVBoxLayout(self)
        bar = QHBoxLayout()
        bar.addWidget(QLabel("Root:"))
        self.root_box = QComboBox()
        self.root_box.addItems(["HKCU", "HKLM", "HKCR", "HKU"])
        bar.addWidget(self.root_box)
        bar.addWidget(QLabel("Subkey:"))
        self.subkey = QLineEdit(r"SOFTWARE")
        bar.addWidget(self.subkey)
        v.addLayout(bar)
        row = QHBoxLayout()
        snap = QPushButton("1 ▸ Take snapshot")
        snap.clicked.connect(self._take_snapshot)
        row.addWidget(snap)
        ana = QPushButton("2 ▸ Run installer, then Analyze")
        ana.clicked.connect(self._analyze)
        row.addWidget(ana)
        save = QPushButton("Save A…")
        save.clicked.connect(self._save_snapshot)
        row.addWidget(save)
        load = QPushButton("Load A…")
        load.clicked.connect(self._load_snapshot)
        row.addWidget(load)
        self.diff_export = QPushButton("Export…")
        self.diff_export.setEnabled(False)
        self.diff_export.clicked.connect(self._export_diff)
        row.addWidget(self.diff_export)
        row.addStretch(1)
        self.diff_status = QLabel("no snapshot yet", objectName="subtle")
        self._status = self.diff_status
        row.addWidget(self.diff_status)
        v.addLayout(row)

        hist = QHBoxLayout()
        self.keep_history = QCheckBox("auto-save snapshots to history")
        self.keep_history.setChecked(True)
        hist.addWidget(self.keep_history)
        hist.addWidget(QLabel("History:"))
        self.history_combo = QComboBox()
        self.history_combo.setMinimumWidth(360)
        hist.addWidget(self.history_combo)
        load_hist = QPushButton("Load as A")
        load_hist.clicked.connect(self._load_from_history)
        hist.addWidget(load_hist)
        refresh_hist = QPushButton("↻")
        refresh_hist.setMaximumWidth(32)
        refresh_hist.clicked.connect(self._refresh_history)
        hist.addWidget(refresh_hist)
        hist.addStretch(1)
        v.addLayout(hist)
        self._refresh_history()

        views = QTabWidget()
        page = QWidget()
        pv = QVBoxLayout(page)
        self.diff_filter = QLineEdit(placeholderText="filter by key…")
        self.diff_filter.textChanged.connect(self._apply_diff_filter)
        pv.addWidget(self.diff_filter)
        self.diff_table = QTableWidget(0, 4)
        self.diff_table.setHorizontalHeaderLabels(["Change", "Key", "Before", "After"])
        self.diff_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.diff_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch)
        pv.addWidget(self.diff_table)
        views.addTab(page, "Changes")
        self.diff_out = QPlainTextEdit(readOnly=True)
        views.addTab(self.diff_out, "Markdown")
        v.addWidget(views)

    # -- snapshot / analyze --------------------------------------------------
    def _take_snapshot(self) -> None:
        # Capture the scope now: the user may edit the fields while it runs,
        # and the history entry must describe what was actually snapshotted.
        root, sub = self.root_box.currentText(), self.subkey.text().strip()
        if self._run(registry.snapshot_tree,
                     lambda tree: self._store_before(root, sub, tree), root, sub):
            self.diff_status.setText("snapshotting…")

    def _store_before(self, root: str, sub: str, tree) -> None:
        self._before = tree
        self.diff_status.setText(f"snapshot A captured: {len(tree)} keys")
        logbus.success(SRC, f"registry snapshot A: {len(tree)} keys")
        if self.keep_history.isChecked():
            registry.save_to_history(root, sub, tree)
            self._refresh_history()

    def _analyze(self) -> None:
        if self._before is None:
            self._toast(False, "take a snapshot first")
            return
        root, sub = self.root_box.currentText(), self.subkey.text().strip()
        if self._run(registry.snapshot_tree, self._render_diff, root, sub):
            self.diff_status.setText("analyzing…")

    def _render_diff(self, after) -> None:
        diff = registry.diff_trees(self._before, after)
        self._last_diff_md = diff.to_markdown()
        self._last_diff_rows = diff.rows()
        self.diff_out.setPlainText(self._last_diff_md)
        self._apply_diff_filter()
        self.diff_export.setEnabled(True)
        self.diff_status.setText(
            f"+{len(diff.added)} ~{len(diff.modified)} -{len(diff.removed)}")

    def _populate_diff_table(self, rows) -> None:
        self.diff_table.setRowCount(len(rows))
        for i, (change, key, before, after) in enumerate(rows):
            for c, val in enumerate([change, key, before, after]):
                item = QTableWidgetItem(val)
                if c == 0:
                    item.setForeground(QColor(_CHANGE_COLORS.get(change, "#c8d3f5")))
                self.diff_table.setItem(i, c, item)

    def _apply_diff_filter(self) -> None:
        rows = self._last_diff_rows
        needle = self.diff_filter.text().lower().strip()
        shown = [r for r in rows if needle in r[1].lower()] if needle else rows
        self._populate_diff_table(shown)

    # -- history / files -----------------------------------------------------
    def _refresh_history(self) -> None:
        self.history_combo.clear()
        self._history = registry.list_history()
        for e in self._history:
            self.history_combo.addItem(e.display(), e.path)
        if not self._history:
            self.history_combo.addItem("(no saved snapshots)", None)

    def _load_from_history(self) -> None:
        path = self.history_combo.currentData()
        if not path:
            self._toast(False, "no snapshot selected")
            return
        self._load_as_a(registry.load_history, path, "from history")

    def _save_snapshot(self) -> None:
        if self._before is None:
            self._toast(False, "take a snapshot first")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save snapshot A", "registry-snapshot.json", "JSON (*.json)")
        if not path:
            return
        ok, msg = registry.save_snapshot(self._before, path)
        self._toast(ok, msg)

    def _load_snapshot(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Load snapshot as A", "", "JSON (*.json)")
        if path:
            self._load_as_a(registry.load_snapshot, path, f"from {path}")

    def _load_as_a(self, loader, path: str, origin: str) -> None:
        try:
            self._before = loader(path)
        except Exception as exc:  # noqa: BLE001
            self._toast(False, f"load failed: {exc}")
            return
        self.diff_status.setText(f"snapshot A loaded: {len(self._before)} keys")
        logbus.success(SRC, f"registry snapshot A loaded {origin}")

    def _export_diff(self) -> None:
        md = self._last_diff_md
        if not md:
            self._toast(False, "run an analysis first")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export registry diff", "registry-diff.md",
            "Markdown (*.md);;HTML (*.html)")
        if not path:
            return
        try:
            if path.lower().endswith(".html"):
                content = report.html_document(
                    "Registry Differential Report", [("Diff", "pre", md)])
            else:
                content = md
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
            self._toast(True, f"registry diff exported -> {path}")
        except Exception as exc:  # noqa: BLE001
            self._toast(False, str(exc))
