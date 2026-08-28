"""
Module 4 — Windows Shell Engineer & Registry Snapshot Diff Suite.

Regshot-style differential tracker (snapshot → run installer → analyze), the
privacy/telemetry toggles (each reversible via the rollback ledger), and a
context-menu editor.
"""
from __future__ import annotations

from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ...core import logbus, registry, report
from ..workers import Worker

_CHANGE_COLORS = {"Added": "#5ee0a0", "Modified": "#e0b341", "Removed": "#ff5d6c"}


class ShellTab(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._before: dict | None = None
        self._worker: Worker | None = None
        self._build()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.addWidget(QLabel("Windows Shell Engineer & Registry Diff", objectName="title"))
        tabs = QTabWidget()
        tabs.addTab(self._diff_panel(), "Registry Diff")
        tabs.addTab(self._privacy_panel(), "Privacy Exterminator")
        tabs.addTab(self._ctx_panel(), "Context Menu")
        tabs.addTab(self._autoruns_panel(), "Autoruns")
        root.addWidget(tabs)

    # -- autoruns -----------------------------------------------------------
    def _autoruns_panel(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.addWidget(QLabel(
            "Everything that launches at logon/boot (Run/RunOnce keys + Startup "
            "folders). Disable is reversible (PANIC restores it).",
            objectName="subtle"))
        self.autoruns_table = QTableWidget(0, 4)
        self.autoruns_table.setHorizontalHeaderLabels(
            ["Name", "Command", "Location", "Enabled"])
        self.autoruns_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self.autoruns_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.autoruns_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch)
        v.addWidget(self.autoruns_table)
        row = QHBoxLayout()
        for label, slot in (("Refresh", self._refresh_autoruns),
                            ("Disable", lambda: self._toggle_autorun(False)),
                            ("Enable", lambda: self._toggle_autorun(True))):
            b = QPushButton(label)
            b.clicked.connect(slot)
            row.addWidget(b)
        row.addStretch(1)
        self.autoruns_count = QLabel("", objectName="subtle")
        row.addWidget(self.autoruns_count)
        v.addLayout(row)
        self._refresh_autoruns()
        return w

    def _refresh_autoruns(self) -> None:
        from ...core import autoruns
        self.autoruns_count.setText("enumerating…")
        self._run(autoruns.enumerate_entries, self._show_autoruns)

    def _show_autoruns(self, entries) -> None:
        self._autoruns = entries
        t = self.autoruns_table
        t.setRowCount(len(self._autoruns))
        for i, e in enumerate(self._autoruns):
            for c, val in enumerate([e.name, e.command, e.location,
                                     "yes" if e.enabled else "DISABLED"]):
                item = QTableWidgetItem(val)
                if not e.enabled:
                    item.setForeground(QColor("#ff5d6c"))
                t.setItem(i, c, item)
        n_off = sum(1 for e in self._autoruns if not e.enabled)
        self.autoruns_count.setText(
            f"{len(self._autoruns)} entries ({n_off} disabled)")

    def _toggle_autorun(self, enable: bool) -> None:
        from ...core import autoruns
        row = self.autoruns_table.currentRow()
        if not (0 <= row < len(self._autoruns)):
            return
        e = self._autoruns[row]
        if enable and e.enabled:
            self._toast(False, "already enabled")
            return
        if not enable and not e.enabled:
            self._toast(False, "already disabled")
            return
        ok, msg = autoruns.enable(e) if enable else autoruns.disable(e)
        self._toast(ok, msg)
        self._refresh_autoruns()

    # -- registry diff ------------------------------------------------------
    def _diff_panel(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
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
        row.addWidget(self.diff_status)
        v.addLayout(row)

        # -- snapshot history (auto-saved, point-in-time diffing) --
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
        # -- structured, color-coded, filterable change table --
        page = QWidget()
        pv = QVBoxLayout(page)
        self.diff_filter = QLineEdit(placeholderText="filter by key…")
        self.diff_filter.textChanged.connect(self._apply_diff_filter)
        pv.addWidget(self.diff_filter)
        self.diff_table = QTableWidget(0, 4)
        self.diff_table.setHorizontalHeaderLabels(["Change", "Key", "Before", "After"])
        self.diff_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.diff_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        pv.addWidget(self.diff_table)
        views.addTab(page, "Changes")
        # -- raw markdown --
        self.diff_out = QPlainTextEdit(readOnly=True)
        views.addTab(self.diff_out, "Markdown")
        v.addWidget(views)
        return w

    def _run(self, fn, on_done, *args) -> None:
        """Run a blocking native call on the shared Worker (keeps the UI live)."""
        if self._worker and self._worker.isRunning():
            self._toast(False, "a task is already running")
            return
        self._worker = Worker(fn, *args)
        self._worker.done.connect(on_done)
        self._worker.failed.connect(lambda e: self._toast(False, e))
        self._worker.start()

    def _take_snapshot(self) -> None:
        root, sub = self.root_box.currentText(), self.subkey.text().strip()
        self.diff_status.setText("snapshotting…")
        self._worker = Worker(registry.snapshot_tree, root, sub)
        self._worker.done.connect(self._store_before)
        self._worker.failed.connect(lambda e: self._toast(False, e))
        self._worker.start()

    def _store_before(self, tree) -> None:
        self._before = tree
        self.diff_status.setText(f"snapshot A captured: {len(tree)} keys")
        logbus.success("ui.shell", f"registry snapshot A: {len(tree)} keys")
        if self.keep_history.isChecked():
            registry.save_to_history(self.root_box.currentText(),
                                     self.subkey.text().strip(), tree)
            self._refresh_history()

    # -- snapshot history ---------------------------------------------------
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
        try:
            self._before = registry.load_history(path)
            self.diff_status.setText(
                f"snapshot A loaded from history: {len(self._before)} keys")
            logbus.success("ui.shell", f"loaded history snapshot as A: {path}")
        except Exception as exc:  # noqa: BLE001
            self._toast(False, f"load failed: {exc}")

    def _analyze(self) -> None:
        if self._before is None:
            self._toast(False, "take a snapshot first")
            return
        root, sub = self.root_box.currentText(), self.subkey.text().strip()
        self.diff_status.setText("analyzing…")
        self._worker = Worker(registry.snapshot_tree, root, sub)
        self._worker.done.connect(self._render_diff)
        self._worker.failed.connect(lambda e: self._toast(False, e))
        self._worker.start()

    def _render_diff(self, after) -> None:
        diff = registry.diff_trees(self._before, after)
        self._last_diff_md = diff.to_markdown()
        self._last_diff_rows = diff.rows()
        self.diff_out.setPlainText(self._last_diff_md)
        self._populate_diff_table(self._last_diff_rows)
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
        rows = getattr(self, "_last_diff_rows", [])
        needle = self.diff_filter.text().lower().strip()
        shown = [r for r in rows if needle in r[1].lower()] if needle else rows
        self._populate_diff_table(shown)

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
        if not path:
            return
        try:
            self._before = registry.load_snapshot(path)
            self.diff_status.setText(f"snapshot A loaded: {len(self._before)} keys")
            logbus.success("ui.shell", f"registry snapshot A loaded from {path}")
        except Exception as exc:  # noqa: BLE001
            self._toast(False, f"load failed: {exc}")

    def _export_diff(self) -> None:
        md = getattr(self, "_last_diff_md", "")
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

    # -- privacy ------------------------------------------------------------
    def _privacy_panel(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.addWidget(QLabel("Each toggle is reversible via PANIC or the rollback ledger.",
                           objectName="subtle"))
        for key, (_r, _s, _n, _d, label) in registry.PRIVACY_TOGGLES.items():
            b = QPushButton(label)
            b.clicked.connect(lambda _=False, k=key: self._apply_toggle(k))
            v.addWidget(b)
        dt = QPushButton("Stop + disable DiagTrack (Connected User Experiences) service")
        dt.clicked.connect(self._disable_diagtrack)
        v.addWidget(dt)
        v.addStretch(1)
        return w

    def _apply_toggle(self, key: str) -> None:
        ok, msg = registry.apply_privacy_toggle(key)
        self._toast(ok, msg)

    def _disable_diagtrack(self) -> None:
        if QMessageBox.question(self, "DiagTrack",
                                "Stop and disable the DiagTrack service?") \
                != QMessageBox.StandardButton.Yes:
            return
        # Two `sc` calls at 30 s timeout each -> offload so the UI never freezes.
        self._run(registry.disable_diagtrack_service, self._show_diagtrack)

    def _show_diagtrack(self, res) -> None:
        ok, msg = res
        self._toast(ok, msg)

    # -- context menu -------------------------------------------------------
    def _ctx_panel(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.addWidget(QLabel(r"Handlers under HKCR\*\shellex\ContextMenuHandlers:",
                           objectName="subtle"))
        self.ctx_list = QListWidget()
        for h in registry.read_context_handlers():
            self.ctx_list.addItem(QListWidgetItem(h))
        v.addWidget(self.ctx_list)
        row = QHBoxLayout()
        add = QPushButton("Add background command…")
        add.clicked.connect(self._add_ctx)
        row.addWidget(add)
        cascade = QPushButton("Add cascading submenu…")
        cascade.clicked.connect(self._add_cascading)
        row.addWidget(cascade)
        row.addStretch(1)
        v.addLayout(row)
        return w

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

    _CASCADE_SAMPLE = (
        "Aetheris Tools | \n"
        "  Open PowerShell here | powershell.exe -NoExit -Command \"cd '%V'\"\n"
        "  Hashing\n"
        "    SHA-256 this file | powershell.exe -Command \"Get-FileHash '%1'\"\n"
        "    MD5 this file | powershell.exe -Command \"Get-FileHash -Algorithm MD5 '%1'\""
    )

    def _add_cascading(self) -> None:
        top, ok = QInputDialog.getText(
            self, "Cascading submenu", "Top-level menu label:", text="Aetheris Tools")
        if not ok or not top.strip():
            return
        spec, ok = QInputDialog.getMultiLineText(
            self, "Cascading submenu",
            "Items — 2-space indent = nesting, 'label | command' = leaf:",
            self._CASCADE_SAMPLE)
        if not ok or not spec.strip():
            return
        items = registry.parse_menu_spec(spec)
        # If the pasted spec starts with the top label as the first root, use its
        # children; otherwise treat all roots as the submenu's items.
        if len(items) == 1 and items[0].children:
            items = items[0].children
        good, msg = registry.add_cascading_menu(top.strip(), items)
        self._toast(good, msg)

    def _toast(self, ok: bool, msg: str) -> None:
        (logbus.success if ok else logbus.error)("ui.shell", msg)
