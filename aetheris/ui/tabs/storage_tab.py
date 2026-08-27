"""
Module 2 — Low-Level Storage Surgery & MFT Direct Parser.

Three panels: a raw MFT quick-scan (binary NTFS parse), a SHA-256 duplicate
finder / ghost-footprint scan, and the guarded file obliterator (locker
discovery + confirmed delete with the system-critical exclusion enforced in
storage.unlock).
"""
from __future__ import annotations

import os

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QTableWidget, QTableWidgetItem,
    QPushButton, QLabel, QLineEdit, QSpinBox, QFileDialog, QMessageBox,
    QPlainTextEdit, QCheckBox, QHeaderView,
)

from ...storage import mft, dedupe, unlock
from ...core import logbus
from ...core.settings import settings
from ..workers import Worker
from ..treemap import TreemapWidget


def _human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:,.1f} {unit}"
        n /= 1024
    return f"{n} B"


class StorageTab(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._worker: Worker | None = None
        self._mft_records: list = []
        self._build()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.addWidget(QLabel("Low-Level Storage Surgery & MFT Parser", objectName="title"))
        tabs = QTabWidget()
        tabs.addTab(self._mft_panel(), "Raw MFT Scan")
        tabs.addTab(self._dupe_panel(), "Duplicates & Ghosts")
        tabs.addTab(self._oblit_panel(), "File Obliterator")
        root.addWidget(tabs)

    # -- MFT ----------------------------------------------------------------
    def _mft_panel(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        bar = QHBoxLayout()
        bar.addWidget(QLabel("Volume:"))
        self.vol = QLineEdit(str(settings().get("mft_volume", r"\\.\C:")),
                             maximumWidth=120)
        bar.addWidget(self.vol)
        bar.addWidget(QLabel("max records:"))
        self.maxrec = QSpinBox()
        self.maxrec.setRange(1000, 500000)
        self.maxrec.setValue(int(settings().get("mft_max_records", 20000)))
        self.maxrec.setSingleStep(1000)
        bar.addWidget(self.maxrec)
        scan = QPushButton("Parse MFT")
        scan.clicked.connect(self._scan_mft)
        bar.addWidget(scan)
        bar.addStretch(1)
        self.mft_status = QLabel("requires elevation", objectName="subtle")
        bar.addWidget(self.mft_status)
        v.addLayout(bar)

        views = QTabWidget()

        # -- records table --
        self.mft_table = QTableWidget(0, 5)
        self.mft_table.setHorizontalHeaderLabels(["#", "Name", "Size", "Dir?", "Parent"])
        self.mft_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.mft_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        views.addTab(self.mft_table, "Records")

        # -- tree-map --
        tm_page = QWidget()
        tmv = QVBoxLayout(tm_page)
        tmbar = QHBoxLayout()
        self.tm_build = QPushButton("Build tree-map")
        self.tm_build.setEnabled(False)
        self.tm_build.clicked.connect(self._build_treemap)
        tmbar.addWidget(self.tm_build)
        up = QPushButton("⬆ Up")
        up.clicked.connect(lambda: self.treemap.go_up())
        tmbar.addWidget(up)
        self.tm_path = QLabel("", objectName="subtle")
        tmbar.addWidget(self.tm_path)
        tmbar.addStretch(1)
        tmv.addLayout(tmbar)
        self.treemap = TreemapWidget()
        self.treemap.pathChanged.connect(self.tm_path.setText)
        tmv.addWidget(self.treemap)
        views.addTab(tm_page, "Tree-map")

        v.addWidget(views)
        return w

    def _scan_mft(self) -> None:
        settings().set("mft_volume", self.vol.text())
        settings().set("mft_max_records", self.maxrec.value())
        self.mft_status.setText("scanning…")
        self.tm_build.setEnabled(False)

        def job(volume, cap):
            return list(mft.parse_volume(volume, max_records=cap))

        self._run(job, self._show_mft, self.vol.text(), self.maxrec.value())

    def _show_mft(self, records) -> None:
        self._mft_records = records
        shown = records[:5000]
        self.mft_table.setRowCount(len(shown))
        for i, r in enumerate(shown):
            for c, v in enumerate([str(r.index), r.name, _human(r.size),
                                   "yes" if r.is_directory else "", str(r.parent_index)]):
                self.mft_table.setItem(i, c, QTableWidgetItem(v))
        self.mft_status.setText(
            f"{len(records):,} records parsed"
            + (f" (showing first {len(shown):,})" if len(records) > len(shown) else ""))
        self.tm_build.setEnabled(bool(records))

    def _build_treemap(self) -> None:
        if not self._mft_records:
            return
        root = mft.build_tree(self._mft_records)
        self.treemap.set_root(root)
        self._toast(True, f"tree-map: {_human(root.total_size)} across "
                          f"{len(root.children)} top-level entries")

    # -- duplicates / ghosts ------------------------------------------------
    def _dupe_panel(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        bar = QHBoxLayout()
        self.dupe_root = QLineEdit(placeholderText="folder to scan…")
        bar.addWidget(self.dupe_root)
        browse = QPushButton("Browse…")
        browse.clicked.connect(lambda: self._pick_dir(self.dupe_root))
        bar.addWidget(browse)
        dbtn = QPushButton("Find duplicates")
        dbtn.clicked.connect(self._find_dupes)
        bar.addWidget(dbtn)
        gbtn = QPushButton("Find ghosts")
        gbtn.clicked.connect(self._find_ghosts)
        bar.addWidget(gbtn)
        v.addLayout(bar)
        self.dupe_out = QPlainTextEdit(readOnly=True)
        v.addWidget(self.dupe_out)
        return w

    def _find_dupes(self) -> None:
        root = self.dupe_root.text().strip()
        if not os.path.isdir(root):
            self._toast(False, "pick a valid folder")
            return
        self.dupe_out.setPlainText("scanning…")
        self._run(lambda r: dedupe.find_duplicates([r]), self._show_dupes, root)

    def _show_dupes(self, groups) -> None:
        if not groups:
            self.dupe_out.setPlainText("No duplicate files found.")
            return
        wasted = sum(g.wasted_bytes for g in groups)
        lines = [f"{len(groups)} duplicate groups — {_human(wasted)} reclaimable\n"]
        for g in groups[:200]:
            lines.append(f"[{_human(g.size)}]  sha256 {g.sha256[:16]}…  ×{len(g.paths)}")
            for p in g.paths:
                lines.append(f"    {p}")
            lines.append("")
        self.dupe_out.setPlainText("\n".join(lines))

    def _find_ghosts(self) -> None:
        root = self.dupe_root.text().strip()
        if not os.path.isdir(root):
            self._toast(False, "pick a valid folder")
            return
        self.dupe_out.setPlainText("scanning…")

        def job(r):
            return dedupe.find_ghosts([r]) + dedupe.find_orphan_appdata()

        self._run(job, self._show_ghosts, root)

    def _show_ghosts(self, ghosts) -> None:
        if not ghosts:
            self.dupe_out.setPlainText("No ghost footprints found.")
            return
        lines = [f"{len(ghosts)} ghost footprints (reported, not deleted)\n"]
        for g in ghosts[:500]:
            note = f"  — {g.note}" if g.note else ""
            lines.append(f"[{g.kind}] {g.path}{note}")
        self.dupe_out.setPlainText("\n".join(lines))

    # -- obliterator --------------------------------------------------------
    def _oblit_panel(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.addWidget(QLabel(
            "Locate the processes locking a file, then delete it after confirming.\n"
            "Files inside protected OS roots are refused in code.", objectName="subtle"))
        bar = QHBoxLayout()
        self.oblit_path = QLineEdit(placeholderText="path to file…")
        bar.addWidget(self.oblit_path)
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._pick_file)
        bar.addWidget(browse)
        find = QPushButton("Find lockers")
        find.clicked.connect(self._find_lockers)
        bar.addWidget(find)
        v.addLayout(bar)
        opts = QHBoxLayout()
        self.kill_lockers = QCheckBox("terminate non-critical lockers")
        opts.addWidget(self.kill_lockers)
        self.take_own = QCheckBox("take ownership first")
        opts.addWidget(self.take_own)
        self.strip_handles_cb = QCheckBox("force-close handles (advanced)")
        self.strip_handles_cb.setToolTip(
            "Enumerate the global handle table and close handles to this file "
            "with DuplicateHandle(DUPLICATE_CLOSE_SOURCE). Critical processes "
            "are refused.")
        opts.addWidget(self.strip_handles_cb)
        opts.addStretch(1)
        strip = QPushButton("Force-close handles")
        strip.clicked.connect(self._strip_handles)
        opts.addWidget(strip)
        oblit = QPushButton("Obliterate file")
        oblit.setObjectName("panic")
        oblit.clicked.connect(self._obliterate)
        opts.addWidget(oblit)
        v.addLayout(opts)
        self.oblit_out = QPlainTextEdit(readOnly=True)
        v.addWidget(self.oblit_out)
        return w

    def _find_lockers(self) -> None:
        path = self.oblit_path.text().strip()
        if not path:
            return
        lockers = unlock.find_lockers(path)
        if not lockers:
            self.oblit_out.setPlainText("No processes currently hold this file open.")
            return
        self.oblit_out.setPlainText(
            "\n".join(f"pid {lk.pid:>7}  {lk.name}" for lk in lockers))

    def _obliterate(self) -> None:
        path = self.oblit_path.text().strip()
        if not path or not os.path.exists(path):
            self._toast(False, "pick an existing file")
            return
        if unlock.is_protected_path(path):
            self._toast(False, "refused: path is inside a protected OS root")
            return
        if QMessageBox.critical(
            self, "Obliterate file",
            f"Permanently delete:\n\n{path}\n\nThis cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        if self.kill_lockers.isChecked():
            for pid, ok, msg in unlock.release_lockers(path, terminate=True):
                logbus.log("ui.storage", f"locker {pid}: {msg}")
        ok, msg = unlock.obliterate(
            path, confirm=True, take_own=self.take_own.isChecked(),
            strip_handles_first=self.strip_handles_cb.isChecked())
        self.oblit_out.appendPlainText(msg)
        self._toast(ok, msg)

    def _strip_handles(self) -> None:
        path = self.oblit_path.text().strip()
        if not path or not os.path.exists(path):
            self._toast(False, "pick an existing file")
            return
        if QMessageBox.warning(
            self, "Force-close handles",
            f"Enumerate and force-close all handles to:\n\n{path}\n\n"
            "This closes handles inside other processes and can destabilize an "
            "app that isn't expecting it. Critical processes are refused.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        results = unlock.strip_handles(path)
        if not results:
            self.oblit_out.setPlainText("No closable handles found for this file.")
            return
        lines = [f"pid {pid:>7}  handle 0x{hv:x}  {'closed' if ok else note}"
                 for pid, hv, ok, note in results]
        self.oblit_out.setPlainText("\n".join(lines))
        closed = sum(1 for _p, _h, ok, _n in results if ok)
        self._toast(True, f"closed {closed}/{len(results)} handle(s)")

    # -- helpers ------------------------------------------------------------
    def _pick_dir(self, target: QLineEdit) -> None:
        d = QFileDialog.getExistingDirectory(self, "Select folder")
        if d:
            target.setText(d)

    def _pick_file(self) -> None:
        f, _ = QFileDialog.getOpenFileName(self, "Select file")
        if f:
            self.oblit_path.setText(f)

    def _run(self, fn, on_done, *args) -> None:
        if self._worker and self._worker.isRunning():
            self._toast(False, "a scan is already running")
            return
        self._worker = Worker(fn, *args)
        self._worker.done.connect(on_done)
        self._worker.failed.connect(lambda e: self._toast(False, e))
        self._worker.start()

    def _toast(self, ok: bool, msg: str) -> None:
        (logbus.success if ok else logbus.error)("ui.storage", msg)
