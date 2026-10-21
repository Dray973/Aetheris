"""Shared plumbing for the Shell Engineer sub-panels.

Every panel owns its own ``Worker`` so a slow job in one panel (a large
registry snapshot, a service enumeration) never blocks or clobbers another,
and every write goes through :meth:`PanelBase._confirm` before it runs.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

import shiboken6
from PySide6.QtWidgets import QLabel, QMessageBox, QWidget

from ....core import logbus
from ...workers import Worker

SRC = "ui.shell"


class PanelBase(QWidget):
    #: Optional status label; set by subclasses so a failed job doesn't leave
    #: it stuck on "enumerating…".
    _status: QLabel | None = None

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._worker: Worker | None = None
        self._busy = False

    def _run(self, fn: Callable[..., Any], on_done: Callable[[Any], None],
             *args: Any) -> bool:
        """Run a blocking call on this panel's Worker (keeps the UI live).

        Returns False (and toasts) if a job is already running. "Busy" is
        tracked explicitly rather than via ``isRunning()``: ``done`` is emitted
        from inside the thread, so a result slot that immediately refreshes
        would otherwise see its own just-finishing worker and be refused.
        """
        if self._busy:
            self._toast(False, "a task is already running in this panel")
            return False
        if self._worker is not None:
            # Its job has delivered; the thread is at most returning from
            # run(). Join it so we never drop the last reference to a live
            # QThread (that aborts the process).
            self._worker.wait()
        self._busy = True

        def finish(res: Any) -> None:
            self._busy = False
            # The panel may have been closed while the job ran; its child
            # widgets are gone, so drop the result instead of touching them.
            if shiboken6.isValid(self):
                on_done(res)

        self._worker = Worker(fn, *args)
        self._worker.done.connect(finish)
        self._worker.failed.connect(self._on_failed)
        self._worker.start()
        return True

    def _on_failed(self, msg: str) -> None:
        self._busy = False
        self._toast(False, msg)
        if self._status is not None and shiboken6.isValid(self._status):
            self._status.setText(f"failed: {msg}")

    def _confirm(self, title: str, text: str) -> bool:
        return QMessageBox.question(
            self, title, text,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        ) == QMessageBox.StandardButton.Yes

    def _toast(self, ok: bool, msg: str) -> None:
        (logbus.success if ok else logbus.error)(SRC, msg)

    def _show_result_then(self, refresh: Callable[[], None]) -> Callable[[Any], None]:
        """Build an ``on_done`` for (ok, msg) results that refreshes on success."""
        def handler(res: Any) -> None:
            ok, msg = res
            self._toast(ok, msg)
            if ok:
                refresh()
        return handler
