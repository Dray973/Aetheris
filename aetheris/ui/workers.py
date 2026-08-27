"""
QThread worker helpers.

``Worker`` runs any callable on a background QThread and delivers the result (or
exception) back on the GUI thread via signals, so long-running native calls
(MFT scans, dedupe hashing, DNS resolution) never block the UI thread.
"""
from __future__ import annotations

from typing import Any, Callable

from PyQt6.QtCore import QThread, pyqtSignal


class Worker(QThread):
    done = pyqtSignal(object)       # result
    failed = pyqtSignal(str)        # error string
    progress = pyqtSignal(str)      # optional status text

    def __init__(self, fn: Callable[..., Any], *args, **kwargs) -> None:
        super().__init__()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs

    def run(self) -> None:  # executes on the worker thread
        try:
            result = self._fn(*self._args, **self._kwargs)
            self.done.emit(result)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(f"{type(exc).__name__}: {exc}")
