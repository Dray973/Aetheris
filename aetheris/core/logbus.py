"""
Thread-safe live API log bus.

Every native transaction, allocation address, handle op, or destructive action
in the suite routes a structured event through this single bus. The UI log
drawer subscribes to it; because it is built on Qt signals, workers running on
QThreads can emit from any thread and the slot is delivered on the GUI thread.

If PyQt6 is unavailable (e.g. running a headless unit test), the bus degrades
to stdout so the same ``log(...)`` calls keep working everywhere.
"""
from __future__ import annotations

import time
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable


class Level(str, Enum):
    TRACE = "TRACE"     # raw API call detail (addresses, handles, return codes)
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"
    ACTION = "ACTION"   # a state-changing operation was performed
    SUCCESS = "SUCCESS"


@dataclass(frozen=True)
class LogEvent:
    level: Level
    source: str            # e.g. "core.privileges", "network.firewall"
    message: str
    detail: str = ""       # optional machine detail: return codes, hex addrs
    ts: float = field(default_factory=time.time)


try:
    from PyQt6.QtCore import QObject, pyqtSignal

    class _QtEmitter(QObject):
        event = pyqtSignal(object)  # emits LogEvent

    _emitter: "_QtEmitter | None" = _QtEmitter()
    _HAS_QT = True
except Exception:  # pragma: no cover - headless fallback
    _emitter = None
    _HAS_QT = False


_plain_subscribers: list[Callable[[LogEvent], None]] = []
_lock = threading.Lock()


def subscribe(slot: Callable[[LogEvent], None]) -> None:
    """Register a callback. On Qt this connects to the cross-thread signal."""
    if _HAS_QT and _emitter is not None:
        _emitter.event.connect(slot)
    else:
        with _lock:
            _plain_subscribers.append(slot)


def emit(event: LogEvent) -> None:
    """Publish an event to all subscribers (thread-safe)."""
    if _HAS_QT and _emitter is not None:
        _emitter.event.emit(event)
    else:  # pragma: no cover
        with _lock:
            subs = list(_plain_subscribers)
        if not subs:
            print(f"[{event.level.value}] {event.source}: {event.message}"
                  f"{(' | ' + event.detail) if event.detail else ''}")
        for s in subs:
            try:
                s(event)
            except Exception:
                pass


def log(source: str, message: str, level: Level = Level.INFO, detail: str = "") -> None:
    """Convenience helper used throughout the codebase."""
    emit(LogEvent(level=level, source=source, message=message, detail=detail))


# Terse aliases for readability at call sites.
def trace(source: str, message: str, detail: str = "") -> None:
    log(source, message, Level.TRACE, detail)


def action(source: str, message: str, detail: str = "") -> None:
    log(source, message, Level.ACTION, detail)


def warn(source: str, message: str, detail: str = "") -> None:
    log(source, message, Level.WARN, detail)


def error(source: str, message: str, detail: str = "") -> None:
    log(source, message, Level.ERROR, detail)


def success(source: str, message: str, detail: str = "") -> None:
    log(source, message, Level.SUCCESS, detail)
