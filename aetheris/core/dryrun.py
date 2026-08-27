"""
Global dry-run mode.

When dry-run is active, every state-changing operation that opts in logs exactly
what it *would* do and returns without touching the system -- and, crucially,
registers no rollback (there is nothing to undo). This lets an operator rehearse
a destructive sequence (firewall isolation, registry writes, autorun disables,
file obliteration) and read the audit console before arming it for real.

Ops opt in with a one-line guard at the very top::

    if dryrun.skip(SRC, "delete C:/x"):
        return True, "[dry-run] not applied"

The flag is process-wide and thread-safe; ``active()`` is a scoped override.
"""
from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager

from . import logbus

SRC = "core.dryrun"

_lock = threading.Lock()
_enabled = False


def enabled() -> bool:
    with _lock:
        return _enabled


def set_enabled(on: bool) -> bool:
    """Set dry-run on/off. Returns the previous state."""
    global _enabled
    with _lock:
        prev, _enabled = _enabled, bool(on)
    if prev != bool(on):
        logbus.action(SRC, f"dry-run mode {'ENABLED' if on else 'disabled'}")
    return prev


@contextmanager
def active(on: bool = True) -> Iterator[None]:
    """Scoped dry-run override that restores the prior state on exit."""
    prev = set_enabled(on)
    try:
        yield
    finally:
        set_enabled(prev)


def skip(source: str, would: str, detail: str = "") -> bool:
    """Return True (and log the intended action) iff dry-run is active.

    Call at the top of a destructive operation; when it returns True the caller
    must return a simulated result *without* mutating state or registering an
    undo.
    """
    if enabled():
        logbus.action(source, f"[DRY-RUN] would {would}", detail)
        return True
    return False
