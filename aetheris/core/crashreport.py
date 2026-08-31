"""
Last-resort crash reporter.

Installs a ``sys.excepthook`` (and thread excepthook) that writes a **scrubbed**
crash file to ``%APPDATA%\\AetherisQuantumCore\\crashes\\crash-<ts>.txt`` and
points the user at it, then chains to the previous hook. The report holds only
the exception, the traceback, and app/OS versions -- never memory contents or
process data, and file paths that contain the user's home / name are redacted so
the report is safe to share.
"""
from __future__ import annotations

import os
import platform
import re
import sys
import threading
import time
import traceback
from pathlib import Path

from . import logbus
from .settings import config_dir

SRC = "core.crashreport"


def crash_dir() -> Path:
    return config_dir() / "crashes"


def _scrub(text: str) -> str:
    """Redact the user's home path and account name(s) from a report."""
    home = os.path.expanduser("~")
    if home and home != "~":
        text = text.replace(home, "<HOME>")
    users = {os.path.basename(home), os.environ.get("USERNAME", ""),
             os.environ.get("USER", "")}
    for u in sorted((u for u in users if u), key=len, reverse=True):
        text = re.sub(re.escape(u), "<USER>", text, flags=re.IGNORECASE)
    return text


def write_report(exc_type, exc_value, exc_tb) -> str | None:
    """Write a scrubbed crash report; return its path (or None on failure)."""
    try:
        from .. import __version__
    except Exception:  # pragma: no cover
        __version__ = "?"
    tb = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
    body = _scrub(
        "Aetheris Quantum Core -- crash report\n"
        f"time:    {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"version: {__version__}\n"
        f"python:  {platform.python_version()}\n"
        f"os:      {platform.platform()}\n\n"
        "This report contains only the error + traceback (no memory or process\n"
        "data); home paths and your account name have been redacted.\n\n"
        f"{tb}")
    try:
        d = crash_dir()
        d.mkdir(parents=True, exist_ok=True)
        path = d / f"crash-{time.strftime('%Y%m%d-%H%M%S')}.txt"
        path.write_text(body, encoding="utf-8")
        return str(path)
    except OSError:
        return None


_prev_hook = None
_installed = False


def install() -> None:
    """Install the process + thread excepthooks (idempotent)."""
    global _prev_hook, _installed
    if _installed:
        return
    _prev_hook = sys.excepthook

    def _hook(exc_type, exc_value, exc_tb):
        if not issubclass(exc_type, KeyboardInterrupt):
            path = write_report(exc_type, exc_value, exc_tb)
            msg = f"unhandled {exc_type.__name__}: crash report written to {path}"
            try:
                logbus.error(SRC, msg)
            except Exception:  # pragma: no cover
                pass
            print(f"\n[Aetheris] {msg}", file=sys.stderr)
        if _prev_hook is not None:
            _prev_hook(exc_type, exc_value, exc_tb)

    def _thread_hook(args):
        if not issubclass(args.exc_type, KeyboardInterrupt):
            write_report(args.exc_type, args.exc_value, args.exc_traceback)

    sys.excepthook = _hook
    try:
        threading.excepthook = _thread_hook
    except Exception:  # pragma: no cover
        pass
    _installed = True
