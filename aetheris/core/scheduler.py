"""
Windows Task Scheduler integration for headless capture.

Registers ``aetheris-cli`` as a scheduled task (via ``schtasks``) so the machine
writes forensic session reports on an interval, unattended. Per-user tasks don't
require elevation. Uses the CLI module so the same code path as the terminal.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from . import logbus

SRC = "core.scheduler"
DEFAULT_TASK = "AetherisCapture"


def _pythonw() -> str:
    base = Path(sys.executable)
    cand = base.with_name("pythonw.exe")     # no console window
    return str(cand if cand.exists() else base)


def capture_command(out_file: str, fmt: str = "html") -> str:
    """The command a scheduled task runs (a single schtasks /TR string)."""
    if getattr(sys, "frozen", False):
        # Frozen exe: it dispatches "cli <args>" to the headless CLI (see run.py).
        return f'"{sys.executable}" cli --format {fmt} --out "{out_file}" report'
    return (f'"{_pythonw()}" -m aetheris.cli --format {fmt} '
            f'--out "{out_file}" report')


def _run(args: list[str], success_msg: str) -> tuple[bool, str]:
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            logbus.action(SRC, success_msg)
            return True, success_msg
        return False, (r.stderr or r.stdout or "schtasks failed").strip()
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def create_capture_task(out_file: str, every_minutes: int = 60,
                        name: str = DEFAULT_TASK, fmt: str = "html") -> tuple[bool, str]:
    """Create/replace a per-user scheduled capture running every N minutes."""
    if sys.platform != "win32":
        return False, "Windows only"
    every_minutes = max(int(every_minutes), 1)
    args = ["schtasks", "/Create", "/TN", name, "/TR", capture_command(out_file, fmt),
            "/SC", "MINUTE", "/MO", str(every_minutes), "/F"]
    return _run(args, f"scheduled capture '{name}' every {every_minutes} min -> {out_file}")


def delete_task(name: str = DEFAULT_TASK) -> tuple[bool, str]:
    if sys.platform != "win32":
        return False, "Windows only"
    return _run(["schtasks", "/Delete", "/TN", name, "/F"], f"removed task '{name}'")


def task_exists(name: str = DEFAULT_TASK) -> bool:
    if sys.platform != "win32":
        return False
    try:
        r = subprocess.run(["schtasks", "/Query", "/TN", name],
                           capture_output=True, text=True, timeout=15)
        return r.returncode == 0
    except Exception:
        return False


def task_info(name: str = DEFAULT_TASK) -> str:
    if not task_exists(name):
        return ""
    try:
        r = subprocess.run(["schtasks", "/Query", "/TN", name, "/FO", "LIST"],
                           capture_output=True, text=True, timeout=15)
        return r.stdout.strip() if r.returncode == 0 else ""
    except Exception:
        return ""
