"""
File unlock + guarded obliterator.

Locates which processes hold a file open, and (only after explicit UI
confirmation) can take ownership and delete a stubbornly-locked file. Two hard
guardrails are enforced here in code, not just in the UI:

  * PROTECTED_ROOTS — refuses to obliterate inside core OS locations.
  * CRITICAL_PROCESSES — refuses to close handles held by / terminate the
    processes whose death bugchecks or destabilizes Windows.

Locker discovery and raw handle stripping live in ``storage.handles``:
``locking_processes`` finds the holders and ``strip_file_handles`` force-closes
their handles with DuplicateHandle(DUPLICATE_CLOSE_SOURCE) over the global handle
table (``NtQuerySystemInformation``), refusing critical processes. This module
wraps them in the confirm/guardrail/obliterate flow; the shipped obliterator can
ask a locking process to release, terminate a non-critical locker, or strip
handles before deleting.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass

import psutil

from ..core import dryrun, logbus
from . import handles

SRC = "storage.unlock"

PROTECTED_ROOTS = (
    os.environ.get("SystemRoot", r"C:\Windows").lower(),
)
CRITICAL_PROCESSES = {
    "system", "system idle process", "registry", "smss.exe", "csrss.exe",
    "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe",
    "fontdrvhost.exe", "dwm.exe", "memory compression",
}


@dataclass
class Locker:
    pid: int
    name: str
    path: str


def is_protected_path(path: str) -> bool:
    low = os.path.abspath(path).lower()
    return any(low.startswith(root) for root in PROTECTED_ROOTS)


def find_lockers(target: str) -> list[Locker]:
    """
    Return processes with ``target`` currently open, via the Restart Manager
    API. (psutil's open_files() is avoided here: enumerating every process's
    open files can hit a native access violation on Windows.)
    """
    target_abs = os.path.abspath(target)
    lockers: list[Locker] = []
    for pid, name in handles.locking_processes(target_abs):
        # Prefer the real image name when we can resolve it cheaply.
        try:
            name = psutil.Process(pid).name()
        except Exception:
            pass
        lockers.append(Locker(pid, name or "?", target_abs))
    logbus.trace(SRC, f"{len(lockers)} process(es) hold {target}")
    return lockers


def release_lockers(target: str, terminate: bool = False) -> list[tuple[int, bool, str]]:
    """
    Try to free a file. If ``terminate`` and the locker is non-critical, kill it.
    Critical processes are always refused.
    """
    results: list[tuple[int, bool, str]] = []
    for lk in find_lockers(target):
        if lk.name.lower() in CRITICAL_PROCESSES:
            results.append((lk.pid, False, f"refused: {lk.name} is system-critical"))
            logbus.warn(SRC, f"refused to touch critical locker {lk.name} ({lk.pid})")
            continue
        if not terminate:
            results.append((lk.pid, False, f"{lk.name} holds the file (terminate not requested)"))
            continue
        try:
            proc = psutil.Process(lk.pid)
            proc.terminate()
            proc.wait(timeout=3)
            results.append((lk.pid, True, f"terminated {lk.name}"))
            logbus.action(SRC, f"terminated locker {lk.name} ({lk.pid}) for {target}")
        except Exception as exc:  # noqa: BLE001
            results.append((lk.pid, False, str(exc)))
    return results


def take_ownership(path: str) -> tuple[bool, str]:
    """Claim ownership + grant admins full control via takeown/icacls."""
    if is_protected_path(path):
        return False, "refused: path is inside a protected OS root"
    try:
        r1 = subprocess.run(["takeown", "/F", path], capture_output=True, text=True, timeout=30)
        r2 = subprocess.run(
            ["icacls", path, "/grant", "administrators:F"],
            capture_output=True, text=True, timeout=30,
        )
        ok = r1.returncode == 0 and r2.returncode == 0
        msg = "ownership claimed" if ok else (r1.stderr + r2.stderr).strip()
        if ok:
            logbus.action(SRC, f"took ownership of {path}")
        return ok, msg
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def strip_handles(path: str) -> list[tuple[int, int, bool, str]]:
    """
    Force-close every handle to ``path`` held by non-critical processes, via
    DuplicateHandle(DUPLICATE_CLOSE_SOURCE). Critical lockers are refused; the
    protected-path guard still applies. Returns per-handle results.
    """
    if is_protected_path(path):
        logbus.warn(SRC, f"refused handle strip on protected path {path}")
        return []
    safe_pids = {lk.pid for lk in find_lockers(path)
                 if lk.name.lower() not in CRITICAL_PROCESSES}
    if not safe_pids:
        return []
    results = handles.strip_file_handles(path, safe_pids)
    closed = sum(1 for _p, _h, ok, _n in results if ok)
    logbus.action(SRC, f"handle strip on {path}: closed {closed}/{len(results)}")
    return results


def obliterate(path: str, confirm: bool, take_own: bool = False,
               strip_handles_first: bool = False) -> tuple[bool, str]:
    """
    Delete a file. Requires ``confirm=True`` (the UI passes this only after the
    user acknowledges a modal). Refuses protected OS roots outright.
    ``strip_handles_first`` force-closes locking handles before deleting.
    """
    if not confirm:
        return False, "refused: confirmation required"
    if is_protected_path(path):
        return False, "refused: path is inside a protected OS root"
    if not os.path.exists(path):
        return False, "path does not exist"
    if dryrun.skip(SRC, f"obliterate {path}"):
        return True, f"[dry-run] would delete {path}"

    release_lockers(path, terminate=False)  # report, don't kill implicitly
    if strip_handles_first:
        strip_handles(path)
    if take_own:
        take_ownership(path)
    try:
        os.chmod(path, 0o777)
        os.remove(path)
        logbus.action(SRC, f"obliterated {path}")
        return True, f"deleted {path}"
    except Exception as exc:  # noqa: BLE001
        return False, f"delete failed: {exc}"
