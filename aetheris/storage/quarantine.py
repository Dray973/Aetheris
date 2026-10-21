"""
Reversible quarantine: neutralise a file without destroying it.

A quarantined file is renamed in place to ``<name>.aetheris-quarantine``.
Renaming works even while the image is running (Windows forbids deleting a
mapped executable, not renaming it), keeps the bytes for later analysis, and
breaks every Run key, task and shortcut that launches the original path.

Every quarantine is recorded twice:

* on the rollback ledger, so PANIC / a containment undo restores it this
  session;
* in a manifest under the config dir, so it can still be restored after the
  app restarts (the ledger is per-session).

Refuses anything under the Windows directory: renaming a system binary is how
a "containment" bricks a machine.
"""
from __future__ import annotations

import json
import ntpath
import os
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from ..core import dryrun, logbus, safety

SRC = "storage.quarantine"
SUFFIX = ".aetheris-quarantine"
_lock = threading.Lock()


@dataclass
class QuarantineRecord:
    original: str
    quarantined: str
    ts: float


def _manifest_path() -> Path:
    from ..core.settings import config_dir
    return config_dir() / "quarantine.json"


def _load() -> list[QuarantineRecord]:
    p = _manifest_path()
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        return [QuarantineRecord(**r) for r in raw]
    except (OSError, ValueError, TypeError):
        return []


def _save(records: list[QuarantineRecord]) -> None:
    p = _manifest_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps([asdict(r) for r in records], indent=2), encoding="utf-8")
    os.replace(tmp, p)


def is_refused(path: str) -> str | None:
    """Why ``path`` must not be quarantined, or None if it may be."""
    if not path:
        return "no path"
    root = os.environ.get("SystemRoot", r"C:\Windows").lower().rstrip("\\")
    low = ntpath.normpath(path).lower()
    if low == root or low.startswith(root + "\\"):
        return "refused: file is under the Windows directory"
    if low.endswith(SUFFIX):
        return "already quarantined"
    return None


def quarantine(path: str) -> tuple[bool, str]:
    reason = is_refused(path)
    if reason:
        return False, reason
    target = path + SUFFIX
    if dryrun.skip(SRC, f"quarantine {path}", target):
        return True, f"[dry-run] would quarantine {path}"
    if not os.path.exists(path):
        return False, f"not found: {path}"
    if os.path.exists(target):
        return False, f"a quarantined copy already exists: {target}"
    try:
        os.rename(path, target)
    except OSError as exc:
        return False, f"could not quarantine {path}: {exc}"
    with _lock:
        records = [r for r in _load() if r.original.lower() != path.lower()]
        records.append(QuarantineRecord(path, target, time.time()))
        _save(records)
    def _undo() -> None:
        _restore_or_raise(path)

    safety.ledger.register(f"quarantine {ntpath.basename(path)}", _undo)
    logbus.action(SRC, f"quarantined {path}", target)
    return True, f"quarantined {ntpath.basename(path)}"


def _restore_or_raise(original: str) -> None:
    ok, msg = restore(original)
    if not ok:
        raise RuntimeError(msg)


def restore(original: str) -> tuple[bool, str]:
    """Put a quarantined file back (works across restarts via the manifest)."""
    with _lock:
        records = _load()
        rec = next((r for r in records if r.original.lower() == original.lower()), None)
        if rec is None:
            return False, f"no quarantine record for {original}"
        if dryrun.skip(SRC, f"restore {original}", rec.quarantined):
            return True, f"[dry-run] would restore {original}"
        if os.path.exists(rec.original):
            return False, f"refusing to overwrite a new file at {rec.original}"
        try:
            os.rename(rec.quarantined, rec.original)
        except OSError as exc:
            return False, f"could not restore {original}: {exc}"
        _save([r for r in records if r is not rec])
    logbus.action(SRC, f"restored {original}")
    return True, f"restored {ntpath.basename(original)}"


def listing() -> list[QuarantineRecord]:
    with _lock:
        return _load()
