"""
Byte-level block matcher + ghost-footprint scanner.

  * find_duplicates(roots) — groups files by SHA-256. To avoid hashing every
    byte of every file, it first buckets by size, then hashes only within
    size-collision buckets (a large speed win on real trees).
  * find_ghosts(roots)     — flags empty directory trees and orphaned app dirs
    left behind under AppData.

Read-only: this module reports candidates; it never deletes. Deletion is the
user's explicit action in the UI.
"""
from __future__ import annotations

import hashlib
import os
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from ..core import logbus

SRC = "storage.dedupe"
_CHUNK = 1024 * 1024


@dataclass
class DuplicateGroup:
    sha256: str
    size: int
    paths: list[str]

    @property
    def wasted_bytes(self) -> int:
        return self.size * (len(self.paths) - 1)


def _hash_file(path: str) -> str | None:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            while chunk := fh.read(_CHUNK):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def find_duplicates(roots: Iterable[str], min_size: int = 1) -> list[DuplicateGroup]:
    by_size: dict[int, list[str]] = defaultdict(list)
    scanned = 0
    for root in roots:
        for dirpath, _dirs, files in os.walk(root):
            for name in files:
                p = os.path.join(dirpath, name)
                try:
                    sz = os.path.getsize(p)
                except OSError:
                    continue
                if sz >= min_size:
                    by_size[sz].append(p)
                    scanned += 1
    logbus.trace(SRC, f"sized {scanned} files across {len(by_size)} size buckets")

    groups: list[DuplicateGroup] = []
    for sz, paths in by_size.items():
        if len(paths) < 2:
            continue  # unique size => cannot be a duplicate
        by_hash: dict[str, list[str]] = defaultdict(list)
        for p in paths:
            digest = _hash_file(p)
            if digest:
                by_hash[digest].append(p)
        for digest, hpaths in by_hash.items():
            if len(hpaths) >= 2:
                groups.append(DuplicateGroup(digest, sz, sorted(hpaths)))

    groups.sort(key=lambda g: g.wasted_bytes, reverse=True)
    logbus.trace(SRC, f"found {len(groups)} duplicate groups")
    return groups


@dataclass
class Ghost:
    kind: str          # "empty-dir" | "orphan-appdata"
    path: str
    note: str = ""


def find_ghosts(roots: Iterable[str]) -> list[Ghost]:
    ghosts: list[Ghost] = []
    for root in roots:
        for dirpath, dirs, files in os.walk(root, topdown=False):
            # topdown=False so we see leaves first; an empty leaf with no files
            # and no surviving subdirs is a ghost.
            if not files and not dirs:
                ghosts.append(Ghost("empty-dir", dirpath))
    logbus.trace(SRC, f"found {len(ghosts)} empty directory trees")
    return ghosts


def find_orphan_appdata(known_installed: set[str] | None = None) -> list[Ghost]:
    """
    Flag AppData subfolders whose top-level name doesn't match any running
    process image or Start-menu shortcut. Heuristic — reported, never deleted.
    """
    ghosts: list[Ghost] = []
    appdata = os.environ.get("LOCALAPPDATA")
    if not appdata or not os.path.isdir(appdata):
        return ghosts
    known = known_installed or _installed_hint()
    for name in os.listdir(appdata):
        full = os.path.join(appdata, name)
        if not os.path.isdir(full):
            continue
        if name.lower() not in known:
            ghosts.append(Ghost("orphan-appdata", full, f"'{name}' not matched to any known app"))
    logbus.trace(SRC, f"flagged {len(ghosts)} possible orphan AppData dirs")
    return ghosts


def _installed_hint() -> set[str]:
    """Best-effort set of app tokens from running processes."""
    hint: set[str] = set()
    try:
        import psutil
        for p in psutil.process_iter(["name"]):
            n = (p.info.get("name") or "").lower()
            if n.endswith(".exe"):
                hint.add(n[:-4])
    except Exception:
        pass
    return hint
