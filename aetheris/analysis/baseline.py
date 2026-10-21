"""
Hunt baselines: remember what a clean machine looks like, then show only change.

A first hunt on any real machine surfaces a handful of harmless findings -- an
unsigned vendor updater, a dev tool running from Downloads -- and they come
back on every later run, burying anything that actually changed. A baseline
records the accepted findings so later hunts are classified as:

* **new**       -- the subject was never seen in the baseline;
* **escalated** -- the subject was known, but now shows an ATT&CK technique it
  did not have (the known updater has started talking to a public host);
* **known**     -- nothing beyond what was accepted;
* **resolved**  -- a baselined subject that no longer appears (reported
  separately, since there is no current finding to tag).

Subjects are matched on the findings engine's correlation key (the binary's
basename), which is also the SARIF fingerprint. Techniques rather than scores
decide escalation: a score moves when unrelated signals merge in, but a new
technique is a new behaviour.

Pure apart from :func:`load` / :meth:`Baseline.save`; the classification works
on in-memory ``Finding`` objects.
"""
from __future__ import annotations

import json
import os
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .export import techniques_of
from .findings import Finding

FORMAT_VERSION = 1

NEW, ESCALATED, KNOWN = "new", "escalated", "known"

#: SARIF ``result.baselineState`` for each status (SARIF 2.1.0 section 3.27.24).
SARIF_STATE = {NEW: "new", ESCALATED: "updated", KNOWN: "unchanged"}


@dataclass
class Entry:
    key: str
    techniques: set[str] = field(default_factory=set)
    subject: str = ""
    title: str = ""
    accepted_at: float = 0.0


@dataclass
class Baseline:
    entries: dict[str, Entry] = field(default_factory=dict)
    host: str = ""
    created_at: float = 0.0

    # -- building ----------------------------------------------------------
    @classmethod
    def from_findings(cls, findings: Iterable[Finding], host: str = "",
                      now: float | None = None) -> Baseline:
        b = cls(host=host, created_at=time.time() if now is None else now)
        for f in findings:
            b.accept(f, now=b.created_at)
        return b

    def accept(self, f: Finding, now: float | None = None) -> None:
        """Mark one finding as known-good (merging techniques if seen before)."""
        e = self.entries.get(f.key)
        if e is None:
            e = self.entries[f.key] = Entry(key=f.key)
        e.techniques |= set(techniques_of(f))
        e.subject, e.title = f.subject, f.title
        e.accepted_at = time.time() if now is None else now

    def forget(self, key: str) -> bool:
        return self.entries.pop(key, None) is not None

    # -- classifying -------------------------------------------------------
    def status(self, f: Finding) -> str:
        e = self.entries.get(f.key)
        if e is None:
            return NEW
        if set(techniques_of(f)) - e.techniques:
            return ESCALATED
        return KNOWN

    def new_techniques(self, f: Finding) -> list[str]:
        e = self.entries.get(f.key)
        known = e.techniques if e else set()
        return [t for t in techniques_of(f) if t not in known]

    def resolved(self, findings: Iterable[Finding]) -> list[Entry]:
        present = {f.key for f in findings}
        return [e for k, e in sorted(self.entries.items()) if k not in present]

    # -- persistence -------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "format": "aetheris-hunt-baseline", "version": FORMAT_VERSION,
            "host": self.host, "created_at": self.created_at,
            "entries": [{"key": e.key, "techniques": sorted(e.techniques),
                         "subject": e.subject, "title": e.title,
                         "accepted_at": e.accepted_at}
                        for _k, e in sorted(self.entries.items())],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Baseline:
        if data.get("format") != "aetheris-hunt-baseline":
            raise ValueError("not an Aetheris hunt baseline")
        if int(data.get("version", 0)) > FORMAT_VERSION:
            raise ValueError(f"baseline format v{data.get('version')} is newer "
                             f"than this build understands (v{FORMAT_VERSION})")
        b = cls(host=str(data.get("host", "")),
                created_at=float(data.get("created_at", 0.0)))
        for raw in data.get("entries", []):
            key = str(raw["key"])
            b.entries[key] = Entry(key=key, techniques=set(raw.get("techniques", [])),
                                   subject=str(raw.get("subject", "")),
                                   title=str(raw.get("title", "")),
                                   accepted_at=float(raw.get("accepted_at", 0.0)))
        return b

    def save(self, path: str | os.PathLike[str]) -> None:
        """Atomic write: a crash mid-save must not leave a truncated baseline,
        which would make every finding look new."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        os.replace(tmp, p)


def load(path: str | os.PathLike[str]) -> Baseline:
    return Baseline.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def default_path() -> Path:
    from ..core.settings import config_dir
    return config_dir() / "hunt-baseline.json"


def load_default() -> Baseline | None:
    """The saved baseline, or None if there is none or it can't be read."""
    p = default_path()
    if not p.exists():
        return None
    try:
        return load(p)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        from ..core import logbus
        logbus.warn("analysis.baseline", f"ignoring unreadable baseline {p}: {exc}")
        return None


def summarize(baseline: Baseline, findings: list[Finding]) -> dict[str, int]:
    counts = {NEW: 0, ESCALATED: 0, KNOWN: 0}
    for f in findings:
        counts[baseline.status(f)] += 1
    counts["resolved"] = len(baseline.resolved(findings))
    return counts
