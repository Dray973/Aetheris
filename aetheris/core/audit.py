"""
Tamper-evident audit log (SHA-256 hash chain).

Every audit record carries the hash of its predecessor, and its own hash is
SHA-256 over (seq, ts, level, source, message, detail, prev_hash). Editing,
deleting, reordering, or inserting any record therefore breaks the chain and is
caught by ``verify()`` -- the log is append-only and any after-the-fact
alteration is detectable, which is what makes the audit console trustworthy.

Pure ``hashlib``/``json``: no Qt, no Windows. ``wire_to_logbus()`` subscribes a
log to the live event bus so the audit console's stream is chained as it is
produced; records can optionally be persisted to a JSONL file as they land.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import asdict, dataclass

GENESIS_HASH = "0" * 64
SRC = "core.audit"


@dataclass(frozen=True)
class AuditRecord:
    seq: int
    ts: float
    level: str
    source: str
    message: str
    detail: str
    prev_hash: str
    hash: str


def _hash(seq: int, ts: float, level: str, source: str, message: str,
          detail: str, prev_hash: str) -> str:
    # Canonical, stable serialization -> identical bytes on recompute/reload.
    payload = json.dumps(
        [seq, f"{ts:.6f}", level, source, message, detail, prev_hash],
        separators=(",", ":"), ensure_ascii=True, sort_keys=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditLog:
    """Append-only, hash-chained audit trail (optionally persisted to JSONL)."""

    def __init__(self, path: str | None = None) -> None:
        self._records: list[AuditRecord] = []
        self._lock = threading.Lock()
        self._path = path

    def append(self, level: str, source: str, message: str,
               detail: str = "", ts: float | None = None) -> AuditRecord:
        with self._lock:
            ts = round(time.time() if ts is None else ts, 6)
            seq = len(self._records)
            prev = self._records[-1].hash if self._records else GENESIS_HASH
            h = _hash(seq, ts, level, source, message, detail, prev)
            rec = AuditRecord(seq, ts, level, source, message, detail, prev, h)
            self._records.append(rec)
            if self._path:
                self._persist(rec)
            return rec

    def append_event(self, event) -> AuditRecord:
        """Adapter for a ``logbus.LogEvent`` (used by :func:`wire_to_logbus`)."""
        level = getattr(event.level, "value", str(event.level))
        return self.append(level, event.source, event.message,
                           getattr(event, "detail", ""), getattr(event, "ts", None))

    def verify(self) -> tuple[bool, int]:
        """Return ``(ok, first_bad_seq)``; ``(True, -1)`` when the chain is intact."""
        prev = GENESIS_HASH
        with self._lock:
            for i, r in enumerate(self._records):
                expect = _hash(r.seq, r.ts, r.level, r.source, r.message,
                               r.detail, r.prev_hash)
                if r.prev_hash != prev or r.hash != expect or r.seq != i:
                    return False, i
                prev = r.hash
        return True, -1

    def records(self) -> list[AuditRecord]:
        with self._lock:
            return list(self._records)

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    # -- persistence --------------------------------------------------------
    def _persist(self, rec: AuditRecord) -> None:
        path = self._path
        if path is None:
            return
        try:
            with open(path, "a", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(asdict(rec), ensure_ascii=True) + "\n")
        except OSError:
            pass  # persistence is best-effort; the in-memory chain still stands

    @classmethod
    def load(cls, path: str) -> AuditLog:
        """Rebuild a log from a JSONL file *as written* (hashes preserved), so
        ``verify()`` can then check it for tampering."""
        log = cls()
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                log._records.append(AuditRecord(
                    d["seq"], d["ts"], d["level"], d["source"],
                    d["message"], d["detail"], d["prev_hash"], d["hash"],
                ))
        return log


# Process-wide audit trail for the running session.
audit = AuditLog()


def wire_to_logbus(target: AuditLog | None = None) -> None:
    """Subscribe an audit log to the live event bus (call once at app start)."""
    from . import logbus
    log = target or audit

    def _sink(event: logbus.LogEvent) -> None:
        log.append_event(event)

    logbus.subscribe(_sink)
