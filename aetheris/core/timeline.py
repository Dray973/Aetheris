"""
Session timeline / state diff.

Takes lightweight snapshots of volatile system state -- the running process set,
listening ports, established remote connections, and the autorun set -- and lets
you diff *any two* points in the session (not just before/after). Pairs with the
persistent audit log: the log says what Aetheris did, the timeline shows what the
machine did around it (a process appearing, a new listener, a fresh autorun).

Snapshots are kept in a bounded in-memory ring. ``capture`` is the heavy part
(process + socket enumeration) and is meant to run on a Worker; ``diff_snapshots``
is pure set arithmetic and is unit-tested off-Windows.
"""
from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass, field

from . import logbus

SRC = "core.timeline"


@dataclass
class Snapshot:
    seq: int
    ts: float
    processes: set[tuple[int, str]] = field(default_factory=set)   # (pid, name)
    listening: set[tuple[str, int]] = field(default_factory=set)   # (proto, port)
    connections: set[str] = field(default_factory=set)            # "ip:port" remotes
    autoruns: set[str] = field(default_factory=set)               # "name @ location"

    @property
    def label(self) -> str:
        return time.strftime("%H:%M:%S", time.localtime(self.ts))

    def counts(self) -> str:
        return (f"{len(self.processes)} proc · {len(self.listening)} listen · "
                f"{len(self.connections)} conn · {len(self.autoruns)} autorun")


@dataclass
class StateDiff:
    procs_started: list[tuple[int, str]] = field(default_factory=list)
    procs_exited: list[tuple[int, str]] = field(default_factory=list)
    ports_opened: list[tuple[str, int]] = field(default_factory=list)
    ports_closed: list[tuple[str, int]] = field(default_factory=list)
    conns_new: list[str] = field(default_factory=list)
    conns_gone: list[str] = field(default_factory=list)
    autoruns_added: list[str] = field(default_factory=list)
    autoruns_removed: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not any((self.procs_started, self.procs_exited, self.ports_opened,
                        self.ports_closed, self.conns_new, self.conns_gone,
                        self.autoruns_added, self.autoruns_removed))

    def summary(self) -> str:
        return (f"+{len(self.procs_started)}/-{len(self.procs_exited)} proc, "
                f"+{len(self.ports_opened)}/-{len(self.ports_closed)} ports, "
                f"+{len(self.conns_new)}/-{len(self.conns_gone)} conn, "
                f"+{len(self.autoruns_added)}/-{len(self.autoruns_removed)} autorun")


def diff_snapshots(a: Snapshot, b: Snapshot) -> StateDiff:
    """Diff snapshot *a* (earlier) -> *b* (later). Pure set arithmetic."""
    return StateDiff(
        procs_started=sorted(b.processes - a.processes),
        procs_exited=sorted(a.processes - b.processes),
        ports_opened=sorted(b.listening - a.listening),
        ports_closed=sorted(a.listening - b.listening),
        conns_new=sorted(b.connections - a.connections),
        conns_gone=sorted(a.connections - b.connections),
        autoruns_added=sorted(b.autoruns - a.autoruns),
        autoruns_removed=sorted(a.autoruns - b.autoruns),
    )


def diff_rows(diff: StateDiff) -> list[tuple[str, str, str]]:
    """Flatten a diff into (change, category, detail) rows for a table."""
    rows: list[tuple[str, str, str]] = []
    for pid, name in diff.procs_started:
        rows.append(("Added", "process", f"{name} (pid {pid})"))
    for pid, name in diff.procs_exited:
        rows.append(("Removed", "process", f"{name} (pid {pid})"))
    for proto, port in diff.ports_opened:
        rows.append(("Added", "listening", f"{proto}/{port}"))
    for proto, port in diff.ports_closed:
        rows.append(("Removed", "listening", f"{proto}/{port}"))
    for c in diff.conns_new:
        rows.append(("Added", "connection", c))
    for c in diff.conns_gone:
        rows.append(("Removed", "connection", c))
    for a in diff.autoruns_added:
        rows.append(("Added", "autorun", a))
    for a in diff.autoruns_removed:
        rows.append(("Removed", "autorun", a))
    return rows


def capture(seq: int, include_autoruns: bool = True) -> Snapshot:
    """Snapshot current process/socket/autorun state (best effort per item)."""
    import psutil
    procs: set[tuple[int, str]] = set()
    for p in psutil.process_iter(["pid", "name"]):
        try:
            procs.add((p.info["pid"], p.info["name"] or "?"))
        except Exception:  # noqa: BLE001 - a process can vanish mid-iteration
            continue
    listening: set[tuple[str, int]] = set()
    connections: set[str] = set()
    try:
        for c in psutil.net_connections(kind="inet"):
            proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
            if c.status == psutil.CONN_LISTEN and c.laddr:
                listening.add((proto, c.laddr.port))
            elif c.status == psutil.CONN_ESTABLISHED and c.raddr:
                connections.add(f"{c.raddr.ip}:{c.raddr.port}")
    except (psutil.AccessDenied, OSError):
        pass
    autoruns: set[str] = set()
    if include_autoruns:
        try:
            from . import autoruns as ar
            for e in ar.enumerate_entries():
                autoruns.add(f"{e.name} @ {e.location}")
        except Exception:  # noqa: BLE001
            pass
    return Snapshot(seq=seq, ts=time.time(), processes=procs, listening=listening,
                    connections=connections, autoruns=autoruns)


class Timeline:
    """Bounded, thread-safe ring of session snapshots."""

    def __init__(self, max_snapshots: int = 50) -> None:
        self._snaps: list[Snapshot] = []
        self._max = max_snapshots
        self._next_seq = 0
        self._lock = threading.Lock()

    def next_seq(self) -> int:
        with self._lock:
            seq = self._next_seq
            self._next_seq += 1
            return seq

    def add(self, snap: Snapshot) -> None:
        with self._lock:
            self._snaps.append(snap)
            if len(self._snaps) > self._max:
                self._snaps.pop(0)
        logbus.trace(SRC, f"snapshot #{snap.seq} captured ({snap.counts()})")

    def snapshots(self) -> list[Snapshot]:
        with self._lock:
            return list(self._snaps)

    def __len__(self) -> int:
        with self._lock:
            return len(self._snaps)
