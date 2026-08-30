"""Session timeline: pure state diff + ring buffer + Windows capture smoke."""
import sys

import pytest

from aetheris.core import timeline as tl


def _snap(seq, procs=(), listen=(), conns=(), autoruns=()):
    return tl.Snapshot(seq=seq, ts=float(seq), processes=set(procs),
                       listening=set(listen), connections=set(conns),
                       autoruns=set(autoruns))


def test_diff_detects_all_categories():
    a = _snap(0, procs=[(1, "a"), (2, "b")], listen=[("tcp", 80)],
              conns=["1.1.1.1:443"], autoruns=["x @ Run"])
    b = _snap(1, procs=[(2, "b"), (3, "c")], listen=[("tcp", 80), ("udp", 53)],
              conns=["2.2.2.2:443"], autoruns=["y @ Run"])
    d = tl.diff_snapshots(a, b)
    assert d.procs_started == [(3, "c")] and d.procs_exited == [(1, "a")]
    assert d.ports_opened == [("udp", 53)] and d.ports_closed == []
    assert d.conns_new == ["2.2.2.2:443"] and d.conns_gone == ["1.1.1.1:443"]
    assert d.autoruns_added == ["y @ Run"] and d.autoruns_removed == ["x @ Run"]
    assert not d.is_empty() and "proc" in d.summary()


def test_diff_empty_when_identical():
    a = _snap(0, procs=[(1, "a")])
    assert tl.diff_snapshots(a, _snap(1, procs=[(1, "a")])).is_empty()


def test_diff_rows_flatten():
    b = _snap(1, procs=[(9, "new")], autoruns=["z @ Startup"])
    rows = tl.diff_rows(tl.diff_snapshots(_snap(0), b))
    assert ("Added", "process", "new (pid 9)") in rows
    assert ("Added", "autorun", "z @ Startup") in rows


def test_timeline_ring_evicts_oldest():
    t = tl.Timeline(max_snapshots=3)
    seqs = [t.next_seq() for _ in range(5)]
    assert seqs == [0, 1, 2, 3, 4]
    for s in seqs:
        t.add(_snap(s))
    assert [s.seq for s in t.snapshots()] == [2, 3, 4] and len(t) == 3


@pytest.mark.skipif(sys.platform != "win32", reason="Windows process/socket enumeration")
def test_capture_smoke():
    snap = tl.capture(0, include_autoruns=False)
    assert snap.processes and all(isinstance(pid, int) for pid, _ in snap.processes)
    assert isinstance(snap.listening, set)
