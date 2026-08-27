"""Tamper-evident (hash-chained) audit log: chaining, verification, persistence.

Pure hashlib/json -- no Qt, no Windows. Proves that any edit, deletion, or
reorder of the recorded audit trail is detectable via the SHA-256 chain.
"""
import dataclasses
from itertools import pairwise

from aetheris.core import audit, logbus


def _fill(log, n=5):
    for i in range(n):
        log.append("ACTION", f"src{i}", f"message {i}", detail=f"d{i}")


def test_chain_links_and_verifies():
    log = audit.AuditLog()
    _fill(log, 5)
    recs = log.records()
    assert len(recs) == 5
    assert recs[0].prev_hash == audit.GENESIS_HASH        # first links to genesis
    for prev, cur in pairwise(recs):
        assert cur.prev_hash == prev.hash                 # each links to the prior
        assert cur.seq == prev.seq + 1
    ok, bad = log.verify()
    assert ok and bad == -1


def test_tampering_with_a_message_breaks_the_chain():
    log = audit.AuditLog()
    _fill(log, 5)
    # Forge record 2's message but keep its (now-stale) hash: verify must catch it.
    log._records[2] = dataclasses.replace(log._records[2], message="FORGED")
    ok, bad = log.verify()
    assert not ok and bad == 2


def test_deleting_a_record_breaks_the_chain():
    log = audit.AuditLog()
    _fill(log, 5)
    del log._records[2]                                    # snip one out
    ok, bad = log.verify()
    assert not ok                                         # prev_hash linkage broken


def test_reordering_records_breaks_the_chain():
    log = audit.AuditLog()
    _fill(log, 5)
    log._records[1], log._records[3] = log._records[3], log._records[1]
    ok, _bad = log.verify()
    assert not ok


def test_persistence_round_trip(tmp_path):
    p = tmp_path / "audit.jsonl"
    log = audit.AuditLog(path=str(p))
    _fill(log, 4)
    assert p.exists()
    reloaded = audit.AuditLog.load(str(p))
    assert len(reloaded) == 4
    ok, bad = reloaded.verify()
    assert ok and bad == -1
    assert [r.hash for r in reloaded.records()] == [r.hash for r in log.records()]


def test_on_disk_tamper_is_detected(tmp_path):
    p = tmp_path / "audit.jsonl"
    log = audit.AuditLog(path=str(p))
    _fill(log, 4)
    # Edit the persisted line for seq 1 without fixing its hash.
    lines = p.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace("message 1", "message HACKED")
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    reloaded = audit.AuditLog.load(str(p))
    ok, bad = reloaded.verify()
    assert not ok and bad == 1


def test_append_event_adapts_a_logbus_event():
    log = audit.AuditLog()
    ev = logbus.LogEvent(level=logbus.Level.ACTION, source="network.firewall",
                         message="isolate app", detail="rc=0")
    rec = log.append_event(ev)
    assert rec.level == "ACTION" and rec.source == "network.firewall"
    assert rec.message == "isolate app" and rec.detail == "rc=0"
    ok, _ = log.verify()
    assert ok
