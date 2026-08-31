"""Guarded DMA physical-memory write: dry-run, audit-backed rollback, refusals.

A fake writable backend (a bytearray standing in for physical RAM) exercises the
whole guarded path with no PCILeech hardware attached.
"""
import pytest

from aetheris.core import dryrun
from aetheris.core.safety import RollbackLedger
from aetheris.forensics import dma
from aetheris.forensics.memvirt import Capabilities, MemoryBackend


class FakeDMA(MemoryBackend):
    """Stands in for a MemProcFS FPGA backend over an in-memory bytearray."""

    name = "Fake DMA device"

    def __init__(self, mem: bytes, writable: bool = True) -> None:
        self.mem = bytearray(mem)
        self.capabilities = Capabilities(physical=True, physical_write=writable)

    def list_processes(self):
        return []

    def memory_map(self, pid):
        return []

    def read(self, pid, address, size):
        return None

    def physical_read(self, address, size):
        return bytes(self.mem[address:address + size])

    def physical_write(self, address, data):
        if not self.capabilities.physical_write:
            return False
        self.mem[address:address + len(data)] = data
        return True


@pytest.fixture
def ledger(monkeypatch):
    """Isolate the rollback ledger so panic() only sees this test's entries."""
    fresh = RollbackLedger()
    monkeypatch.setattr(dma.safety, "ledger", fresh)
    return fresh


def test_write_changes_bytes_and_is_reversible(ledger):
    be = FakeDMA(b"\x00" * 16)
    ok, msg = dma.physical_write(be, 4, b"\xde\xad\xbe\xef")
    assert ok, msg
    assert be.mem[4:8] == b"\xde\xad\xbe\xef"
    # An undo was registered; running PANIC restores the original bytes.
    assert ledger.pending()
    ledger.panic()
    assert be.mem[4:8] == b"\x00\x00\x00\x00"


def test_dry_run_writes_nothing_and_registers_no_undo(ledger):
    be = FakeDMA(b"\x11" * 8)
    with dryrun.active(True):
        ok, msg = dma.physical_write(be, 0, b"\xff\xff")
    assert ok and "dry-run" in msg.lower()
    assert be.mem == bytearray(b"\x11" * 8)   # untouched
    assert not ledger.pending()               # nothing to undo


def test_read_only_backend_is_refused(ledger):
    be = FakeDMA(b"\x00" * 8, writable=False)
    ok, msg = dma.physical_write(be, 0, b"\x01")
    assert not ok and "cannot write" in msg
    assert be.mem == bytearray(b"\x00" * 8)
    assert not ledger.pending()


def test_zero_length_write_is_refused(ledger):
    be = FakeDMA(b"\x00" * 4)
    ok, _msg = dma.physical_write(be, 0, b"")
    assert not ok


def test_no_undo_when_snapshot_unreadable(ledger, monkeypatch):
    be = FakeDMA(b"\x00" * 8)
    monkeypatch.setattr(be, "physical_read", lambda address, size: None)
    ok, msg = dma.physical_write(be, 0, b"\x01\x02", verify=False)
    assert ok and "no rollback" in msg
    assert not ledger.pending()               # couldn't snapshot -> no undo


def test_write_capable_reflects_backend():
    assert dma.write_capable(FakeDMA(b"\x00", writable=True))
    assert not dma.write_capable(FakeDMA(b"\x00", writable=False))
