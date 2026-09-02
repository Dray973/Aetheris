"""Debugger pure core: breakpoint bookkeeping, event decoding, RIP/flag math.

A bytearray stands in for the target's memory so the whole breakpoint lifecycle
(set -> hit -> restore) is exercised with no live process."""
from aetheris.forensics import debugger as dbg


class FakeMem:
    def __init__(self, data: bytes) -> None:
        self.mem = bytearray(data)

    def read(self, address, size):
        return bytes(self.mem[address:address + size])

    def write(self, address, data):
        self.mem[address:address + len(data)] = data
        return True


def test_rip_fixup_and_trap_flag():
    assert dbg.rip_after_break(0x1001) == 0x1000
    assert dbg.set_trap_flag(0) == dbg.TRAP_FLAG
    assert dbg.clear_trap_flag(dbg.TRAP_FLAG | 0x2) == 0x2
    # setting then clearing is a round trip
    assert dbg.clear_trap_flag(dbg.set_trap_flag(0x202)) == 0x202


def test_decode_event():
    assert dbg.decode_event(dbg.CREATE_PROCESS_DEBUG_EVENT) == "create-process"
    assert dbg.decode_event(dbg.LOAD_DLL_DEBUG_EVENT) == "load-dll"
    assert dbg.decode_event(dbg.EXCEPTION_DEBUG_EVENT, dbg.EXCEPTION_BREAKPOINT) == "breakpoint"
    assert dbg.decode_event(dbg.EXCEPTION_DEBUG_EVENT, dbg.EXCEPTION_SINGLE_STEP) == "single-step"
    assert "access-violation" in dbg.decode_event(
        dbg.EXCEPTION_DEBUG_EVENT, dbg.EXCEPTION_ACCESS_VIOLATION)
    assert "0x" in dbg.decode_event(dbg.EXCEPTION_DEBUG_EVENT, 0xDEAD)


def test_breakpoint_set_saves_original_and_writes_cc():
    fm = FakeMem(b"\x90\x90\x48\x89\xe5")   # nop nop mov rbp,rsp
    bpm = dbg.BreakpointManager(fm.read, fm.write)
    ok, _ = bpm.set(2)
    assert ok
    assert fm.mem[2] == dbg.BREAKPOINT_BYTE            # 0xCC written
    assert bpm.get(2).original_byte == 0x48            # original saved
    assert bpm.is_ours(2) and bpm.addresses() == [2]


def test_breakpoint_clear_restores_original_byte():
    fm = FakeMem(b"\x90\x90\x48\x89\xe5")
    bpm = dbg.BreakpointManager(fm.read, fm.write)
    bpm.set(2)
    ok, _ = bpm.clear(2)
    assert ok
    assert fm.mem[2] == 0x48                            # restored exactly
    assert bpm.addresses() == [] and not bpm.is_ours(2)


def test_breakpoint_duplicate_and_missing_are_refused():
    fm = FakeMem(b"\x90\x90\x90\x90")
    bpm = dbg.BreakpointManager(fm.read, fm.write)
    assert bpm.set(1)[0]
    ok, msg = bpm.set(1)
    assert not ok and "already set" in msg
    ok, msg = bpm.clear(3)
    assert not ok and "no breakpoint" in msg


def test_on_hit_counts_and_restore_all():
    fm = FakeMem(b"\x90\x90\x90\x90")
    bpm = dbg.BreakpointManager(fm.read, fm.write)
    bpm.set(0)
    bpm.set(2)
    assert bpm.on_hit(0).hits == 1
    assert bpm.on_hit(0).hits == 2
    assert bpm.on_hit(99) is None                       # unknown address
    bpm.restore_all()
    assert fm.mem == bytearray(b"\x90\x90\x90\x90")     # both restored
    assert bpm.addresses() == []


def test_can_debug_refuses_critical():
    assert dbg.can_debug("notepad.exe")
    assert not dbg.can_debug("lsass.exe")
    assert not dbg.can_debug("CSRSS.EXE")               # case-insensitive
