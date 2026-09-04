"""
C++ Win32 engine: struct-layout contract and live behaviour.

These tests run against the real machine, so they assert invariants rather
than fixed values. The whole module skips when the DLL isn't built — it is an
optional engine, and its absence is a supported configuration, not a failure.

The layout tests are the important ones: every struct here is shared with
``aetheris_win.cpp`` by memory layout alone, so a field reordered on one side
and not the other would silently misread every row rather than raise. Pinning
the sizes catches that at test time instead of in a forensics report.
"""
import ctypes
import os

import pytest

from aetheris.native import win

pytestmark = pytest.mark.skipif(not win.available(), reason="aetheris_win.dll not built")


# --- ABI contract ----------------------------------------------------------


def test_struct_sizes_match_the_cpp_side():
    """Mirrors the #pragma pack(push, 8) structs in aetheris_win.cpp."""
    assert ctypes.sizeof(win._AwProcess) == 1576
    assert ctypes.sizeof(win._AwRegion) == 32
    assert ctypes.sizeof(win._AwHandleRaw) == 32


def test_error_codes_are_distinct():
    codes = {win.ERR_INVALID, win.ERR_UNSUPPORTED, win.ERR_DENIED, win.ERR_TIMEOUT}
    assert len(codes) == 4
    assert all(c < 0 for c in codes)


# --- processes -------------------------------------------------------------


def test_enum_processes_finds_this_one():
    procs = win.enum_processes()
    assert procs, "expected at least one process"
    me = [p for p in procs if p.pid == os.getpid()]
    assert len(me) == 1
    assert me[0].name.lower().startswith("python")
    # Our own image path is always readable; protected processes' may not be.
    assert me[0].exe.lower().endswith(".exe")


def test_process_pids_are_unique():
    procs = win.enum_processes()
    pids = [p.pid for p in procs]
    assert len(pids) == len(set(pids))


def test_mitigations_report_a_known_state():
    result = win.process_mitigations(os.getpid())
    assert result is not None
    dep, aslr = result
    assert dep in ("on", "off", "unknown")
    assert aslr in ("on", "off", "unknown")


def test_mitigations_on_a_dead_pid_do_not_raise():
    # pid 0xFFFFFFF0 will not exist; the engine must report, not crash.
    assert win.process_mitigations(0xFFFFFFF0) is None


# --- memory ----------------------------------------------------------------


def test_memory_map_of_self_is_sane():
    regions = win.memory_map(os.getpid())
    assert regions is not None
    assert len(regions) > 10
    assert all(r.size > 0 for r in regions)
    # MEM_FREE (0x10000) regions are filtered out by the engine.
    assert all(r.state != 0x10000 for r in regions)
    # The walk is monotonic: each region starts at or after the previous end.
    for a, b in zip(regions, regions[1:], strict=False):  # pairwise; last has no successor
        assert b.base >= a.base + a.size


def test_read_memory_round_trips_a_known_buffer():
    payload = b"AETHERIS-NATIVE-READ-PROBE-0123456789"
    buf = ctypes.create_string_buffer(payload)
    addr = ctypes.addressof(buf)
    got = win.read_memory(os.getpid(), addr, len(payload))
    assert got == payload


def test_read_memory_of_an_unmapped_address_returns_none():
    # A deliberately unmapped low address; must fail cleanly, not crash.
    assert win.read_memory(os.getpid(), 0x10, 16) is None


def test_read_memory_rejects_a_zero_length():
    assert win.read_memory(os.getpid(), 0x1000, 0) is None


# --- handles ---------------------------------------------------------------


def test_enum_handles_for_this_process():
    handles = win.enum_handles(os.getpid())
    assert handles, "this process holds handles"
    assert all(h.pid == os.getpid() for h in handles)
    assert all(h.handle for h in handles)


def test_system_wide_enumeration_is_a_superset():
    """The capability with no Python equivalent: every process at once."""
    mine = win.enum_handles(os.getpid())
    everything = win.enum_handles(0)
    assert len(everything) > len(mine)
    assert len({h.pid for h in everything}) > 1


def test_type_names_resolve_and_are_stable():
    handles = win.enum_handles(os.getpid())
    names = {}
    for h in handles:
        name = win.handle_type_name(h)
        if name:
            names.setdefault(h.type_index, name)
            # The engine caches by type index; the answer must not drift.
            assert names[h.type_index] == name
    assert names, "expected at least one resolvable type"
    assert any(v in ("File", "Key", "Event", "Directory", "Mutant", "Thread")
               for v in names.values())


def test_object_names_resolve_for_some_handles():
    handles = win.enum_handles(os.getpid())
    named = [win.handle_object_name(h) for h in handles]
    resolved = [n for n in named if n]
    assert resolved, "expected at least one named object in this process"
    # Named kernel objects are absolute paths in the object namespace.
    assert all(n.startswith("\\") for n in resolved)


def test_object_name_resolution_never_hangs():
    """The whole point of the C++ worker: a full sweep completes, even though
    NtQueryObject blocks forever on some handles."""
    import time

    handles = win.enum_handles(os.getpid())
    start = time.perf_counter()
    for h in handles:
        win.handle_object_name(h, timeout_ms=50)
    elapsed = time.perf_counter() - start
    # Generous: a hang would be unbounded, not merely slow.
    assert elapsed < 30.0, f"sweep took {elapsed:.1f}s — a query likely hung"


def test_process_handle_targets_resolve():
    """A Process handle names no object — only a target pid."""
    # Skip the System/Idle processes: they own the head of the table and refuse
    # PROCESS_DUP_HANDLE, so sampling from there resolves nothing at all.
    handles = [h for h in win.enum_handles(0) if h.pid not in (0, 4)]
    type_names = {}
    for h in handles:
        if h.type_index not in type_names:
            name = win.handle_type_name(h)
            if name:
                type_names[h.type_index] = name
        if "Process" in type_names.values():
            break
    proc_index = next((i for i, n in type_names.items() if n == "Process"), None)
    if proc_index is None:
        pytest.skip("no resolvable Process-type handle on this machine")
    targets = [
        win.handle_process_target(h) for h in handles if h.type_index == proc_index
    ]
    assert any(t > 0 for t in targets), "expected at least one resolvable target"


def test_reset_cache_is_safe_to_call():
    win.reset_cache()
    # Still functional afterwards — the cache is an optimisation, not state.
    assert win.enum_handles(os.getpid())
