"""LSASS-access + download detectors, ledger transaction groups, suspend."""
import threading
from types import SimpleNamespace as NS

import psutil
import pytest

from aetheris.analysis import findings
from aetheris.core import dryrun
from aetheris.core.safety import RollbackLedger
from aetheris.forensics import credaccess, motw, processes
from aetheris.native import win

EVIL = r"C:\Users\bob\AppData\Local\Temp\dump.exe"


def _h(pid=4242, exe=EVIL, name="dump.exe", access=0x1010):
    return credaccess.LsassHandle(pid, name, exe, 700, access)


# --- LSASS detector --------------------------------------------------------


def test_unsigned_reader_of_lsass_is_critical():
    procs = [NS(pid=4242, signature="unsigned")]
    (f,) = findings.detect_credential_access([_h()], procs)
    assert f.technique == "T1003.001" and f.severity == "critical"
    assert "VM_READ" in " ".join(f.evidence)
    assert f.key == "dump.exe"


def test_query_only_handles_are_ignored_by_collection_filter():
    assert not credaccess.is_dangerous(0x1000)        # QUERY_LIMITED_INFORMATION
    assert credaccess.is_dangerous(0x1010)
    assert credaccess.is_dangerous(0x1FFFFF)          # PROCESS_ALL_ACCESS


@pytest.mark.parametrize("exe,sig,expected", [
    (r"C:\Windows\System32\svchost.exe", "signed", True),
    (r"C:\Windows\System32\csrss.exe", "", True),
    (r"C:\Users\bob\Temp\svchost.exe", "signed", False),   # look-alike in the wrong place
    (r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe", "signed", True),
    (r"C:\Temp\MsMpEng.exe", "unsigned", False),            # unsigned impostor
    (EVIL, "unsigned", False),
])
def test_expected_holders_match_on_path_and_signature(exe, sig, expected):
    assert credaccess.is_expected(exe, sig) is expected


def test_allowed_system_holders_produce_no_finding():
    h = _h(pid=900, exe=r"C:\Windows\System32\svchost.exe", name="svchost.exe")
    assert findings.detect_credential_access([h], [NS(pid=900, signature="signed")]) == []


def test_handles_from_one_holder_merge_into_one_finding():
    hs = [_h(access=0x1000 | 0x0010), _h(access=0x0020)]
    (f,) = findings.detect_credential_access(hs, [NS(pid=4242, signature="signed")])
    assert "VM_READ" in f.evidence[1] and "VM_WRITE" in f.evidence[1]
    assert f.score == 70


def test_collect_filters_by_type_access_and_target(monkeypatch):
    E = win.HandleEntry
    table = [
        E(pid=4242, handle=0x10, object=1, granted_access=0x1010, attributes=0, type_index=7),
        E(pid=4242, handle=0x14, object=2, granted_access=0x1000, attributes=0, type_index=7),
        E(pid=4242, handle=0x18, object=3, granted_access=0x1010, attributes=0, type_index=7),
        E(pid=5555, handle=0x20, object=4, granted_access=0x1010, attributes=0, type_index=9),
        E(pid=700, handle=0x30, object=5, granted_access=0x1FFFFF, attributes=0, type_index=7),
    ]
    targets = {(4242, 0x10): 700, (4242, 0x18): 812}
    type_lookups: list[int] = []

    def type_name(e):
        type_lookups.append(e.type_index)
        return {7: "Process", 9: "File"}[e.type_index]

    monkeypatch.setattr(win, "available", lambda: True)
    monkeypatch.setattr(win, "enum_handles", lambda pid=0: table)
    monkeypatch.setattr(win, "handle_type_name", type_name)
    monkeypatch.setattr(win, "handle_process_target",
                        lambda e: targets.get((e.pid, e.handle), 0))
    procs = [NS(pid=700, name="lsass.exe", exe=r"C:\Windows\System32\lsass.exe"),
             NS(pid=4242, name="dump.exe", exe=EVIL)]
    got = credaccess.collect(procs)
    assert got == [credaccess.LsassHandle(4242, "dump.exe", EVIL, 700, 0x1010)]
    assert sorted(type_lookups) == [7, 9], "type resolved once per index"


def test_collect_is_none_when_it_cannot_answer(monkeypatch):
    monkeypatch.setattr(win, "available", lambda: False)
    assert credaccess.collect([]) is None
    monkeypatch.setattr(win, "available", lambda: True)
    assert credaccess.collect([NS(pid=1, name="x.exe")]) is None  # no lsass seen


# --- downloads (Mark-of-the-Web) -------------------------------------------


def _origin():
    return motw.parse("[ZoneTransfer]\nZoneId=3\nHostUrl=https://cdn.bad.example/u.exe\n")


def test_download_detector_and_correlation():
    procs = [NS(pid=1, name="upd.exe", exe=EVIL, signature="unsigned")]
    origins = {EVIL.lower(): _origin()}
    (d,) = findings.detect_downloads(procs, origins)
    assert d.technique == "T1204.002" and "cdn.bad.example" in " ".join(d.evidence)
    merged = findings.analyze(processes=procs, origins=origins,
                              lsass_handles=[_h(pid=1, exe=EVIL)])
    top = merged[0]
    assert top.category == "correlated" and top.severity == "critical"
    assert "T1204.002" in top.technique_name and "T1003.001" in top.technique_name


def test_local_zone_files_are_not_flagged():
    local = motw.parse("[ZoneTransfer]\nZoneId=0\n")
    procs = [NS(pid=1, name="a.exe", exe=EVIL, signature="unsigned")]
    assert findings.detect_downloads(procs, {EVIL.lower(): local}) == []


def test_collect_origins_skips_windows_and_dedupes():
    calls: list[str] = []

    def read(path):
        calls.append(path)
        return _origin()

    procs = [NS(exe=EVIL), NS(exe=EVIL), NS(exe=r"C:\Windows\System32\cmd.exe"), NS(exe="")]
    out = findings.collect_origins(procs, read)
    assert calls == [EVIL] and list(out) == [EVIL.lower()]


# --- ledger groups ---------------------------------------------------------


def test_group_undoes_as_a_unit_in_reverse():
    led = RollbackLedger()
    log: list[str] = []
    led.register("before", lambda: log.append("before"))
    with led.group("contain x") as g:
        led.register("a", lambda: log.append("a"))
        led.register("b", lambda: log.append("b"))
    assert g.id and g.members == ["a", "b"]
    assert led.pending() == ["before", "contain x"]
    results = led.undo(g.id)
    assert log == ["b", "a"] and [r[1] for r in results] == [True, True]
    assert led.pending() == ["before"] and not led.has(g.id)
    assert led.undo(g.id)[0][1] is False  # second undo is a no-op


def test_group_survives_a_failure_midway():
    led = RollbackLedger()
    with pytest.raises(RuntimeError):
        with led.group("half done"):
            led.register("step 1", lambda: None)
            raise RuntimeError("step 2 failed")
    assert led.pending() == ["half done"]


def test_failed_member_is_reported_not_raised():
    led = RollbackLedger()

    def boom():
        raise OSError("nope")

    with led.group("g") as g:
        led.register("ok", lambda: None)
        led.register("bad", boom)
    results = led.undo(g.id)
    assert ("bad", False, "nope") in results and ("ok", True, "reverted") in results


def test_empty_group_leaves_nothing_and_panic_expands_groups():
    led = RollbackLedger()
    with led.group("empty") as g:
        pass
    assert g.id == 0 and led.pending() == []
    log: list[str] = []
    with led.group("g"):
        led.register("x", lambda: log.append("x"))
    assert [r[0] for r in led.panic()] == ["x"] and log == ["x"]


def test_groups_are_per_thread():
    led = RollbackLedger()
    ready, done = threading.Event(), threading.Event()

    def other():
        ready.wait(2)
        led.register("other thread", lambda: None)
        done.set()

    t = threading.Thread(target=other)
    t.start()
    with led.group("mine"):
        led.register("mine-1", lambda: None)
        ready.set()
        done.wait(2)
    t.join()
    assert sorted(led.pending()) == ["mine", "other thread"]


# --- suspend / resume ------------------------------------------------------


def test_suspend_registers_a_guarded_resume(monkeypatch):
    led = RollbackLedger()
    monkeypatch.setattr(processes.safety, "ledger", led)
    calls: list[str] = []

    class FakeProc:
        def __init__(self, pid):
            self.pid = pid
        def name(self):
            return "dump.exe"
        def create_time(self):
            return 100.0
        def suspend(self):
            calls.append("suspend")
        def resume(self):
            calls.append("resume")

    monkeypatch.setattr(psutil, "Process", FakeProc)
    ok, msg = processes.suspend(4242)
    assert ok and "suspended" in msg and led.pending() == ["suspend dump.exe (pid 4242)"]
    led.panic()
    assert calls == ["suspend", "resume"]


def test_resume_refuses_a_recycled_pid(monkeypatch):
    class Recycled:
        def __init__(self, pid):
            pass
        def create_time(self):
            return 999.0
        def resume(self):
            raise AssertionError("must not resume another process")

    monkeypatch.setattr(psutil, "Process", Recycled)
    with pytest.raises(RuntimeError, match="different process"):
        processes._resume_checked(4242, 100.0)


def test_suspend_respects_dry_run(monkeypatch):
    monkeypatch.setattr(psutil, "Process",
                        lambda pid: pytest.fail("dry-run must not touch the process"))
    with dryrun.active():
        ok, msg = processes.suspend(1)
    assert ok and msg.startswith("[dry-run]")


def test_snapshot_carries_lineage():
    me = next(p for p in processes.snapshot() if p.pid == psutil.Process().pid)
    assert me.ppid == psutil.Process().ppid()
    assert me.create_time > 0 and "python" in me.cmdline.lower()
