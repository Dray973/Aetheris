"""Reversible quarantine: rename in place, restore via ledger or manifest."""
from aetheris.core import dryrun
from aetheris.core.safety import RollbackLedger
from aetheris.storage import quarantine as Q


def _isolated_ledger(monkeypatch):
    led = RollbackLedger()
    monkeypatch.setattr(Q.safety, "ledger", led)
    return led


def test_quarantine_then_undo_via_ledger(tmp_path, monkeypatch):
    led = _isolated_ledger(monkeypatch)
    f = tmp_path / "upd.exe"
    f.write_bytes(b"MZ")
    ok, msg = Q.quarantine(str(f))
    assert ok and not f.exists() and (tmp_path / ("upd.exe" + Q.SUFFIX)).exists()
    assert [r.original for r in Q.listing()] == [str(f)]
    led.panic()
    assert f.read_bytes() == b"MZ" and Q.listing() == []


def test_restore_after_restart_uses_the_manifest(tmp_path, monkeypatch):
    _isolated_ledger(monkeypatch)
    f = tmp_path / "a.exe"
    f.write_bytes(b"x")
    Q.quarantine(str(f))
    # A new session has an empty ledger; the manifest alone must suffice.
    _isolated_ledger(monkeypatch)
    ok, _ = Q.restore(str(f))
    assert ok and f.exists()


def test_refusals(tmp_path, monkeypatch):
    _isolated_ledger(monkeypatch)
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    assert "Windows directory" in Q.is_refused(r"C:\Windows\System32\cmd.exe")
    assert Q.is_refused(r"C:\WindowsApps\x.exe") is None
    assert Q.is_refused("x.exe" + Q.SUFFIX) == "already quarantined"
    ok, msg = Q.quarantine(str(tmp_path / "missing.exe"))
    assert not ok and "not found" in msg


def test_restore_never_overwrites_a_new_file(tmp_path, monkeypatch):
    _isolated_ledger(monkeypatch)
    f = tmp_path / "b.exe"
    f.write_bytes(b"old")
    Q.quarantine(str(f))
    f.write_bytes(b"new")
    ok, msg = Q.restore(str(f))
    assert not ok and "refusing to overwrite" in msg and f.read_bytes() == b"new"


def test_dry_run_touches_nothing(tmp_path, monkeypatch):
    led = _isolated_ledger(monkeypatch)
    f = tmp_path / "c.exe"
    f.write_bytes(b"x")
    with dryrun.active():
        ok, msg = Q.quarantine(str(f))
    assert ok and msg.startswith("[dry-run]") and f.exists()
    assert led.pending() == [] and Q.listing() == []


def test_unknown_restore_is_reported():
    ok, msg = Q.restore(r"C:\nope.exe")
    assert not ok and "no quarantine record" in msg
