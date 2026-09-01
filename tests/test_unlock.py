"""Guarded obliterator: the safety guardrails (protected roots, confirm, dry-run)."""
import sys

import pytest

from aetheris.storage import unlock


def test_obliterate_requires_confirm():
    ok, msg = unlock.obliterate("anything", confirm=False)
    assert not ok and "confirmation" in msg.lower()


def test_obliterate_refuses_missing_file(tmp_path):
    ok, msg = unlock.obliterate(str(tmp_path / "nope.bin"), confirm=True)
    assert not ok and "does not exist" in msg.lower()


def test_obliterate_honors_dry_run(tmp_path):
    from aetheris.core import dryrun
    f = tmp_path / "victim.bin"
    f.write_bytes(b"x")
    with dryrun.active():
        ok, msg = unlock.obliterate(str(f), confirm=True)
    assert ok and "dry-run" in msg.lower()
    assert f.exists()


def test_critical_processes_cover_the_essentials():
    assert {"lsass.exe", "csrss.exe", "winlogon.exe", "services.exe",
            "smss.exe", "wininit.exe"} <= unlock.CRITICAL_PROCESSES


@pytest.mark.skipif(sys.platform != "win32", reason="Windows path semantics")
def test_is_protected_path_boundary_and_coverage(monkeypatch):
    monkeypatch.setattr(unlock, "PROTECTED_ROOTS", ("c:\\windows", "c:\\program files"))
    assert unlock.is_protected_path(r"C:\Windows\System32\x.dll")
    assert unlock.is_protected_path("C:\\Windows")
    assert unlock.is_protected_path(r"C:\Program Files\App\x.exe")
    assert not unlock.is_protected_path(r"C:\WindowsApps\evil.exe")
    assert not unlock.is_protected_path(r"C:\Users\me\Downloads\x.txt")
