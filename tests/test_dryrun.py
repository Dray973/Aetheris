"""Global dry-run mode: flag semantics + a real op that must not mutate."""
import sys

import pytest

from aetheris.core import dryrun


def teardown_function(_fn):
    dryrun.set_enabled(False)   # never leak the flag between tests


def test_disabled_by_default():
    assert dryrun.enabled() is False
    assert dryrun.skip("t", "do a thing") is False


def test_set_enabled_returns_previous_and_toggles():
    assert dryrun.set_enabled(True) is False
    assert dryrun.enabled() is True
    assert dryrun.set_enabled(False) is True
    assert dryrun.enabled() is False


def test_active_context_restores_prior_state():
    assert dryrun.enabled() is False
    with dryrun.active():
        assert dryrun.enabled() is True
        assert dryrun.skip("t", "would act") is True
    assert dryrun.enabled() is False           # restored


def test_active_restores_even_when_already_on():
    dryrun.set_enabled(True)
    with dryrun.active(False):
        assert dryrun.enabled() is False
    assert dryrun.enabled() is True            # restored to prior (on)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows registry")
def test_registry_set_value_dryrun_makes_no_change_and_no_undo():
    import winreg

    from aetheris.core import registry, safety

    root, subkey, name = "HKCU", r"Software\AetherisQuantumCoreTest", "dryrun_probe"
    # Ensure the probe value does not exist beforehand.
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey, 0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(k, name)
        winreg.CloseKey(k)
    except OSError:
        pass

    before = len(safety.ledger.pending())
    with dryrun.active():
        ok, msg = registry.set_value(root, subkey, name, 1)
    assert ok                                   # reports simulated success
    assert len(safety.ledger.pending()) == before   # registered NO rollback

    # The value was never written.
    with pytest.raises(OSError):
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey)
        try:
            winreg.QueryValueEx(k, name)
        finally:
            winreg.CloseKey(k)


def test_auto_shell_run_honors_dry_run(monkeypatch):
    from aetheris.automation import nlshell

    called = {"n": 0}
    monkeypatch.setattr(nlshell.subprocess, "run",
                        lambda *a, **k: called.__setitem__("n", called["n"] + 1))
    cmd = nlshell.compile("flush dns")
    assert cmd.matched and cmd.script                # a real compiled script exists
    with dryrun.active():
        ok, msg = nlshell.run(cmd)
    assert ok and "dry-run" in msg.lower()           # simulated success
    assert called["n"] == 0                          # PowerShell never executed


@pytest.mark.skipif(sys.platform != "win32", reason="Windows process APIs")
def test_process_kill_honors_dry_run():
    import subprocess as sp

    from aetheris.forensics import processes

    child = sp.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        with dryrun.active():
            ok, msg = processes.kill(child.pid)
        assert ok and "dry-run" in msg.lower()
        assert child.poll() is None                  # still alive -> not terminated
    finally:
        child.kill()
        child.wait()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows memory APIs")
def test_patch_memory_honors_dry_run():
    from aetheris.forensics import disasm

    with dryrun.active():                            # gate is first -> never opens pid
        ok, msg = disasm.patch_memory(0x7FFFFFFF, 0x1000, b"\x90\x90")
    assert ok and "dry-run" in msg.lower()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows service APIs")
def test_disable_diagtrack_honors_dry_run(monkeypatch):
    import subprocess as sp

    from aetheris.core import registry

    called = {"n": 0}
    monkeypatch.setattr(sp, "run", lambda *a, **k: called.__setitem__("n", called["n"] + 1))
    with dryrun.active():
        ok, msg = registry.disable_diagtrack_service()
    assert ok and "dry-run" in msg.lower()
    assert called["n"] == 0                           # `sc` never ran


@pytest.mark.skipif(sys.platform != "win32", reason="Windows registry")
def test_registry_set_value_applies_when_not_dry_run():
    import winreg

    from aetheris.core import registry

    root, subkey, name = "HKCU", r"Software\AetherisQuantumCoreTest", "live_probe"
    try:
        ok, _ = registry.set_value(root, subkey, name, 7)
        assert ok
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey)
        val, _t = winreg.QueryValueEx(k, name)
        winreg.CloseKey(k)
        assert val == 7
    finally:                                    # clean up the probe key entirely
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, subkey)
        except OSError:
            pass
