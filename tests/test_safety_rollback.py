"""RollbackLedger: PANIC round-trips every registered reversible op.

Covers the ledger contract (LIFO, error isolation, queue drain), a model of
every reversible *shape* used in the codebase (set/restore, add/remove,
rename-back), and a real Windows registry op that mutates then reverts via
panic() -- the end-to-end "register alongside the change, PANIC reverses it"
guarantee the safety model promises.
"""
import sys

import pytest

from aetheris.core import safety


def test_panic_runs_undos_lifo_and_drains_the_queue():
    ledger = safety.RollbackLedger()
    order = []
    for i in range(4):
        ledger.register(f"op{i}", lambda i=i: order.append(i))
    assert ledger.pending() == ["op0", "op1", "op2", "op3"]

    results = ledger.panic()
    assert order == [3, 2, 1, 0]
    assert all(ok for _lbl, ok, _note in results)
    assert results[0][0] == "op3"
    assert ledger.pending() == []
    assert ledger.panic() == []


def test_panic_isolates_a_failing_undo():
    ledger = safety.RollbackLedger()
    ran = []

    def boom():
        raise RuntimeError("undo failed")

    ledger.register("good-1", lambda: ran.append("g1"))
    ledger.register("bad", boom)
    ledger.register("good-2", lambda: ran.append("g2"))

    results = {lbl: (ok, note) for lbl, ok, note in ledger.panic()}
    assert ran == ["g2", "g1"]
    assert results["good-1"][0] and results["good-2"][0]
    assert results["bad"][0] is False
    assert "undo failed" in results["bad"][1]
    assert ledger.pending() == []


def test_every_reversible_shape_round_trips():
    """One representative of each reversible category in the app: each registers
    an undo that must return the shared state to its exact starting snapshot."""
    ledger = safety.RollbackLedger()
    state = {"reg_value": 1, "firewall_rules": set(), "autorun_enabled": True}
    initial = {"reg_value": 1, "firewall_rules": set(), "autorun_enabled": True}

    prior = state["reg_value"]
    state["reg_value"] = 99
    ledger.register("registry set", lambda p=prior: state.__setitem__("reg_value", p))

    added = {"BLOCK out", "BLOCK in"}
    state["firewall_rules"] |= added
    ledger.register("firewall isolate",
                    lambda a=added: state["firewall_rules"].difference_update(a))

    state["autorun_enabled"] = False
    ledger.register("autorun disable",
                    lambda: state.__setitem__("autorun_enabled", True))

    assert state != initial
    results = ledger.panic()
    assert all(ok for _l, ok, _n in results)
    assert state == initial


@pytest.mark.skipif(sys.platform != "win32", reason="Windows registry")
def test_real_registry_op_round_trips_via_panic(monkeypatch):
    import winreg

    from aetheris.core import registry

    fresh = safety.RollbackLedger()
    monkeypatch.setattr(safety, "ledger", fresh)

    root, subkey, name = "HKCU", r"Software\AetherisQuantumCoreTest", "rollback_probe"
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, subkey)
    except OSError:
        pass
    ok, _ = registry.set_value(root, subkey, name, 5)
    assert ok
    assert fresh.pending() == [f"registry {root}\\{subkey}\\{name}"]
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey)
    assert winreg.QueryValueEx(k, name)[0] == 5
    winreg.CloseKey(k)

    fresh.panic()
    with pytest.raises(OSError):
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey)
        try:
            winreg.QueryValueEx(k, name)
        finally:
            winreg.CloseKey(k)

    registry.set_value(root, subkey, name, 3)
    fresh2 = safety.RollbackLedger()
    monkeypatch.setattr(safety, "ledger", fresh2)
    registry.set_value(root, subkey, name, 8)
    fresh2.panic()
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey)
    restored = winreg.QueryValueEx(k, name)[0]
    winreg.CloseKey(k)
    assert restored == 3

    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, subkey)
