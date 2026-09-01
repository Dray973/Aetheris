"""Service & driver inspector: pure path/detector helpers + a Windows smoke."""
import sys

import pytest

from aetheris.core import services


def test_parse_binary_quoted_unquoted_and_driver():
    assert services.parse_binary('"C:\\Program Files\\App\\s.exe" -k x') \
        == r"C:\Program Files\App\s.exe"
    assert services.parse_binary(r"C:\Windows\system32\svchost.exe -k netsvcs") \
        == r"C:\Windows\system32\svchost.exe"
    assert services.parse_binary(r"\SystemRoot\System32\drivers\x.sys") \
        == r"\SystemRoot\System32\drivers\x.sys"
    assert services.parse_binary("") == ""


def test_resolve_path_expands_systemroot(monkeypatch):
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    assert services.resolve_path(r"\SystemRoot\System32\drivers\x.sys").lower() \
        == r"c:\windows\system32\drivers\x.sys"
    assert services.resolve_path(r"System32\drivers\y.sys").lower() == r"c:\windows\system32\drivers\y.sys"
    assert services.resolve_path(r'"C:\a\b.exe"') == r"C:\a\b.exe"


def test_start_type_label():
    assert services.start_type_label(2) == "auto"
    assert services.start_type_label(4) == "disabled"
    assert services.start_type_label(99) == "unknown"


def test_normalize_start_folds_psutil_vocab():
    assert services.normalize_start("Automatic") == "auto"
    assert services.normalize_start("automatic delayed") == "auto"
    assert services.normalize_start("Manual") == "manual"
    assert services.normalize_start("Disabled") == "disabled"
    assert services.normalize_start("") == "unknown"


def test_unquoted_path_detector():
    assert services.has_unquoted_path_vuln(r"C:\Program Files\App\svc.exe", "service") is True
    assert services.has_unquoted_path_vuln(r'"C:\Program Files\App\svc.exe"', "service") is False
    assert services.has_unquoted_path_vuln(
        r"C:\Windows\system32\svchost.exe -k net", "service") is False
    assert services.has_unquoted_path_vuln(
        r"C:\Program Files\App\svc.exe", "driver") is False
    assert services.has_unquoted_path_vuln(r"C:\NoSpace\svc.exe", "service") is False


def test_unquoted_path_issues_filter():
    a = services.ServiceInfo("a", "A", "", "", "auto", "service", unquoted_path=True)
    b = services.ServiceInfo("b", "B", "", "", "auto", "service", unquoted_path=False)
    assert services.unquoted_path_issues([a, b]) == [a]


def test_stop_service_registers_reverse_undo(monkeypatch):
    from aetheris.core import safety
    calls = []
    monkeypatch.setattr(services, "_sc", lambda *a, **k: (calls.append(a), (0, "ok"))[1])
    fresh = safety.RollbackLedger()
    monkeypatch.setattr(safety, "ledger", fresh)

    ok, _ = services.stop_service("Foo")
    assert ok and calls[-1] == ("stop", "Foo")
    assert fresh.pending() == ["service Foo (stopped)"]
    fresh.panic()
    assert calls[-1] == ("start", "Foo")


def test_set_start_type_undo_restores_old(monkeypatch):
    from aetheris.core import safety
    calls = []
    monkeypatch.setattr(services, "_sc", lambda *a, **k: (calls.append(a), (0, "ok"))[1])
    monkeypatch.setattr(services, "current_start_type", lambda name: "auto")
    fresh = safety.RollbackLedger()
    monkeypatch.setattr(safety, "ledger", fresh)

    ok, _ = services.set_start_type("Bar", "disabled")
    assert ok and calls[-1] == ("config", "Bar", "start=", "disabled")
    fresh.panic()
    assert calls[-1] == ("config", "Bar", "start=", "auto")


def test_service_control_honors_dry_run(monkeypatch):
    from aetheris.core import dryrun, safety
    called = {"n": 0}
    monkeypatch.setattr(services, "_sc",
                        lambda *a, **k: (called.__setitem__("n", called["n"] + 1), (0, "ok"))[1])
    fresh = safety.RollbackLedger()
    monkeypatch.setattr(safety, "ledger", fresh)
    with dryrun.active():
        assert services.start_service("X")[0]
        assert services.stop_service("X")[0]
        assert services.set_start_type("X", "disabled")[0]
    assert called["n"] == 0
    assert fresh.pending() == []


def test_set_start_type_rejects_unknown():
    ok, msg = services.set_start_type("X", "bogus")
    assert not ok and "unknown" in msg.lower()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows SCM/registry")
def test_enumerate_services_and_drivers_smoke():
    svcs = services.enumerate_services()
    assert svcs and all(s.kind == "service" for s in svcs)
    assert svcs[0].name and svcs[0].start_type and svcs[0].state
    drvs = services.enumerate_drivers()
    assert drvs and all(d.kind == "driver" for d in drvs)
    assert any(d.state == "loaded" for d in drvs)
    for v in services.unquoted_path_issues(svcs):
        assert " " in v.image_path and not v.image_path.strip().startswith('"')
