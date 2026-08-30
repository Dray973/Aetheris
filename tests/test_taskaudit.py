"""Scheduled-task auditor: pure XML parser + suspicion heuristics + Windows smoke."""
import sys

import pytest

from aetheris.core import taskaudit as ta

_NS = 'xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"'


def _xml(author="MS", enabled=True, hidden=False, triggers="<LogonTrigger/>",
         command=r"C:\Windows\system32\foo.exe", args=""):
    en = "true" if enabled else "false"
    hd = "true" if hidden else "false"
    return (f'<?xml version="1.0" encoding="UTF-16"?>\n<Task {_NS}>'
            f"<RegistrationInfo><Author>{author}</Author><Description>d</Description>"
            f"</RegistrationInfo><Triggers>{triggers}</Triggers>"
            f"<Settings><Enabled>{en}</Enabled><Hidden>{hd}</Hidden></Settings>"
            f"<Actions><Exec><Command>{command}</Command>"
            f"<Arguments>{args}</Arguments></Exec></Actions></Task>")


def test_parse_basic_fields():
    t = ta.parse_task_xml(_xml(author="Contoso", triggers="<BootTrigger/><LogonTrigger/>"),
                          r"\A\B")
    assert t.name == "B" and t.path == r"\A\B"
    assert t.author == "Contoso" and t.enabled is True and t.hidden is False
    assert "boot" in t.triggers and "logon" in t.triggers
    assert t.action_binaries == [r"C:\Windows\system32\foo.exe"]


def test_parse_disabled_and_hidden():
    t = ta.parse_task_xml(_xml(enabled=False, hidden=True))
    assert t.enabled is False and t.hidden is True


def test_parse_invalid_and_non_task():
    assert ta.parse_task_xml("not xml at all") is None
    assert ta.parse_task_xml('<Foo xmlns="x"/>') is None


def test_suspicion_flags_and_is_suspicious():
    clean = ta.parse_task_xml(_xml(triggers="<CalendarTrigger/>"))
    clean.signed = "signed"
    clean.flags = ta.suspicion_flags(clean)
    assert clean.flags == [] and not ta.is_suspicious(clean)

    bad = ta.parse_task_xml(_xml(command=r"C:\Users\p\AppData\Local\Temp\x.exe",
                                 args="-enc ABCD"))
    bad.signed = "unsigned"
    bad.flags = ta.suspicion_flags(bad)
    assert "temp/download/public-dir action" in bad.flags
    assert "obfuscated/encoded shell command" in bad.flags
    assert "unsigned action binary" in bad.flags
    assert "runs at logon/boot" in bad.flags
    assert ta.is_suspicious(bad)

    weak = ta.parse_task_xml(_xml())          # signed logon task -> flagged but weak
    weak.signed = "signed"
    weak.flags = ta.suspicion_flags(weak)
    assert weak.flags == ["runs at logon/boot"] and not ta.is_suspicious(weak)


def test_resolve_binary(monkeypatch):
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    assert ta.resolve_binary(r'"%SystemRoot%\a.exe"').lower() == r"c:\windows\a.exe"


def test_render_markdown():
    bad = ta.parse_task_xml(_xml(command=r"C:\Temp\x.exe"), r"\Evil")
    bad.signed = "unsigned"
    bad.flags = ta.suspicion_flags(bad)
    md = ta.render_markdown([bad])
    assert "Suspicious scheduled tasks" in md and r"\Evil" in md
    assert "None flagged" in ta.render_markdown([])


def test_disable_task_registers_reverse_undo(monkeypatch):
    from aetheris.core import safety
    calls = []
    monkeypatch.setattr(ta, "_schtasks", lambda *a, **k: (calls.append(a), (0, "ok"))[1])
    fresh = safety.RollbackLedger()
    monkeypatch.setattr(safety, "ledger", fresh)

    ok, _ = ta.disable_task(r"\Evil")
    assert ok and calls[-1] == ("/change", "/tn", r"\Evil", "/disable")
    assert fresh.pending() == [r"task \Evil (disabled)"]
    fresh.panic()
    assert calls[-1] == ("/change", "/tn", r"\Evil", "/enable")   # undo re-enabled it


def test_task_remediation_honors_dry_run(monkeypatch):
    from aetheris.core import dryrun, safety
    called = {"n": 0}
    monkeypatch.setattr(ta, "_schtasks",
                        lambda *a, **k: (called.__setitem__("n", called["n"] + 1), (0, "ok"))[1])
    fresh = safety.RollbackLedger()
    monkeypatch.setattr(safety, "ledger", fresh)
    with dryrun.active():
        assert ta.disable_task(r"\X")[0]
        assert ta.enable_task(r"\X")[0]
    assert called["n"] == 0 and fresh.pending() == []


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Task Scheduler")
def test_enumerate_tasks_smoke():
    tasks = ta.enumerate_tasks()
    assert tasks and all(isinstance(t.path, str) and t.path for t in tasks)
    assert any(t.triggers for t in tasks)
    for t in ta.suspicious_tasks(tasks):
        assert ta.is_suspicious(t)
