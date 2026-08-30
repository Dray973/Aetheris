"""Unified persistence map: source merge + reversible toggle dispatch."""
import sys

import pytest

from aetheris.core import persistence


def test_set_enabled_dispatches_by_source(monkeypatch):
    from aetheris.core import autoruns, services, taskaudit
    calls = []
    monkeypatch.setattr(autoruns, "disable",
                        lambda e: (calls.append(("ar.disable", e)), (True, ""))[1])
    monkeypatch.setattr(autoruns, "enable",
                        lambda e: (calls.append(("ar.enable", e)), (True, ""))[1])
    monkeypatch.setattr(services, "set_start_type",
                        lambda n, t: (calls.append(("svc", n, t)), (True, ""))[1])
    monkeypatch.setattr(taskaudit, "disable_task",
                        lambda p: (calls.append(("task.disable", p)), (True, ""))[1])

    persistence.set_enabled(persistence.PersistenceEntry("Run", "a", "", "", ref="AR"), False)
    persistence.set_enabled(persistence.PersistenceEntry("Startup", "b", "", "", ref="AR2"), True)
    persistence.set_enabled(persistence.PersistenceEntry("Service", "S", "", "", ref="Spooler"), False)
    persistence.set_enabled(persistence.PersistenceEntry("Task", "t", "", "", ref=r"\X"), False)

    assert calls[0] == ("ar.disable", "AR")
    assert calls[1] == ("ar.enable", "AR2")
    assert calls[2] == ("svc", "Spooler", "disabled")
    assert calls[3] == ("task.disable", r"\X")


def test_set_enabled_unknown_source():
    ok, msg = persistence.set_enabled(
        persistence.PersistenceEntry("Weird", "x", "", ""), True)
    assert not ok and "cannot toggle" in msg.lower()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows enumeration")
def test_enumerate_all_merges_sources():
    entries = persistence.enumerate_all()
    assert entries
    sources = {e.source for e in entries}
    assert "Service" in sources                 # a real box always has auto services
    for e in entries:
        assert e.source in ("Run", "Startup", "Service", "Task") and e.name
