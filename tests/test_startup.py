"""Startup-impact parsing, merge/ranking (pure) + the tab."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from aetheris.core import startup  # noqa: E402

NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _event(eid: int, data: dict[str, str]) -> str:
    rows = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return (f'<Event xmlns="{NS}"><System><EventID>{eid}</EventID></System>'
            f'<EventData>{rows}</EventData></Event>')


def test_parse_boot_total_and_degradations():
    events = [
        _event(100, {"BootTime": "42000"}),
        _event(101, {"Name": r"C:\Temp\upd.exe", "TotalTime": "5200"}),
        _event(103, {"Name": "LazySvc", "TotalTime": "1500"}),
        _event(102, {"Name": "slowdrv.sys", "DegradationTime": "800"}),
    ]
    costs, boot = startup.parse_boot_events(events)
    assert boot == 42000
    by = {c.name: (c.kind, c.total_ms) for c in costs}
    assert by[r"C:\Temp\upd.exe"] == ("app", 5200)
    assert by["LazySvc"] == ("service", 1500)
    assert by["slowdrv.sys"] == ("driver", 800)


def test_parse_skips_junk_and_unknown_ids():
    costs, boot = startup.parse_boot_events(["not xml", _event(999, {"Name": "x"}),
                                             _event(101, {"Name": "", "TotalTime": "9"})])
    assert costs == [] and boot is None


def test_impact_bands():
    def band(ms):
        return startup.StartupItem("n", "c", "app", "s", impact_ms=ms).impact
    assert band(None) == startup.NONE
    assert band(200) == startup.LOW
    assert band(1500) == startup.MEDIUM
    assert band(4000) == startup.HIGH


def test_merge_matches_on_basename_and_sums():
    items = [
        startup.StartupItem("Updater", r"C:\Temp\upd.exe", "app", "Run"),
        startup.StartupItem("LazySvc", r"C:\svc\lazy.exe", "service", "service (auto)"),
        startup.StartupItem("Quiet", r"C:\q\quiet.exe", "app", "Run"),
    ]
    costs = [startup.BootCost(r"C:\Windows\Temp\upd.exe", "app", 3000),
             startup.BootCost("upd.exe", "app", 1000),   # same binary, another boot
             startup.BootCost("LazySvc", "service", 1500)]
    report = startup.merge(items, costs)
    by = {i.name: i.impact_ms for i in report.items}
    assert by["Updater"] == 4000      # 3000 + 1000 summed, matched by basename
    assert by["LazySvc"] == 1500      # matched by display name
    assert by["Quiet"] is None
    assert report.measured is True


def test_ranked_measured_first_then_by_cost():
    items = [
        startup.StartupItem("a", "a", "app", "s", impact_ms=None),
        startup.StartupItem("b", "b", "app", "s", impact_ms=500),
        startup.StartupItem("c", "c", "app", "s", impact_ms=4000),
    ]
    order = [i.name for i in startup.StartupReport(items=items).ranked()]
    assert order == ["c", "b", "a"]


def test_collect_merges_live_items(monkeypatch):
    # No boot log here (non-Windows); collect still lists what starts.
    monkeypatch.setattr(startup, "_boot_costs", lambda: ([], None))
    monkeypatch.setattr(startup, "_items_from_autoruns_services",
                        lambda: [startup.StartupItem("X", "x.exe", "app", "Run")])
    report = startup.collect()
    assert [i.name for i in report.items] == ["X"]
    assert report.measured is False and report.items[0].impact == startup.NONE


def test_startup_tab_populates(qtbot):
    from aetheris.ui.tabs.startup_tab import StartupTab

    tab = StartupTab()
    qtbot.addWidget(tab)
    qtbot.waitUntil(lambda: tab._worker is None or not tab._worker.isRunning(),
                    timeout=5000)
    report = startup.StartupReport(
        items=[startup.StartupItem("Heavy", "h.exe", "app", "Run", impact_ms=5000),
               startup.StartupItem("Light", "l.exe", "service", "service (auto)")],
        last_boot_ms=30000, measured=True)
    tab._populate(report)
    assert tab.table.rowCount() == 2
    assert tab.table.item(0, 2).text() == "Heavy"   # measured, ranked first
    assert tab.table.item(0, 1).text() == "5.0 s"
    assert "last boot 30 s" in tab.summary.text()
