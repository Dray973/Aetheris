"""Software inventory: row parsing, dedupe, diff, persistence, the tab."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from aetheris.core import inventory as inv  # noqa: E402
from aetheris.core.inventory import InstalledApp  # noqa: E402


def test_parse_row_builds_an_app():
    app = inv.parse_row({"DisplayName": "Acme Reader", "DisplayVersion": "2.1",
                         "Publisher": "Acme", "InstallDate": "20260514",
                         "InstallLocation": r"C:\Acme"}, "HKLM")
    assert app is not None
    assert (app.name, app.version, app.publisher) == ("Acme Reader", "2.1", "Acme")
    assert app.pretty_date() == "2026-05-14"


def test_parse_row_filters_non_apps():
    assert inv.parse_row({}, "HKLM") is None                              # no name
    assert inv.parse_row({"DisplayName": "X", "SystemComponent": 1}, "HKLM") is None
    assert inv.parse_row({"DisplayName": "Patch", "WindowsInstaller": 1}, "HKLM") is None
    assert inv.parse_row({"DisplayName": "Sub", "ParentKeyName": "Big"}, "HKLM") is None
    # A WindowsInstaller entry that *does* carry a version is a real program.
    assert inv.parse_row({"DisplayName": "Real", "WindowsInstaller": 1,
                          "DisplayVersion": "1.0"}, "HKLM") is not None


def test_dedupe_prefers_versioned_and_collapses_hives():
    apps = [InstalledApp("App", "", "Acme", source="HKLM"),
            InstalledApp("App", "3.0", "Acme", source="HKLM-WOW6432"),
            InstalledApp("Other", "1.0", "Beta")]
    out = inv.dedupe(apps)
    names = {a.name: a.version for a in out}
    assert names == {"App": "3.0", "Other": "1.0"}      # one App, the versioned one
    assert [a.name for a in out] == ["App", "Other"]    # sorted


def test_diff_reports_added_removed_changed():
    old = [InstalledApp("Keep", "1.0", "P"), InstalledApp("Gone", "2.0", "P"),
           InstalledApp("Bump", "1.0", "P")]
    new = [InstalledApp("Keep", "1.0", "P"), InstalledApp("Bump", "1.1", "P"),
           InstalledApp("Fresh", "1.0", "P")]
    changes = {(c.kind, c.app.name): c for c in inv.diff(old, new)}
    assert set(changes) == {("added", "Fresh"), ("removed", "Gone"), ("changed", "Bump")}
    assert changes[("changed", "Bump")].old_version == "1.0"


def test_save_load_round_trip(tmp_path):
    apps = [InstalledApp("A", "1.0", "P", signature="signed"),
            InstalledApp("B", "2.0", "Q")]
    p = tmp_path / "snap.json"
    inv.save(apps, p)
    loaded = inv.load(p)
    assert loaded == apps
    assert not list(tmp_path.glob("*.tmp"))


def test_load_missing_or_corrupt_is_empty(tmp_path):
    assert inv.load(tmp_path / "nope.json") == []
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert inv.load(bad) == []


def test_collect_is_empty_off_windows():
    import sys
    if sys.platform != "win32":
        assert inv.collect() == []


def test_inventory_tab_shows_changes(qtbot, tmp_path, monkeypatch):
    from aetheris.ui.tabs.inventory_tab import InventoryTab

    snap = tmp_path / "snap.json"
    monkeypatch.setattr(inv, "default_path", lambda: snap)
    inv.save([InstalledApp("Keep", "1.0", "P"), InstalledApp("Gone", "2.0", "P")], snap)

    tab = InventoryTab()
    qtbot.addWidget(tab)
    qtbot.waitUntil(lambda: tab._worker is None or not tab._worker.isRunning(),
                    timeout=5000)
    tab._loaded([InstalledApp("Keep", "1.0", "P"), InstalledApp("New", "1.0", "P")])
    assert "1 added" in tab.changes_label.text() and "1 removed" in tab.changes_label.text()
    # The table lists current apps (2), with the added one badged.
    assert tab.table.rowCount() == 2
    tab.filter.setText("new")
    assert tab.table.rowCount() == 1 and tab.table.item(0, 0).text() == "ADD"
