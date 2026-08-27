"""Registry snapshot persistence + structured diff rows (pure logic)."""
from aetheris.core import registry


def test_snapshot_save_load_roundtrip(tmp_path):
    tree = {"HKCU\\A": {"x": ("data", 1), "": ("default", 1)}}
    p = tmp_path / "snap.json"
    ok, _ = registry.save_snapshot(tree, str(p))
    assert ok and p.is_file()
    loaded = registry.load_snapshot(str(p))
    assert loaded["HKCU\\A"]["x"] == ["data", 1]      # JSON tuples -> lists


def test_diff_normalizes_loaded_lists(tmp_path):
    before = {"HKCU\\A": {"x": ("1", 1)}}
    p = tmp_path / "snap.json"
    registry.save_snapshot(before, str(p))
    loaded = registry.load_snapshot(str(p))           # x -> ["1", 1]
    after = {"HKCU\\A": {"x": ("2", 1)}}
    d = registry.diff_trees(loaded, after)
    # tuple(before) vs list(loaded) must not create spurious add/remove
    assert any("x" in k for k in d.modified)
    assert not d.added and not d.removed


def test_regdiff_rows_are_categorized_and_sorted():
    before = {"K": {"a": ("1", 1), "b": ("2", 1)}}
    after = {"K": {"a": ("9", 1), "c": ("3", 1)}}
    rows = registry.diff_trees(before, after).rows()
    kinds = {r[0] for r in rows}
    assert kinds == {"Added", "Modified", "Removed"}
    modified = [r for r in rows if r[0] == "Modified"][0]
    assert "a" in modified[1] and modified[2] and modified[3]  # key, before, after


def test_history_save_list_load_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(registry, "history_dir", lambda: tmp_path)
    tree = {"HKCU\\A": {"x": ("1", 1)}}
    e = registry.save_to_history("HKCU", "A", tree, label="pre-install")
    assert e.keys == 1 and e.root == "HKCU" and e.label == "pre-install"

    entries = registry.list_history()
    assert len(entries) == 1 and entries[0].subkey == "A"
    assert "pre-install" in entries[0].display()

    loaded = registry.load_history(entries[0].path)
    assert loaded == {"HKCU\\A": {"x": ["1", 1]}}   # JSON tuples -> lists
    # …and a diff against it works despite the tuple/list difference
    d = registry.diff_trees(loaded, {"HKCU\\A": {"x": ("2", 1)}})
    assert d.modified and not d.added and not d.removed
