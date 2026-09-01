"""Registry differential engine (pure dict logic; no live registry needed)."""
from aetheris.core.registry import diff_trees


def test_diff_classifies_added_modified_removed():
    before = {"HKCU\\A": {"x": ("1", 1), "y": ("2", 1)}}
    after = {"HKCU\\A": {"x": ("9", 1), "z": ("3", 1)}}
    d = diff_trees(before, after)
    assert any("x" in k for k in d.modified)
    assert any("z" in k for k in d.added)
    assert any("y" in k for k in d.removed)


def test_diff_markdown_sections():
    before = {"HKCU\\A": {"x": ("1", 1)}}
    after = {"HKCU\\A": {"x": ("2", 1)}}
    md = diff_trees(before, after).to_markdown()
    assert "# Registry Differential Report" in md
    assert "Modified" in md


def test_diff_no_change():
    tree = {"HKCU\\A": {"x": ("1", 1)}}
    d = diff_trees(tree, dict(tree))
    assert not (d.added or d.modified or d.removed)
    assert "No changes detected" in d.to_markdown()
