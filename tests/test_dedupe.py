"""SHA-256 duplicate detection and ghost (empty-dir) scanning."""
from aetheris.storage import dedupe


def test_find_duplicates_groups_identical_files(tmp_path):
    payload = b"hello world " * 200
    (tmp_path / "a.txt").write_bytes(payload)
    (tmp_path / "b.txt").write_bytes(payload)
    (tmp_path / "c.txt").write_bytes(b"unique content")
    groups = dedupe.find_duplicates([str(tmp_path)])
    assert len(groups) == 1
    assert sorted(p.rsplit("\\", 1)[-1].rsplit("/", 1)[-1] for p in groups[0].paths) \
        == ["a.txt", "b.txt"]
    assert groups[0].wasted_bytes == len(payload)


def test_size_unique_files_are_not_hashed_as_dupes(tmp_path):
    (tmp_path / "a.txt").write_bytes(b"x" * 10)
    (tmp_path / "b.txt").write_bytes(b"y" * 20)
    assert dedupe.find_duplicates([str(tmp_path)]) == []


def test_find_ghosts_flags_empty_dirs(tmp_path):
    (tmp_path / "empty").mkdir()
    ghosts = dedupe.find_ghosts([str(tmp_path)])
    assert any(g.kind == "empty-dir" for g in ghosts)
