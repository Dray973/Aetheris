"""Persistent settings store — defaults, round-trip, resilience."""
from aetheris.core.settings import DEFAULTS, Settings


def test_defaults_returned_for_unset(tmp_path):
    s = Settings(tmp_path / "settings.json")
    assert s.get("mft_max_records") == DEFAULTS["mft_max_records"]
    assert s.get("does_not_exist", "fallback") == "fallback"


def test_set_save_load_roundtrip(tmp_path):
    p = tmp_path / "settings.json"
    s = Settings(p)
    s.set("active_tab", 3)
    s.set("network_resolve_dns", True)
    assert s.save()
    assert p.is_file()

    s2 = Settings(p)                       # fresh instance reads from disk
    assert s2.get("active_tab") == 3
    assert s2.get("network_resolve_dns") is True
    # unset keys still fall back to defaults
    assert s2.get("log_min_level") == DEFAULTS["log_min_level"]


def test_corrupt_file_falls_back_to_defaults(tmp_path):
    p = tmp_path / "settings.json"
    p.write_text("{ this is not json", encoding="utf-8")
    s = Settings(p)
    assert s.get("active_tab") == DEFAULTS["active_tab"]


def test_missing_file_is_harmless(tmp_path):
    s = Settings(tmp_path / "nope" / "settings.json")
    assert s.get("mft_volume") == DEFAULTS["mft_volume"]
