"""
Native registry subtree snapshot: exact parity with the winreg walk.

Parity here is not a nicety. Snapshots are written to disk and later diffed
against ones taken on another run — possibly through the other code path — so
any difference in how a value renders shows up as a phantom "modified" row in
a registry differential report. The value-decoding rules below were each found
by diffing ~180k real values against winreg, and every one of them is a case
the obvious implementation gets wrong.
"""
import sys

import pytest

from aetheris.core import registry
from aetheris.native import win

pytestmark = pytest.mark.skipif(
    not win.available() or sys.platform != "win32",
    reason="aetheris_win.dll not built, or not Windows",
)

# Small, present on every Windows box, and cheap to walk twice.
CASES = [
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer", 3),
    ("HKLM", r"SYSTEM\CurrentControlSet\Services\Dnscache", 2),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", 1),
]


def _both(monkeypatch, root, sub, depth):
    native = registry.snapshot_tree(root, sub, max_depth=depth)
    monkeypatch.setattr(win, "reg_snapshot", lambda *a, **k: None)
    fallback = registry.snapshot_tree(root, sub, max_depth=depth)
    return native, fallback


@pytest.mark.parametrize("root,sub,depth", CASES)
def test_snapshot_matches_winreg_exactly(monkeypatch, root, sub, depth):
    native, fallback = _both(monkeypatch, root, sub, depth)
    assert set(native) == set(fallback), "key sets differ"
    for key in native:
        assert set(native[key]) == set(fallback[key]), f"value names differ at {key}"
        for name in native[key]:
            assert native[key][name] == fallback[key][name], f"{key}::{name}"


def test_depth_limit_is_honoured():
    shallow = registry.snapshot_tree("HKCU", r"Software\Microsoft", max_depth=1)
    deep = registry.snapshot_tree("HKCU", r"Software\Microsoft", max_depth=3)
    assert len(deep) > len(shallow)


def test_unknown_root_still_raises():
    """The native path must not swallow the error the Python path raises."""
    with pytest.raises(ValueError):
        registry.snapshot_tree("HKNOPE", "Software")


def test_missing_subkey_yields_nothing():
    assert registry.snapshot_tree("HKCU", r"Software\NoSuchKey_Aetheris") == {}


def test_hive_names_map_to_the_engine():
    assert set(win.HIVES) == {"HKCR", "HKCU", "HKLM", "HKU"}
    assert win.reg_snapshot("HKNOPE", "Software") is None


# --- value decoding: the rules that cost real divergences ------------------


def test_empty_string_value_is_empty_not_none():
    """REG_SZ with no data is '', while other types are None."""
    assert win._reg_value(b"", 1) == ""
    assert win._reg_value(b"", 2) == ""
    assert win._reg_value(b"", 0) is None
    assert win._reg_value(b"", 3) is None
    assert win._reg_value(b"", 7) is None


def test_string_truncates_at_the_first_nul():
    """Values written with a wrong length carry junk past their terminator."""
    raw = "name\x00 ".encode("utf-16-le")
    assert win._reg_value(raw, 1) == "name"
    padded = ("id" + "\x00" * 8).encode("utf-16-le")
    assert win._reg_value(padded, 1) == "id"


def test_odd_length_buffer_does_not_leave_a_replacement_char():
    raw = "abc".encode("utf-16-le") + b"\x7f"   # stray trailing byte
    assert win._reg_value(raw, 1) == "abc"
    assert "�" not in win._reg_value(raw, 1)


def test_multi_sz_drops_exactly_one_terminator():
    one = "a\x00\x00".encode("utf-16-le")
    assert win._reg_value(one, 7) == ["a"]
    two = "a\x00b\x00\x00".encode("utf-16-le")
    assert win._reg_value(two, 7) == ["a", "b"]


def test_multi_sz_keeps_a_single_empty_string():
    """The case that makes 'strip all trailing empties' wrong."""
    assert win._reg_value("\x00\x00".encode("utf-16-le"), 7) == [""]


def test_multi_sz_keeps_interior_empties():
    raw = "a\x00\x00b\x00\x00".encode("utf-16-le")
    assert win._reg_value(raw, 7) == ["a", "", "b"]


def test_numeric_types():
    assert win._reg_value((1234).to_bytes(4, "little"), 4) == 1234
    assert win._reg_value((1234).to_bytes(4, "big"), 5) == 1234
    assert win._reg_value((2**40).to_bytes(8, "little"), 11) == 2**40


def test_binary_passes_through():
    assert win._reg_value(b"\x00\x01\xff", 3) == b"\x00\x01\xff"
