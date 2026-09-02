"""Native scan helpers: entropy + byte-pattern search, native and fallback."""
import os

import pytest

from aetheris.forensics import nativescan as ns


def test_entropy_extremes():
    assert ns.entropy(b"") == 0.0
    assert ns.entropy(b"\x00" * 512) == 0.0            # all one byte -> 0 bits
    assert abs(ns.entropy(bytes(range(256))) - 8.0) < 1e-9  # every byte once -> 8 bits


def test_entropy_matches_pure_python():
    data = bytes((i * 167 + 13) & 0xFF for i in range(4096))
    assert abs(ns.entropy(data) - ns._py_entropy(data)) < 1e-9


def test_find():
    assert ns.find(b"hello world", b"world") == 6
    assert ns.find(b"abc", b"z") == -1
    assert ns.find(b"abc", b"") == -1              # empty pattern -> -1 (both paths)
    assert ns.find(b"ab", b"abcd") == -1           # pattern longer than data
    mz = b"....MZ\x90\x00...."
    assert ns.find(mz, b"MZ\x90") == 4


def test_max_window_flags_hidden_high_entropy_region():
    low = b"A" * 4096
    blob = bytes((i * 211 + 7) & 0xFF for i in range(256))  # ~8 bits/byte
    data = low + blob + low
    # overall entropy is low, but a single window catches the high-entropy blob
    assert ns.max_window_entropy(data, 256) > ns.entropy(data) + 1.0
    assert ns.max_window_entropy(data, 256) > 7.0


def test_native_parity_when_available():
    if not ns.available():
        pytest.skip("native scan lib not built")
    data = os.urandom(16384)
    assert abs(ns.entropy(data) - ns._py_entropy(data)) < 1e-9
    assert abs(ns.max_window_entropy(data, 512) - ns._py_max_window(data, 512)) < 1e-9
    needle = data[1000:1012]
    assert ns.find(data, needle) == data.find(needle)
