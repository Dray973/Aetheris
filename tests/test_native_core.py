"""
Rust analysis core: native/Python parity across the whole surface.

Every function in ``aetheris.native.core`` has a pure-Python fallback, and the
suite must behave identically either way. Each test here runs the function
twice — once as configured, once with the library forced off — and asserts the
two agree. When the DLL isn't built both runs take the same path and the tests
still pass, which is exactly the "no hard dependency" guarantee.
"""
import hashlib
import os

import pytest

from aetheris.native import core


@pytest.fixture
def forced_fallback(monkeypatch):
    """Force the pure-Python path regardless of what is installed."""
    monkeypatch.setattr(core, "_load", lambda: None)
    return core


def both_paths(monkeypatch, fn, *args, **kwargs):
    """Run ``fn`` natively (if available) and on the fallback; return both."""
    native = fn(*args, **kwargs)
    monkeypatch.setattr(core, "_load", lambda: None)
    fallback = fn(*args, **kwargs)
    return native, fallback


# --- entropy ---------------------------------------------------------------


def test_entropy_extremes():
    assert core.entropy(b"") == 0.0
    assert core.entropy(b"\x00" * 512) == 0.0
    assert abs(core.entropy(bytes(range(256))) - 8.0) < 1e-9


def test_entropy_parity(monkeypatch):
    data = os.urandom(8192)
    native, fallback = both_paths(monkeypatch, core.entropy, data)
    assert abs(native - fallback) < 1e-9


def test_max_window_entropy_parity(monkeypatch):
    low = b"A" * 4096
    blob = bytes((i * 211 + 7) & 0xFF for i in range(256))
    data = low + blob + low
    native, fallback = both_paths(monkeypatch, core.max_window_entropy, data, 256)
    assert abs(native - fallback) < 1e-9
    assert native > core.entropy(data) + 1.0


def test_max_window_zero_scores_whole_buffer(monkeypatch):
    data = os.urandom(2048)
    native, fallback = both_paths(monkeypatch, core.max_window_entropy, data, 0)
    assert abs(native - fallback) < 1e-9


# --- search ----------------------------------------------------------------


def test_find_parity(monkeypatch):
    data = b"....MZ\x90\x00....MZ...."
    for needle in (b"MZ", b"MZ\x90", b"zz", b""):
        native, fallback = both_paths(monkeypatch, core.find, data, needle)
        assert native == fallback, needle
    assert core.find(b"ab", b"abcd") == -1


def test_find_all_is_non_overlapping(monkeypatch):
    native, fallback = both_paths(monkeypatch, core.find_all, b"aaaa", b"aa", 10)
    assert native == fallback == [0, 2]


def test_find_all_respects_limit(monkeypatch):
    data = b"MZ" * 50
    native, fallback = both_paths(monkeypatch, core.find_all, data, b"MZ", 5)
    assert native == fallback
    assert len(native) == 5


def test_find_all_rejects_bad_input():
    assert core.find_all(b"abc", b"", 10) == []
    assert core.find_all(b"abc", b"abcd", 10) == []
    assert core.find_all(b"abc", b"a", 0) == []


# --- classification --------------------------------------------------------


@pytest.mark.parametrize(
    "protect,rtype,expected",
    [
        ("rwx", "private", "rwx"),
        ("rwx", "image", "rwx"),
        ("rwxc", "image", "rwx"),
        ("r-x", "private", "unbacked-exec"),
        ("r-x", "mapped", "unbacked-exec"),
        ("r-x", "image", None),
        ("rw-", "private", None),
        ("r--", "image", None),
        ("---", "private", None),
        ("", "private", None),
        ("r-x+guard", "private", "unbacked-exec"),
    ],
)
def test_classify_parity(monkeypatch, protect, rtype, expected):
    native, fallback = both_paths(monkeypatch, core.classify_region, protect, rtype)
    assert native == fallback == expected


def test_promote_parity(monkeypatch):
    for kind, head in [
        ("unbacked-exec", b"MZ\x90\x00"),
        ("unbacked-exec", b"ZM"),
        ("unbacked-exec", b"M"),
        ("unbacked-exec", b""),
        ("rwx", b"MZ"),
    ]:
        native, fallback = both_paths(monkeypatch, core.promote_kind, kind, head)
        assert native == fallback, (kind, head)
    assert core.promote_kind("unbacked-exec", b"MZ") == "private-pe"
    assert core.promote_kind(None, b"MZ") is None


def test_kind_scores_match_injection_table(monkeypatch):
    from aetheris.forensics.injection import SCORE

    for kind, score in SCORE.items():
        native, fallback = both_paths(monkeypatch, core.kind_score, kind)
        assert native == fallback == score
    assert core.kind_score(None) == 0


# --- PE --------------------------------------------------------------------


def synth_pe(sections=(("`.text", 0x6000_0020),), pe32=False):
    """A minimal but structurally valid PE. Mirrors the Rust crate's fixture."""
    import struct

    nt, size_opt = 0x80, 240
    b = bytearray(nt + 24 + size_opt + len(sections) * 40)
    b[0:2] = b"MZ"
    struct.pack_into("<I", b, 0x3C, nt)
    struct.pack_into("<I", b, nt, 0x0000_4550)
    struct.pack_into("<H", b, nt + 4, 0x014C if pe32 else 0x8664)
    struct.pack_into("<H", b, nt + 6, len(sections))
    struct.pack_into("<I", b, nt + 8, 0x6642_1337)
    struct.pack_into("<H", b, nt + 20, size_opt)
    struct.pack_into("<H", b, nt + 22, 0x0022)
    opt = nt + 24
    struct.pack_into("<H", b, opt, 0x010B if pe32 else 0x020B)
    struct.pack_into("<I", b, opt + 16, 0x1000)
    if pe32:
        struct.pack_into("<I", b, opt + 28, 0x0040_0000)
    else:
        struct.pack_into("<Q", b, opt + 24, 0x1_4000_0000)
    struct.pack_into("<I", b, opt + 56, 0x2_0000)
    struct.pack_into("<H", b, opt + 68, 2)
    struct.pack_into("<H", b, opt + 70, 0x0160)
    so = opt + size_opt
    for name, chars in sections:
        nb = name.encode()[:8]
        b[so:so + len(nb)] = nb
        struct.pack_into("<I", b, so + 8, 0x1000)
        struct.pack_into("<I", b, so + 12, 0x1000)
        struct.pack_into("<I", b, so + 16, 0x200)
        struct.pack_into("<I", b, so + 20, 0x400)
        struct.pack_into("<I", b, so + 36, chars)
        so += 40
    return bytes(b)


def test_pe_parse_parity(monkeypatch):
    data = synth_pe()
    native, fallback = both_paths(monkeypatch, core.pe_parse, data)
    assert native == fallback
    assert native is not None
    assert native.is_64 and native.machine == 0x8664
    assert native.entry_point == 0x1000
    assert native.image_base == 0x1_4000_0000
    assert native.size_of_image == 0x2_0000
    assert native.timestamp == 0x6642_1337


def test_pe32_image_base_offset_parity(monkeypatch):
    """PE32 keeps ImageBase at +28; PE32+ widens it and moves it to +24."""
    data = synth_pe(pe32=True)
    native, fallback = both_paths(monkeypatch, core.pe_parse, data)
    assert native == fallback
    assert native is not None and not native.is_64
    assert native.image_base == 0x0040_0000


def test_pe_sections_parity(monkeypatch):
    data = synth_pe(sections=((".text", 0x6000_0020), (".data", 0xC000_0040)))
    native, fallback = both_paths(monkeypatch, core.pe_sections, data)
    assert native == fallback
    assert [s.name for s in native] == [".text", ".data"]
    assert native[0].is_executable and not native[0].is_writable
    assert native[1].is_writable and not native[1].is_executable


def test_pe_rejects_junk_and_truncation(monkeypatch):
    for data in (b"", b"MZ", bytes(512), synth_pe()[:0x60]):
        native, fallback = both_paths(monkeypatch, core.pe_is_valid, data)
        assert native == fallback is False, data[:4]


def test_pe_rejects_wild_e_lfanew(monkeypatch):
    import struct

    b = bytearray(4096)
    b[0:2] = b"MZ"
    struct.pack_into("<I", b, 0x3C, 0xDEAD_BEEF)
    native, fallback = both_paths(monkeypatch, core.pe_is_valid, bytes(b))
    assert native == fallback is False


def test_pe_carve_parity(monkeypatch):
    pe = synth_pe()
    buf = bytearray(4096 * 4)
    buf[0:len(pe)] = pe
    buf[8192:8192 + len(pe)] = pe
    buf[4096:4098] = b"MZ"                    # bare MZ, no NT headers
    buf[5000:5000 + len(pe)] = pe             # real, but unaligned
    native, fallback = both_paths(monkeypatch, core.pe_carve, bytes(buf), 4096, 32)
    assert native == fallback == [0, 8192]


def test_carve_aligned_parity(monkeypatch):
    buf = bytearray(4096 * 3)
    buf[0:4] = b"Proc"
    buf[4096:4100] = b"Proc"
    buf[5000:5004] = b"Proc"                  # unaligned — must be skipped
    native, fallback = both_paths(monkeypatch, core.carve_aligned, bytes(buf), b"Proc", 4096, 16)
    assert native == fallback == [0, 4096]


# --- hashing ---------------------------------------------------------------


def test_sha256_matches_hashlib(monkeypatch):
    for data in (b"", b"abc", os.urandom(100_000)):
        native, fallback = both_paths(monkeypatch, core.sha256, data)
        assert native == fallback == hashlib.sha256(data).digest()


def test_sha256_block_boundaries(monkeypatch):
    """Padding is where a hand-rolled SHA-256 goes wrong; walk the boundary."""
    for n in (55, 56, 57, 63, 64, 65, 119, 120, 128):
        data = bytes(range(256)) * 4
        data = data[:n]
        native, fallback = both_paths(monkeypatch, core.sha256, data)
        assert native == fallback == hashlib.sha256(data).digest(), n


# --- availability ----------------------------------------------------------


def test_fallback_path_is_fully_functional(forced_fallback):
    """With the library forced off the whole surface still works."""
    assert not core.available()
    assert core.entropy(b"\x00" * 64) == 0.0
    assert core.find(b"abcMZ", b"MZ") == 3
    assert core.classify_region("rwx", "private") == "rwx"
    assert core.pe_is_valid(synth_pe())
    assert core.sha256(b"abc") == hashlib.sha256(b"abc").digest()
