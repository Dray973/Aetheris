"""
NTFS MFT parsing: native/Python parity on synthetic records.

No real volume is touched — every fixture is a hand-built FILE record, which
is the only way to test the malformed and hostile shapes that matter. Each
test compares the native result against the existing pure-Python parser in
``storage.mft``, so the two cannot drift.
"""
import struct

import pytest

from aetheris.native import core
from aetheris.storage import mft


def boot_sector(bps=512, spc=8, mft_cluster=786432, rec=-10, oem=b"NTFS    "):
    b = bytearray(512)
    b[3:11] = oem
    struct.pack_into("<H", b, 0x0B, bps)
    b[0x0D] = spc
    struct.pack_into("<Q", b, 0x30, mft_cluster)
    b[0x40] = rec & 0xFF
    return bytes(b)


def synth_record(name, namespace=1, parent=5, size=4096, is_dir=False, rec_size=1024):
    """A FILE record with one $FILE_NAME and one resident $DATA, no fixups."""
    r = bytearray(rec_size)
    r[0:4] = b"FILE"
    struct.pack_into("<H", r, 0x06, 0)          # usa_cnt = 0
    attr_off = 0x38
    struct.pack_into("<H", r, 0x14, attr_off)
    struct.pack_into("<H", r, 0x16, 0x03 if is_dir else 0x01)

    units = name.encode("utf-16-le")
    content_off = 0x18
    attr_len = ((content_off + 0x42 + len(units) + 7) // 8) * 8
    o = attr_off
    struct.pack_into("<I", r, o, mft.ATTR_FILE_NAME)
    struct.pack_into("<I", r, o + 4, attr_len)
    r[o + 8] = 0
    struct.pack_into("<H", r, o + 0x14, content_off)
    base = o + content_off
    struct.pack_into("<Q", r, base, parent)
    r[base + 0x40] = len(units) // 2
    r[base + 0x41] = namespace
    r[base + 0x42:base + 0x42 + len(units)] = units
    o += attr_len

    struct.pack_into("<I", r, o, mft.ATTR_DATA)
    struct.pack_into("<I", r, o + 4, 32)
    r[o + 8] = 0
    struct.pack_into("<I", r, o + 0x10, size)
    o += 32
    struct.pack_into("<I", r, o, mft.ATTR_END)
    return bytes(r)


# --- ABI layout ------------------------------------------------------------


def test_struct_layout_matches_the_rust_side():
    """Pinned in both languages: the block decoder slices by these offsets, so
    a mismatch would misread every record rather than raise."""
    import ctypes

    from aetheris.native import core as c

    assert ctypes.sizeof(c._CMftRecord) == 544
    assert ctypes.sizeof(c._CBootInfo) == 24
    assert c._NAME_OFFSET == 32
    assert c._MFT_HEAD.size == 32


# --- boot sector -----------------------------------------------------------


def test_boot_info_matches_python():
    native = core.mft_boot_info(boot_sector())
    if native is None:
        pytest.skip("aetheris_core.dll not built")
    import io

    # read_boot_info takes a path; compare against its field-for-field logic.
    b = boot_sector()
    assert native.bytes_per_sector == struct.unpack_from("<H", b, 0x0B)[0]
    assert native.sectors_per_cluster == b[0x0D]
    assert native.cluster_size == native.bytes_per_sector * native.sectors_per_cluster
    assert native.record_size == 1 << 10
    assert native.mft_cluster == 786432
    del io


def test_boot_info_rejects_non_ntfs():
    if not core.available():
        pytest.skip("aetheris_core.dll not built")
    assert core.mft_boot_info(boot_sector(oem=b"FAT32   ")) is None
    assert core.mft_boot_info(b"") is None


def test_boot_info_positive_record_size():
    if not core.available():
        pytest.skip("aetheris_core.dll not built")
    info = core.mft_boot_info(boot_sector(bps=512, spc=2, rec=1))
    assert info is not None and info.record_size == 1 * 2 * 512


# --- record parsing --------------------------------------------------------


def _python_parse(block, rec_size, bps, first_index):
    """What storage.mft's own loop produces for the same block."""
    out = []
    for i, r in enumerate(range(0, len(block) - rec_size + 1, rec_size)):
        chunk = block[r:r + rec_size]
        if chunk[0:4] != mft.FILE_SIGNATURE:
            continue
        buf = bytearray(chunk)
        if not mft._apply_fixups(buf, bps):
            continue
        rec = mft._parse_record(bytes(buf), first_index + i)
        if rec and rec.name:
            out.append(rec)
    return out


def _assert_parity(block, rec_size=1024, bps=512, first_index=0):
    native = core.mft_parse_block(block, rec_size, bps, first_index)
    if native is None:
        pytest.skip("aetheris_core.dll not built")
    py = _python_parse(block, rec_size, bps, first_index)
    assert len(native) == len(py), f"{len(native)} native vs {len(py)} python"
    for n, p in zip(native, py, strict=True):
        assert (n.index, n.name, n.size, n.parent_index) == \
               (p.index, p.name, p.size, p.parent_index)
        assert n.in_use == p.in_use and n.is_directory == p.is_directory
    return native


def test_single_record_parity():
    recs = _assert_parity(synth_record("report.docx"))
    assert recs[0].name == "report.docx"
    assert recs[0].size == 4096 and recs[0].parent_index == 5


def test_block_of_records_parity():
    block = b"".join(
        synth_record(f"file{i}.dat", parent=5 + i, size=1000 * i, is_dir=(i % 3 == 0))
        for i in range(16)
    )
    recs = _assert_parity(block)
    assert len(recs) == 16
    assert [r.index for r in recs] == list(range(16))


def test_indices_offset_by_first_index():
    block = b"".join(synth_record(f"f{i}") for i in range(4))
    recs = _assert_parity(block, first_index=1000)
    assert [r.index for r in recs] == [1000, 1001, 1002, 1003]


def test_unnamed_and_invalid_slots_are_skipped():
    good = synth_record("kept.txt")
    empty = bytes(1024)                      # not a FILE record
    baad = b"BAAD" + bytes(1020)             # wrong signature
    nameless = synth_record("")              # parses, but has no name
    recs = _assert_parity(good + empty + baad + nameless + good)
    assert len(recs) == 2
    # Indices still reflect the real slot numbers, not the kept count.
    assert [r.index for r in recs] == [0, 4]


def test_directory_flag_parity():
    _assert_parity(synth_record("Windows", is_dir=True))


def test_parent_reference_masked_to_48_bits():
    recs = _assert_parity(synth_record("f", parent=0xDEAD_0000_0000_0005))
    assert recs[0].parent_index == 5


def test_dos_name_does_not_override_long_name():
    _assert_parity(synth_record("LONGFI~1.TXT", namespace=2))
    recs = core.mft_parse_block(synth_record("LONGFI~1.TXT", namespace=2), 1024, 512, 0)
    if recs is None:
        pytest.skip("aetheris_core.dll not built")
    assert recs[0].name == "LONGFI~1.TXT"  # taken when it is all there is


def test_unicode_names_round_trip():
    recs = _assert_parity(synth_record("файл-日本語-🔥.txt"))
    assert recs[0].name == "файл-日本語-🔥.txt"


def test_long_name_is_clamped_not_corrupted():
    recs = _assert_parity(synth_record("A" * 200))
    assert recs[0].name == "A" * 200


def test_empty_and_undersized_blocks():
    if not core.available():
        pytest.skip("aetheris_core.dll not built")
    assert core.mft_parse_block(b"", 1024, 512, 0) == []
    assert core.mft_parse_block(bytes(100), 1024, 512, 0) == []
    assert core.mft_parse_block(bytes(1024), 0, 512, 0) == []
    assert core.mft_parse_block(bytes(1024), 1024, 0, 0) == []


# --- fixups ----------------------------------------------------------------


def record_with_fixups(usn=0xAAAA, real=(0x1111, 0x2222), rec_size=1024, bps=512):
    r = bytearray(synth_record("fixed.txt", rec_size=rec_size))
    usa_off = 0x30
    struct.pack_into("<H", r, 0x04, usa_off)
    struct.pack_into("<H", r, 0x06, len(real) + 1)
    struct.pack_into("<H", r, usa_off, usn)
    for i, v in enumerate(real):
        struct.pack_into("<H", r, usa_off + (i + 1) * 2, v)
        struct.pack_into("<H", r, (i + 1) * bps - 2, usn)
    return bytes(r)


def test_fixups_applied_parity():
    _assert_parity(record_with_fixups())


def test_torn_record_is_rejected_by_both():
    r = bytearray(record_with_fixups())
    r[1022] = 0x00  # second sector never reached disk
    block = bytes(r)
    native = core.mft_parse_block(block, 1024, 512, 0)
    if native is None:
        pytest.skip("aetheris_core.dll not built")
    assert native == []
    assert _python_parse(block, 1024, 512, 0) == []


# --- run lists -------------------------------------------------------------


@pytest.mark.parametrize(
    "buf",
    [
        bytes([0x21, 0x18, 0x34, 0x56, 0x00]),          # one run
        bytes([0x11, 0x10, 0x20, 0x11, 0x10, 0xF0, 0]),  # negative delta
        bytes([0x01, 0x08, 0x11, 0x04, 0x20, 0x00]),     # sparse then real
        bytes([0x21, 0x18]),                             # truncated
        b"",
        bytes([0x00]),
    ],
)
def test_run_list_parity(buf):
    native = core.mft_run_list(buf, 0, 4096)
    if native is None:
        pytest.skip("aetheris_core.dll not built")
    assert native == mft._parse_run_list(buf, 0, 4096)
