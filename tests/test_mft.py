"""NTFS MFT parsing primitives: run-list decode, fixups, tree aggregation."""
import io
import struct

from aetheris.storage import mft


def test_parse_run_list_single_extent():
    buf = bytes([0x21, 0x08, 0x34, 0x00, 0x00])
    assert mft._parse_run_list(buf, 0, 4096) == [(0x34 * 4096, 8 * 4096)]


def test_parse_run_list_multi_with_sparse():
    buf = bytes([0x11, 0x04, 0x02, 0x01, 0x08, 0x11, 0x02, 0x05, 0x00])
    assert mft._parse_run_list(buf, 0, 1000) == [(2000, 4000), (7000, 2000)]


def _make_record(bps=512, usn=b"\x01\x00", tail1=b"\x01\x00", tail2=b"\x01\x00"):
    rec = bytearray(2 * bps)
    rec[0:4] = b"FILE"
    struct.pack_into("<H", rec, 0x04, 48)
    struct.pack_into("<H", rec, 0x06, 3)
    rec[48:50] = usn
    rec[50:52] = b"\xAA\xBB"
    rec[52:54] = b"\xCC\xDD"
    rec[bps - 2:bps] = tail1
    rec[2 * bps - 2:2 * bps] = tail2
    return rec


def test_apply_fixups_success_restores_sector_tails():
    rec = _make_record()
    assert mft._apply_fixups(rec, 512) is True
    assert bytes(rec[510:512]) == b"\xAA\xBB"
    assert bytes(rec[1022:1024]) == b"\xCC\xDD"


def test_apply_fixups_detects_torn_write():
    rec = _make_record(tail2=b"\x99\x99")
    assert mft._apply_fixups(rec, 512) is False


def _synthetic_mft_record0(bps=512, record_size=1024):
    """Build a valid $MFT record 0 whose non-resident $DATA attribute carries a
    *fragmented* (two-extent) run-list, so _mft_extents must decode fixups, walk
    the attributes, and follow the mapping pairs -- the headline "fragmented MFT
    walk" end to end (no raw disk needed)."""
    rec = bytearray(record_size)
    rec[0:4] = b"FILE"
    struct.pack_into("<H", rec, 0x04, 0x30)
    struct.pack_into("<H", rec, 0x06, 3)
    struct.pack_into("<H", rec, 0x14, 0x38)
    usn = b"\x2a\x00"
    rec[0x30:0x32] = usn
    rec[0x32:0x34] = b"\xde\xad"
    rec[0x34:0x36] = b"\xbe\xef"
    rec[bps - 2:bps] = usn
    rec[2 * bps - 2:2 * bps] = usn

    off = 0x38
    struct.pack_into("<I", rec, off + 0x00, mft.ATTR_DATA)
    struct.pack_into("<I", rec, off + 0x04, 0x48)
    rec[off + 0x08] = 1
    struct.pack_into("<H", rec, off + 0x20, 0x40)
    runs = bytes([0x11, 0x04, 0x02, 0x11, 0x02, 0x03, 0x00])
    rec[off + 0x40:off + 0x40 + len(runs)] = runs
    struct.pack_into("<I", rec, off + 0x48, mft.ATTR_END)
    return bytes(rec)


def test_mft_extents_follows_fragmented_data_run():
    boot = mft.BootInfo(bytes_per_sector=512, sectors_per_cluster=8,
                        cluster_size=4096, mft_cluster=0, record_size=1024)
    fh = io.BytesIO(_synthetic_mft_record0())
    extents = mft._mft_extents(fh, boot)
    assert extents == [(2 * 4096, 4 * 4096), (5 * 4096, 2 * 4096)]
    assert len(extents) == 2


def test_build_tree_aggregates_sizes():
    R = mft.MftRecord
    recs = [
        R(5, True, True, "\\", 0, 5),
        R(10, True, True, "Dir", 0, 5),
        R(11, True, False, "a.bin", 100, 10),
        R(12, True, False, "b.bin", 250, 10),
    ]
    root = mft.build_tree(recs)
    assert root.total_size == 350
    dir_node = next(c for c in root.children if c.name == "Dir")
    assert dir_node.total_size == 350
    assert dir_node.leaf_count == 2


def test_build_tree_preserves_orphans():
    """Records whose parent wasn't in the (bounded) scan must not vanish -- they
    land under a synthetic <orphans> node and still count toward the total."""
    R = mft.MftRecord
    recs = [
        R(5, True, True, "\\", 0, 5),
        R(20, True, False, "lost.bin", 500, 9999),
        R(21, True, True, "LostDir", 0, 9999),
        R(22, True, False, "child.bin", 40, 21),
    ]
    root = mft.build_tree(recs)
    orphans = next((c for c in root.children if c.name == "<orphans>"), None)
    assert orphans is not None, "orphaned records were silently dropped"
    names = {c.name for c in orphans.children}
    assert {"lost.bin", "LostDir"} <= names
    assert root.total_size == 540
