"""NTFS MFT parsing primitives: run-list decode, fixups, tree aggregation."""
import struct

from aetheris.storage import mft


def test_parse_run_list_single_extent():
    # header 0x21: len field = 1 byte, offset field = 2 bytes.
    buf = bytes([0x21, 0x08, 0x34, 0x00, 0x00])
    assert mft._parse_run_list(buf, 0, 4096) == [(0x34 * 4096, 8 * 4096)]


def test_parse_run_list_multi_with_sparse():
    # run1: len4 @lcn2 ; run2 sparse (offset field absent, skipped) ;
    # run3: len2 @lcn 2+5=7 ; terminator.
    buf = bytes([0x11, 0x04, 0x02, 0x01, 0x08, 0x11, 0x02, 0x05, 0x00])
    assert mft._parse_run_list(buf, 0, 1000) == [(2000, 4000), (7000, 2000)]


def _make_record(bps=512, usn=b"\x01\x00", tail1=b"\x01\x00", tail2=b"\x01\x00"):
    rec = bytearray(2 * bps)
    rec[0:4] = b"FILE"
    struct.pack_into("<H", rec, 0x04, 48)   # update-sequence array offset
    struct.pack_into("<H", rec, 0x06, 3)    # USA count (1 USN + 2 fixups)
    rec[48:50] = usn
    rec[50:52] = b"\xAA\xBB"                 # fixup for sector 1
    rec[52:54] = b"\xCC\xDD"                 # fixup for sector 2
    rec[bps - 2:bps] = tail1
    rec[2 * bps - 2:2 * bps] = tail2
    return rec


def test_apply_fixups_success_restores_sector_tails():
    rec = _make_record()
    assert mft._apply_fixups(rec, 512) is True
    assert bytes(rec[510:512]) == b"\xAA\xBB"
    assert bytes(rec[1022:1024]) == b"\xCC\xDD"


def test_apply_fixups_detects_torn_write():
    rec = _make_record(tail2=b"\x99\x99")   # sector-2 tail != USN
    assert mft._apply_fixups(rec, 512) is False


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
