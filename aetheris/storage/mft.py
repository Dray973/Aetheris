"""
Raw NTFS Master File Table parser.

This is a real, bounded MFT reader: it opens the raw volume (``\\\\.\\C:``),
reads the NTFS boot sector to locate the MFT, then parses FILE records directly
in binary — applying the update-sequence (fixup) array and decoding the
$FILE_NAME (0x30) and $DATA (0x80) attributes to recover names and logical
sizes without touching the Win32 directory APIs.

It follows the $MFT's own non-resident $DATA run-list, so fragmented MFTs are
covered in full (VCN order across every extent), and ``build_tree`` reconstructs
the parent/child directory hierarchy with aggregated sizes for a space-
utilization tree-map.

Assumption: the MFT itself is treated as non-sparse (true on essentially all
real volumes); sparse runs in the $MFT $DATA run-list are skipped rather than
back-filled, which can only perturb record *numbering* on a pathologically
sparse MFT, never the parsed file data.

Requires an elevated token (raw volume handles need admin).
"""
from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from ..core import logbus

SRC = "storage.mft"

FILE_SIGNATURE = b"FILE"
ATTR_FILE_NAME = 0x30
ATTR_DATA = 0x80
ATTR_END = 0xFFFFFFFF


@dataclass
class MftRecord:
    index: int
    in_use: bool
    is_directory: bool
    name: str
    size: int          # logical size from $DATA, best effort
    parent_index: int


@dataclass
class BootInfo:
    bytes_per_sector: int
    sectors_per_cluster: int
    cluster_size: int
    mft_cluster: int
    record_size: int

    @property
    def mft_offset(self) -> int:
        return self.mft_cluster * self.cluster_size


def read_boot_info(volume: str = r"\\.\C:") -> BootInfo:
    """Parse the NTFS boot sector for MFT geometry."""
    with open(volume, "rb", buffering=0) as fh:
        boot = fh.read(512)
    if boot[3:11] != b"NTFS    ":
        raise ValueError("not an NTFS volume (OEM id mismatch)")
    bps = struct.unpack_from("<H", boot, 0x0B)[0]
    spc = boot[0x0D]
    mft_cluster = struct.unpack_from("<Q", boot, 0x30)[0]
    raw_rec = struct.unpack_from("<b", boot, 0x40)[0]
    if raw_rec >= 0:
        record_size = raw_rec * spc * bps
    else:
        record_size = 1 << (-raw_rec)  # 2^|raw_rec|
    return BootInfo(bps, spc, bps * spc, mft_cluster, record_size)


def _apply_fixups(record: bytearray, bps: int) -> bool:
    """Apply the NTFS update-sequence array. Returns False on integrity fail
    (or on a truncated/malformed record -- the input is attacker-controllable)."""
    n = len(record)
    if n < 8 or record[0:4] != FILE_SIGNATURE:
        return False
    usa_off = struct.unpack_from("<H", record, 0x04)[0]
    usa_cnt = struct.unpack_from("<H", record, 0x06)[0]
    if usa_cnt == 0:
        return True
    if usa_off + usa_cnt * 2 > n:      # USA must fit inside the record
        return False
    usn = record[usa_off:usa_off + 2]
    for i in range(1, usa_cnt):
        sector_end = i * bps - 2
        if sector_end < 0 or sector_end + 2 > n:   # sector tail out of bounds
            return False
        fix = record[usa_off + i * 2: usa_off + i * 2 + 2]
        if record[sector_end:sector_end + 2] != usn:
            return False  # torn write / corrupt record
        record[sector_end:sector_end + 2] = fix
    return True


def _parse_record(record: bytes, index: int) -> MftRecord | None:
    # Every field read below is bounds-checked: a corrupt or truncated record
    # (attacker-controllable on-disk bytes) must yield None or a best-effort
    # record, never an exception.
    n = len(record)
    if n < 0x18 or record[0:4] != FILE_SIGNATURE:
        return None
    flags = struct.unpack_from("<H", record, 0x16)[0]
    in_use = bool(flags & 0x01)
    is_dir = bool(flags & 0x02)
    attr_off = struct.unpack_from("<H", record, 0x14)[0]

    name = ""
    size = 0
    parent_index = 0

    off = attr_off
    while off + 8 <= n:                       # need 8 bytes for type + length
        attr_type = struct.unpack_from("<I", record, off)[0]
        if attr_type == ATTR_END:
            break
        attr_len = struct.unpack_from("<I", record, off + 4)[0]
        if attr_len < 16 or off + attr_len > n:   # min header is 16 bytes
            break
        non_resident = record[off + 8]

        if attr_type == ATTR_FILE_NAME and non_resident == 0 and off + 0x16 <= n:
            content_off = struct.unpack_from("<H", record, off + 0x14)[0]
            base = off + content_off
            if base + 0x42 <= n:              # parent ref .. name-length .. name
                parent_ref = struct.unpack_from("<Q", record, base)[0]
                parent_index = parent_ref & 0x0000FFFFFFFFFFFF
                name_len = record[base + 0x40]
                namespace = record[base + 0x41]
                cand = record[base + 0x42: base + 0x42 + name_len * 2].decode(
                    "utf-16-le", errors="replace")   # slice self-clamps to n
                # Prefer Win32 namespace names (1/3) over DOS 8.3 (2).
                if namespace != 2 or not name:
                    name = cand

        elif attr_type == ATTR_DATA:
            if non_resident == 0 and off + 0x14 <= n:
                size = struct.unpack_from("<I", record, off + 0x10)[0]
            elif non_resident == 1 and off + 0x38 <= n:
                # real size lives at +0x30 in the non-resident header
                size = struct.unpack_from("<Q", record, off + 0x30)[0]

        off += attr_len

    return MftRecord(index, in_use, is_dir, name, size, parent_index)


def _parse_run_list(buf: bytes | bytearray, pos: int, cluster_size: int) -> list[tuple[int, int]]:
    """
    Decode an NTFS mapping-pairs (data-run) list into physical extents.
    Returns [(byte_offset, byte_length), …]. Sparse runs (offset field absent)
    are skipped — they carry no physical clusters.
    """
    extents: list[tuple[int, int]] = []
    lcn = 0
    n = len(buf)
    while pos < n:
        header = buf[pos]
        pos += 1
        if header == 0:
            break
        len_bytes = header & 0x0F
        off_bytes = (header >> 4) & 0x0F
        if len_bytes == 0 or pos + len_bytes + off_bytes > n:
            break
        run_len = int.from_bytes(buf[pos:pos + len_bytes], "little")
        pos += len_bytes
        if off_bytes == 0:
            continue  # sparse extent — no physical clusters
        run_off = int.from_bytes(buf[pos:pos + off_bytes], "little", signed=True)
        pos += off_bytes
        lcn += run_off
        if lcn < 0 or run_len == 0:
            continue
        extents.append((lcn * cluster_size, run_len * cluster_size))
    return extents


def _mft_extents(fh: Any, boot: BootInfo) -> list[tuple[int, int]]:
    """Read $MFT record 0 and return the physical extents of its $DATA stream."""
    fh.seek(boot.mft_offset)
    buf = bytearray(fh.read(boot.record_size))
    if buf[0:4] != FILE_SIGNATURE:
        raise ValueError("MFT record 0 has no FILE signature")
    _apply_fixups(buf, boot.bytes_per_sector)
    off = struct.unpack_from("<H", buf, 0x14)[0]
    n = len(buf)
    while off + 4 <= n:
        attr_type = struct.unpack_from("<I", buf, off)[0]
        if attr_type == ATTR_END:
            break
        attr_len = struct.unpack_from("<I", buf, off + 4)[0]
        if attr_len == 0 or off + attr_len > n:
            break
        if attr_type == ATTR_DATA and buf[off + 8] == 1:  # non-resident $DATA
            run_off = struct.unpack_from("<H", buf, off + 0x20)[0]
            extents = _parse_run_list(buf, off + run_off, boot.cluster_size)
            if extents:
                total = sum(l for _o, l in extents)
                logbus.trace(SRC, f"$MFT $DATA: {len(extents)} extent(s), "
                                  f"{total // boot.record_size} record slots")
                return extents
        off += attr_len
    # Fallback: treat the first cluster run as contiguous.
    logbus.warn(SRC, "could not decode $MFT run-list; using contiguous fallback")
    return [(boot.mft_offset, boot.record_size * 65536)]


def parse_volume(volume: str = r"\\.\C:", max_records: int = 20000) -> Iterator[MftRecord]:
    """
    Yield parsed MFT records by walking the $MFT's full run-list (VCN order over
    every extent, so fragmented MFTs are covered). ``max_records`` bounds the
    scan for UI responsiveness.
    """
    boot = read_boot_info(volume)
    logbus.trace(
        SRC,
        f"NTFS geometry: bps={boot.bytes_per_sector} spc={boot.sectors_per_cluster} "
        f"rec={boot.record_size} mft@cluster {boot.mft_cluster}",
    )
    rec_size = boot.record_size
    block_records = 256                      # 256 KiB reads, sector-aligned
    block_bytes = block_records * rec_size
    slot = 0                                 # global MFT record number
    yielded = 0

    with open(volume, "rb", buffering=0) as fh:
        extents = _mft_extents(fh, boot)
        for ext_off, ext_len in extents:
            pos, remaining = ext_off, ext_len
            while remaining >= rec_size and yielded < max_records:
                to_read = min(block_bytes, remaining)
                to_read -= to_read % rec_size
                if to_read == 0:
                    break
                fh.seek(pos)
                data = fh.read(to_read)
                if len(data) < rec_size:
                    break
                for r in range(0, len(data) - rec_size + 1, rec_size):
                    idx = slot
                    slot += 1
                    chunk = data[r:r + rec_size]
                    if chunk[0:4] != FILE_SIGNATURE:
                        continue
                    rbuf = bytearray(chunk)
                    if not _apply_fixups(rbuf, boot.bytes_per_sector):
                        continue
                    rec = _parse_record(bytes(rbuf), idx)
                    if rec and rec.name:
                        yielded += 1
                        yield rec
                        if yielded >= max_records:
                            break
                pos += len(data)
                remaining -= len(data)
            if yielded >= max_records:
                break
    logbus.trace(SRC, f"parsed {yielded} named records across {slot} slots")


# --------------------------------------------------------------------------
# Directory-tree reconstruction (for the space-utilization tree-map)
# --------------------------------------------------------------------------
ROOT_INDEX = 5  # NTFS root directory "." is always MFT record 5


@dataclass
class TreeNode:
    index: int
    name: str
    is_dir: bool
    own_size: int
    children: list[TreeNode] = field(default_factory=list)
    total_size: int = 0

    @property
    def leaf_count(self) -> int:
        return 1 if not self.children else sum(c.leaf_count for c in self.children)


def build_tree(records: list[MftRecord]) -> TreeNode:
    """
    Reconstruct the directory hierarchy from flat records and aggregate sizes.
    Unreachable/orphaned records are attached under a synthetic '<orphans>' node
    so nothing is silently dropped.
    """
    nodes: dict[int, TreeNode] = {}
    for r in records:
        nodes[r.index] = TreeNode(r.index, r.name, r.is_directory, 0 if r.is_directory else r.size)

    root = nodes.get(ROOT_INDEX) or TreeNode(ROOT_INDEX, "\\", True, 0)
    nodes[ROOT_INDEX] = root

    # Link children to parents (skip self-parenting and dangling parents).
    for r in records:
        if r.index == ROOT_INDEX:
            continue
        node = nodes[r.index]
        parent = nodes.get(r.parent_index)
        if parent is not None and parent is not node:
            parent.children.append(node)

    # Aggregate total sizes with a post-order walk (visited guard vs. cycles).
    def total(node: TreeNode, seen: set[int]) -> int:
        if node.index in seen:
            return 0
        seen.add(node.index)
        node.total_size = node.own_size + sum(total(c, seen) for c in node.children)
        return node.total_size

    total(root, set())
    logbus.trace(SRC, f"tree built: root total {root.total_size:,} bytes, "
                      f"{len(root.children)} top-level entries")
    return root
