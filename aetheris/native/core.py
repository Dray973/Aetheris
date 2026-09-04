"""
Bindings to the Rust analysis core (``aetheris_core.dll``).

Every function here has a pure-Python fallback with identical behaviour, so
the suite works unchanged when the library is absent — the native path is a
speed-up, never a requirement. ``tests/test_native_core.py`` runs the whole
surface both ways and asserts the two agree.

Buffers are passed by address, not copied: ``ctypes.c_char_p(data)`` yields a
pointer into the ``bytes`` object's own storage, which stays alive for the
duration of the call. On the multi-megabyte reads this is used for, copying
first would cost more than the scan.
"""
from __future__ import annotations

import ctypes
import math
import struct
from dataclasses import dataclass

from . import loader

SRC = "native.core"

#: Region-classification codes, mirroring `classify::Kind` in the Rust crate.
KIND_LABELS: dict[int, str | None] = {
    0: None,
    1: "rwx",
    2: "unbacked-exec",
    3: "private-pe",
}
KIND_CODES = {v: k for k, v in KIND_LABELS.items() if v}
#: Matches `forensics.injection.SCORE`.
KIND_SCORES = {"rwx": 55, "unbacked-exec": 55, "private-pe": 75}

_DOS_MAGIC = 0x5A4D
_NT_SIGNATURE = 0x0000_4550
_PE32_MAGIC = 0x010B
_PE32PLUS_MAGIC = 0x020B
_SECTION_HEADER_SIZE = 40


@dataclass
class PeInfo:
    is_64: bool
    machine: int
    num_sections: int
    timestamp: int
    characteristics: int
    entry_point: int
    size_of_image: int
    subsystem: int
    dll_characteristics: int
    nt_offset: int
    image_base: int


@dataclass
class PeSection:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_ptr: int
    characteristics: int

    @property
    def is_executable(self) -> bool:
        return bool(self.characteristics & 0x2000_0000)

    @property
    def is_writable(self) -> bool:
        return bool(self.characteristics & 0x8000_0000)


class _CPeInfo(ctypes.Structure):
    _fields_ = [
        ("is_64", ctypes.c_uint32),
        ("machine", ctypes.c_uint32),
        ("num_sections", ctypes.c_uint32),
        ("timestamp", ctypes.c_uint32),
        ("characteristics", ctypes.c_uint32),
        ("entry_point", ctypes.c_uint32),
        ("size_of_image", ctypes.c_uint32),
        ("subsystem", ctypes.c_uint32),
        ("dll_characteristics", ctypes.c_uint32),
        ("nt_offset", ctypes.c_uint32),
        ("image_base", ctypes.c_uint64),
    ]


class _CBootInfo(ctypes.Structure):
    _fields_ = [
        ("bytes_per_sector", ctypes.c_uint32),
        ("sectors_per_cluster", ctypes.c_uint32),
        ("cluster_size", ctypes.c_uint32),
        ("record_size", ctypes.c_uint32),
        ("mft_cluster", ctypes.c_uint64),
    ]


class _CMftRecord(ctypes.Structure):
    # `name` mirrors Rust's [u16; 255]. It is never read through this field —
    # see _NAME_OFFSET below. Declaring it as c_uint16 * 255 and lifting it with
    # bytearray() makes ctypes materialise 255 Python ints per record, which
    # measured 5x *slower* than the pure-Python parser this replaces.
    _fields_ = [
        ("index", ctypes.c_uint64),
        ("parent_index", ctypes.c_uint64),
        ("size", ctypes.c_uint64),
        ("flags", ctypes.c_uint32),
        ("name_len", ctypes.c_uint32),
        ("name", ctypes.c_uint16 * 255),
        ("_pad", ctypes.c_uint16),
    ]


# A parsed block is lifted in one memcpy and decoded with struct.unpack_from
# rather than through ctypes field access. Indexing a ctypes Structure array
# builds a view object per element and converts each field individually, which
# is slow enough to lose to the pure-Python parser it replaces: reading records
# this way measured 5x slower at first, and still 2x slower after the obvious
# fixes. struct.unpack_from over a plain bytes object is C-speed throughout.
_NAME_OFFSET = _CMftRecord.name.offset
_MFT_STRIDE = ctypes.sizeof(_CMftRecord)
_MFT_HEAD = struct.Struct("<QQQII")  # index, parent_index, size, flags, name_len


class _CPeSection(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * 8),
        ("virtual_size", ctypes.c_uint32),
        ("virtual_address", ctypes.c_uint32),
        ("raw_size", ctypes.c_uint32),
        ("raw_ptr", ctypes.c_uint32),
        ("characteristics", ctypes.c_uint32),
    ]


_VOID = ctypes.c_void_p
_SIZE = ctypes.c_size_t
_SSIZE = ctypes.c_ssize_t

_SIGNATURES = {
    "aetheris_entropy": ([_VOID, _SIZE], ctypes.c_double),
    "aetheris_max_window_entropy": ([_VOID, _SIZE, _SIZE], ctypes.c_double),
    "aetheris_find": ([_VOID, _SIZE, _VOID, _SIZE], _SSIZE),
    "aetheris_find_all": ([_VOID, _SIZE, _VOID, _SIZE, _VOID, _SIZE], _SSIZE),
    "aetheris_classify_region": ([ctypes.c_char_p, ctypes.c_char_p], ctypes.c_int32),
    "aetheris_promote_kind": ([ctypes.c_int32, _VOID, _SIZE], ctypes.c_int32),
    "aetheris_kind_score": ([ctypes.c_int32], ctypes.c_int32),
    "aetheris_pe_is_valid": ([_VOID, _SIZE], ctypes.c_int32),
    "aetheris_pe_parse": ([_VOID, _SIZE, ctypes.POINTER(_CPeInfo)], ctypes.c_int32),
    "aetheris_pe_sections": ([_VOID, _SIZE, ctypes.POINTER(_CPeSection), _SIZE], _SSIZE),
    "aetheris_pe_carve": ([_VOID, _SIZE, _SIZE, _VOID, _SIZE], _SSIZE),
    "aetheris_carve_aligned": ([_VOID, _SIZE, _VOID, _SIZE, _SIZE, _VOID, _SIZE], _SSIZE),
    "aetheris_sha256": ([_VOID, _SIZE, _VOID], ctypes.c_int32),
    "aetheris_mft_boot_info": ([_VOID, _SIZE, ctypes.POINTER(_CBootInfo)], ctypes.c_int32),
    "aetheris_mft_parse_block": ([_VOID, _SIZE, _SIZE, _SIZE, ctypes.c_uint64,
                                  ctypes.POINTER(_CMftRecord), _SIZE], _SSIZE),
    "aetheris_mft_run_list": ([_VOID, _SIZE, _SIZE, ctypes.c_uint64, _VOID, _VOID, _SIZE],
                              _SSIZE),
}

_lib: ctypes.CDLL | None = None
_tried = False


def _load() -> ctypes.CDLL | None:
    global _lib, _tried
    if _tried:
        return _lib
    _tried = True
    lib = loader.load("aetheris_core", "aetheris_abi_version")
    if lib is not None:
        for sym, (argtypes, restype) in _SIGNATURES.items():
            fn = getattr(lib, sym)
            fn.argtypes = argtypes
            fn.restype = restype
    _lib = lib
    return _lib


def available() -> bool:
    """True when the Rust core is loaded."""
    return _load() is not None


def reset() -> None:
    """Drop the cached handle. For tests that force the fallback path."""
    global _lib, _tried
    _lib, _tried = None, False
    loader.reset()


def _ptr(data: bytes) -> ctypes.c_char_p:
    """Address of a bytes buffer, without copying it."""
    return ctypes.c_char_p(data)


# --- entropy + search ------------------------------------------------------


def _py_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def entropy(data: bytes) -> float:
    """Shannon entropy of ``data`` in bits/byte (0.0..8.0)."""
    lib = _load()
    if lib is None or not data:
        return _py_entropy(data)
    return float(lib.aetheris_entropy(_ptr(data), len(data)))


def max_window_entropy(data: bytes, window: int = 256) -> float:
    """Highest entropy over ``window``-byte tiles — catches a high-entropy blob
    hiding inside an otherwise low-entropy buffer. ``window=0`` scores it all."""
    lib = _load()
    if lib is None or not data:
        w = window or len(data) or 1
        return max((_py_entropy(data[i:i + w]) for i in range(0, len(data), w)), default=0.0)
    return float(lib.aetheris_max_window_entropy(_ptr(data), len(data), window))


def find(data: bytes, pattern: bytes) -> int:
    """
    First offset of ``pattern`` in ``data``, or -1.

    Deliberately uses Python's ``bytes.find`` rather than the native core.
    CPython implements it with a two-way (Crochemore-Perrin) search; the
    portable Rust version is an anchored linear scan and measures ~2.3x slower
    across the FFI boundary (2.54 ms against 1.09 ms over 8 MB). The
    ``aetheris_find`` export is kept for callers inside the crate, but
    preferring it here would make every search slower.

    Note this does *not* apply to `pe_carve` / `carve_aligned`, which stride
    and validate rather than search, and are ~16x faster natively.
    """
    if not pattern or len(pattern) > len(data):
        return -1
    return data.find(pattern)


def _py_find_all(data: bytes, pattern: bytes, limit: int) -> list[int]:
    out: list[int] = []
    start = 0
    while len(out) < limit:
        hit = data.find(pattern, start)
        if hit < 0:
            break
        out.append(hit)
        start = hit + len(pattern)  # non-overlapping, matching the Rust side
    return out


def find_all(data: bytes, pattern: bytes, limit: int = 4096) -> list[int]:
    """
    Every non-overlapping offset of ``pattern``, capped at ``limit``.

    Uses ``bytes.find`` in a loop for the same reason :func:`find` does — the
    fallback is built on CPython's two-way search and beats the native path
    (1.09 ms against 2.48 ms over 8 MB).
    """
    if not pattern or len(pattern) > len(data) or limit <= 0:
        return []
    return _py_find_all(data, pattern, limit)


# --- region classification -------------------------------------------------


def classify_region(protect: str, region_type: str) -> str | None:
    """Injection kind for a region ('rwx', 'unbacked-exec'), or None."""
    lib = _load()
    if lib is None:
        p = (protect or "").lower()
        if "x" in p and "w" in p:
            return "rwx"
        if "x" in p and region_type != "image":
            return "unbacked-exec"
        return None
    code = int(lib.aetheris_classify_region(
        (protect or "").encode("utf-8", "replace"),
        (region_type or "").encode("utf-8", "replace"),
    ))
    return KIND_LABELS.get(code)


def promote_kind(kind: str | None, head: bytes) -> str | None:
    """Promote 'unbacked-exec' to 'private-pe' when ``head`` starts with MZ."""
    if kind is None:
        return None
    lib = _load()
    if lib is None:
        if kind == "unbacked-exec" and head[:2] == b"MZ":
            return "private-pe"
        return kind
    code = KIND_CODES.get(kind, 0)
    return KIND_LABELS.get(int(lib.aetheris_promote_kind(code, _ptr(head), len(head))), kind)


def kind_score(kind: str | None) -> int:
    """Threat score for a kind, matching ``injection.SCORE``."""
    if kind is None:
        return 0
    lib = _load()
    if lib is None:
        return KIND_SCORES.get(kind, 0)
    return int(lib.aetheris_kind_score(KIND_CODES.get(kind, 0)))


# --- PE --------------------------------------------------------------------


def _py_nt_offset(data: bytes) -> int | None:
    if len(data) < 0x40 or struct.unpack_from("<H", data, 0)[0] != _DOS_MAGIC:
        return None
    nt = int(struct.unpack_from("<I", data, 0x3C)[0])
    if nt < 0x40 or nt > len(data) - 24:
        return None
    if struct.unpack_from("<I", data, nt)[0] != _NT_SIGNATURE:
        return None
    return nt


def _py_pe_parse(data: bytes) -> PeInfo | None:
    nt = _py_nt_offset(data)
    if nt is None:
        return None
    file_h, opt = nt + 4, nt + 24
    try:
        magic = struct.unpack_from("<H", data, opt)[0]
        if magic == _PE32PLUS_MAGIC:
            is_64, image_base = True, struct.unpack_from("<Q", data, opt + 24)[0]
        elif magic == _PE32_MAGIC:
            is_64, image_base = False, struct.unpack_from("<I", data, opt + 28)[0]
        else:
            return None
        return PeInfo(
            is_64=is_64,
            machine=struct.unpack_from("<H", data, file_h)[0],
            num_sections=struct.unpack_from("<H", data, file_h + 2)[0],
            timestamp=struct.unpack_from("<I", data, file_h + 4)[0],
            characteristics=struct.unpack_from("<H", data, file_h + 18)[0],
            entry_point=struct.unpack_from("<I", data, opt + 16)[0],
            size_of_image=struct.unpack_from("<I", data, opt + 56)[0],
            subsystem=struct.unpack_from("<H", data, opt + 68)[0],
            dll_characteristics=struct.unpack_from("<H", data, opt + 70)[0],
            nt_offset=nt,
            image_base=image_base,
        )
    except struct.error:
        return None


def pe_is_valid(data: bytes) -> bool:
    """True when ``data`` begins with a structurally valid PE image."""
    lib = _load()
    if lib is None:
        return _py_nt_offset(data) is not None
    return bool(lib.aetheris_pe_is_valid(_ptr(data), len(data)))


def pe_parse(data: bytes) -> PeInfo | None:
    """Parse the DOS + NT headers at the start of ``data``."""
    lib = _load()
    if lib is None:
        return _py_pe_parse(data)
    info = _CPeInfo()
    if int(lib.aetheris_pe_parse(_ptr(data), len(data), ctypes.byref(info))) != 1:
        return None
    return PeInfo(
        is_64=bool(info.is_64), machine=info.machine, num_sections=info.num_sections,
        timestamp=info.timestamp, characteristics=info.characteristics,
        entry_point=info.entry_point, size_of_image=info.size_of_image,
        subsystem=info.subsystem, dll_characteristics=info.dll_characteristics,
        nt_offset=info.nt_offset, image_base=info.image_base,
    )


def _py_pe_sections(data: bytes, limit: int) -> list[PeSection]:
    nt = _py_nt_offset(data)
    info = _py_pe_parse(data)
    if nt is None or info is None:
        return []
    try:
        size_of_optional = struct.unpack_from("<H", data, nt + 20)[0]
    except struct.error:
        return []
    out: list[PeSection] = []
    off = nt + 24 + size_of_optional
    for _ in range(min(info.num_sections, limit)):
        chunk = data[off:off + _SECTION_HEADER_SIZE]
        if len(chunk) < _SECTION_HEADER_SIZE:
            break
        out.append(PeSection(
            name=chunk[0:8].split(b"\0")[0].decode("utf-8", "replace"),
            virtual_size=struct.unpack_from("<I", chunk, 8)[0],
            virtual_address=struct.unpack_from("<I", chunk, 12)[0],
            raw_size=struct.unpack_from("<I", chunk, 16)[0],
            raw_ptr=struct.unpack_from("<I", chunk, 20)[0],
            characteristics=struct.unpack_from("<I", chunk, 36)[0],
        ))
        off += _SECTION_HEADER_SIZE
    return out


def pe_sections(data: bytes, limit: int = 96) -> list[PeSection]:
    """Parse the section table, at most ``limit`` entries."""
    lib = _load()
    if lib is None:
        return _py_pe_sections(data, limit)
    buf = (_CPeSection * limit)()
    n = int(lib.aetheris_pe_sections(_ptr(data), len(data), buf, limit))
    return [
        PeSection(
            name=buf[i].name.split(b"\0")[0].decode("utf-8", "replace"),
            virtual_size=buf[i].virtual_size, virtual_address=buf[i].virtual_address,
            raw_size=buf[i].raw_size, raw_ptr=buf[i].raw_ptr,
            characteristics=buf[i].characteristics,
        )
        for i in range(max(n, 0))
    ]


def _py_pe_carve(data: bytes, stride: int, limit: int) -> list[int]:
    out: list[int] = []
    off = 0
    while off + 2 <= len(data) and len(out) < limit:
        if data[off:off + 2] == b"MZ" and _py_nt_offset(data[off:]) is not None:
            out.append(off)
        off += stride
    return out


def pe_carve(data: bytes, stride: int = 4096, limit: int = 4096) -> list[int]:
    """Offsets of PE images in a raw buffer, scanning on ``stride`` boundaries.
    Only headers that actually parse are reported — a bare ``MZ`` pair is far
    too common in arbitrary memory to be worth surfacing."""
    if stride <= 0 or limit <= 0:
        return []
    lib = _load()
    if lib is None:
        return _py_pe_carve(data, stride, limit)
    out = (ctypes.c_uint64 * limit)()
    n = int(lib.aetheris_pe_carve(_ptr(data), len(data), stride, out, limit))
    return [int(out[i]) for i in range(max(n, 0))]


def carve_aligned(data: bytes, tag: bytes, stride: int = 16, limit: int = 4096) -> list[int]:
    """Offsets where ``tag`` sits on a ``stride`` boundary — the pool-tag sweep
    used to surface kernel allocations in a physical image."""
    if not tag or stride <= 0 or limit <= 0:
        return []
    lib = _load()
    if lib is None:
        return [i for i in range(0, max(len(data) - len(tag) + 1, 0), stride)
                if data[i:i + len(tag)] == tag][:limit]
    out = (ctypes.c_uint64 * limit)()
    n = int(lib.aetheris_carve_aligned(_ptr(data), len(data), _ptr(tag), len(tag),
                                       stride, out, limit))
    return [int(out[i]) for i in range(max(n, 0))]


# --- NTFS MFT --------------------------------------------------------------


@dataclass
class MftBootInfo:
    bytes_per_sector: int
    sectors_per_cluster: int
    cluster_size: int
    mft_cluster: int
    record_size: int


@dataclass
class MftRecordData:
    index: int
    in_use: bool
    is_directory: bool
    name: str
    size: int
    parent_index: int


def mft_boot_info(boot: bytes) -> MftBootInfo | None:
    """Parse NTFS geometry from a boot sector. None if it isn't NTFS.

    Returns None on the fallback path too, so the caller keeps its own parser —
    this is the one MFT function cheap enough that Python duplication would be
    pure redundancy.
    """
    lib = _load()
    if lib is None:
        return None
    info = _CBootInfo()
    if int(lib.aetheris_mft_boot_info(_ptr(boot), len(boot), ctypes.byref(info))) != 1:
        return None
    return MftBootInfo(
        bytes_per_sector=info.bytes_per_sector,
        sectors_per_cluster=info.sectors_per_cluster,
        cluster_size=info.cluster_size,
        mft_cluster=info.mft_cluster,
        record_size=info.record_size,
    )


def mft_parse_block(data: bytes, record_size: int, bytes_per_sector: int,
                    first_index: int) -> list[MftRecordData] | None:
    """
    Fix up and decode a contiguous block of FILE records in one call.

    None means the library isn't loaded (the caller falls back to its own
    per-record loop). Records that fail their fixups or carry no name are
    skipped, matching the Python original, so the result is shorter than the
    slot count. ``first_index`` is the MFT slot of the first record, which
    keeps indices correct across extents.
    """
    lib = _load()
    if lib is None:
        return None
    if record_size <= 0 or bytes_per_sector <= 0 or len(data) < record_size:
        return []
    cap = len(data) // record_size
    buf = (_CMftRecord * cap)()
    n = int(lib.aetheris_mft_parse_block(_ptr(data), len(data), record_size,
                                         bytes_per_sector, first_index, buf, cap))
    if n < 0:
        return []
    raw = ctypes.string_at(ctypes.addressof(buf), n * _MFT_STRIDE)
    unpack = _MFT_HEAD.unpack_from
    out = []
    for i in range(n):
        o = i * _MFT_STRIDE
        index, parent_index, size, flags, name_len = unpack(raw, o)
        nstart = o + _NAME_OFFSET
        out.append(MftRecordData(
            index=index,
            in_use=bool(flags & 0x1),
            is_directory=bool(flags & 0x2),
            name=raw[nstart:nstart + name_len * 2].decode("utf-16-le", "replace"),
            size=size,
            parent_index=parent_index,
        ))
    return out


def mft_run_list(buf: bytes, pos: int, cluster_size: int,
                 limit: int = 4096) -> list[tuple[int, int]] | None:
    """Decode a mapping-pairs list into (byte_offset, byte_length) extents.
    None when the library isn't loaded."""
    lib = _load()
    if lib is None:
        return None
    offs = (ctypes.c_uint64 * limit)()
    lens = (ctypes.c_uint64 * limit)()
    n = int(lib.aetheris_mft_run_list(_ptr(buf), len(buf), pos, cluster_size,
                                      offs, lens, limit))
    if n < 0:
        return []
    return [(int(offs[i]), int(lens[i])) for i in range(n)]


# --- hashing ---------------------------------------------------------------


def sha256(data: bytes) -> bytes:
    """
    SHA-256 digest of ``data`` (32 raw bytes).

    Deliberately uses ``hashlib``, not the native core. CPython's hashlib goes
    through OpenSSL, which issues the CPU's SHA-NI instructions; the portable
    Rust implementation does not, and measures ~11x slower (277 MB/s against
    3.2 GB/s on this machine). The Rust `aetheris_sha256` export is kept for
    callers inside the crate and for hosts without a hashlib, but preferring it
    here would make every hash slower for no benefit.
    """
    import hashlib
    return hashlib.sha256(data).digest()
