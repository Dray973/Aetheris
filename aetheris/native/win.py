"""
Bindings to the C++ Win32 engine (``aetheris_win.dll``).

Unlike :mod:`aetheris.native.core`, this module does **not** carry its own
fallbacks. The Win32 paths it replaces already exist in Python — the
``VirtualQueryEx`` loop in :mod:`aetheris.forensics.memvirt`, the psutil walk in
:mod:`aetheris.forensics.processes` — so duplicating them here would mean two
copies of the same logic drifting apart. Instead every function returns ``None``
or an empty list when the library is absent, and the caller keeps using what it
already had. ``available()`` says which path is live.

The one capability with no Python equivalent is the system-wide handle table.
:mod:`aetheris.storage.handles` can only enumerate handles for a caller-supplied
set of PIDs, because ``NtQueryObject`` blocks indefinitely on some handles and
Python cannot abandon a blocked call. The C++ side runs those queries on a
worker thread it can walk away from, so :func:`enum_handles` with no filter is
safe. Without the DLL that view is simply unavailable, not silently partial.
"""
from __future__ import annotations

import ctypes
import struct
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypeVar

from ..core import logbus
from . import loader

SRC = "native.win"

#: The ctypes Structure a _grow buffer is built from.
_CT = TypeVar("_CT", bound=ctypes.Structure)

#: A registry value as winreg would report it, paired with its type code.
RegValue = tuple[Any, int]

# Error codes returned by the engine (mirrors AW_ERR_* in aetheris_win.cpp).
ERR_INVALID = -1
ERR_UNSUPPORTED = -2
ERR_DENIED = -3
ERR_TIMEOUT = -4

#: Mitigation states, mirroring aw_process_mitigations.
_MITIGATION = {0: "off", 1: "on", 2: "unknown"}


@dataclass
class NativeProcess:
    pid: int
    ppid: int
    threads: int
    name: str
    exe: str


@dataclass
class NativeRegion:
    """A raw region. State/protect/type stay as the Win32 constants; the
    caller maps them to labels with its own tables so the two backends keep
    producing identical strings."""
    base: int
    size: int
    state: int
    protect: int
    type: int


@dataclass
class HandleEntry:
    pid: int
    handle: int
    object: int
    granted_access: int
    attributes: int
    type_index: int


class _AwProcess(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("threads", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
        ("name", ctypes.c_wchar * 260),
        ("exe", ctypes.c_wchar * 520),
    ]


class _AwRegion(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("base", ctypes.c_uint64),
        ("size", ctypes.c_uint64),
        ("state", ctypes.c_uint32),
        ("protect", ctypes.c_uint32),
        ("type", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
    ]


class _AwService(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("name", ctypes.c_wchar * 256),
        ("display_name", ctypes.c_wchar * 256),
        ("image_path", ctypes.c_wchar * 520),
        ("account", ctypes.c_wchar * 256),
        ("service_type", ctypes.c_uint32),
        ("start_type", ctypes.c_uint32),
        ("state", ctypes.c_uint32),
    ]


class _AwConnection(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("state", ctypes.c_uint32),
        ("family", ctypes.c_uint32),
        ("proto", ctypes.c_uint32),
        ("local_port", ctypes.c_uint16),
        ("remote_port", ctypes.c_uint16),
        ("local_addr", ctypes.c_uint8 * 16),
        ("remote_addr", ctypes.c_uint8 * 16),
    ]


class _AwHandleRaw(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("handle", ctypes.c_uint64),
        ("object", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("granted_access", ctypes.c_uint32),
        ("attributes", ctypes.c_uint32),
        ("type_index", ctypes.c_uint16),
        ("reserved", ctypes.c_uint16),
    ]


_U32 = ctypes.c_uint32
_U64 = ctypes.c_uint64
_SIZE = ctypes.c_size_t

_SIGNATURES = {
    "aw_reset_cache": ([], None),
    "aw_enum_processes": ([ctypes.POINTER(_AwProcess), _SIZE], ctypes.c_int32),
    "aw_process_mitigations": ([_U32, ctypes.POINTER(_U32), ctypes.POINTER(_U32)],
                               ctypes.c_int32),
    "aw_memory_map": ([_U32, ctypes.POINTER(_AwRegion), _SIZE], ctypes.c_int32),
    "aw_read_memory": ([_U32, _U64, ctypes.POINTER(ctypes.c_uint8), _SIZE], ctypes.c_int64),
    "aw_enum_handles": ([_U32, ctypes.POINTER(_AwHandleRaw), _SIZE], ctypes.c_int32),
    "aw_handle_object_name": ([_U32, _U64, ctypes.c_wchar_p, _SIZE, _U32], ctypes.c_int32),
    "aw_handle_type_name": ([_U32, _U64, ctypes.c_uint16, ctypes.c_wchar_p, _SIZE, _U32],
                            ctypes.c_int32),
    "aw_handle_process_target": ([_U32, _U64], _U32),
    "aw_find_handles_by_name": ([ctypes.c_wchar_p, ctypes.POINTER(_U32), _SIZE,
                                 ctypes.POINTER(_AwHandleRaw), _SIZE, _U32], ctypes.c_int32),
    "aw_close_handle_in_process": ([_U32, _U64], ctypes.c_int32),
    "aw_verify_signature": ([ctypes.c_wchar_p], ctypes.c_int32),
    "aw_enum_services": ([ctypes.POINTER(_AwService), _SIZE], ctypes.c_int32),
    "aw_enum_driver_services": ([ctypes.POINTER(_AwService), _SIZE], ctypes.c_int32),
    "aw_enum_connections": ([ctypes.POINTER(_AwConnection), _SIZE], ctypes.c_int32),
    "aw_enable_privilege": ([ctypes.c_wchar_p], ctypes.c_int32),
    "aw_reg_snapshot": ([_U32, ctypes.c_wchar_p, _U32,
                         ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8))], ctypes.c_int64),
    "aw_reg_free": ([ctypes.POINTER(ctypes.c_uint8)], None),
}

#: Hive index passed to aw_reg_snapshot, mirroring AW_HIVES in the engine.
HIVES = {"HKCR": 0, "HKCU": 1, "HKLM": 2, "HKU": 3}

#: Signature verdicts from aw_verify_signature.
SIG_NONE, SIG_EMBEDDED, SIG_CATALOG = 0, 1, 2

# Output buffers start at a size that covers the common case and double until
# the engine stops filling them. Sizing for the worst case up front is what the
# obvious implementation does, and it is badly wrong here: ctypes zero-fills on
# construction, so a 500k-row handle buffer costs 16 MB of memset on *every*
# call — and memory_map is called once per process during a scan.
#
# The growth check is `n == cap`, i.e. "the engine filled every slot", which
# cannot distinguish a truncated result from one that exactly fit. Retrying the
# exact-fit case is one wasted call in rare circumstances, versus silently
# dropping rows — for a forensics sweep that trade is not close.
PROCESSES_START, PROCESSES_MAX = 512, 8192
REGIONS_START, REGIONS_MAX = 4096, 262_144
HANDLES_START, HANDLES_MAX = 262_144, 4_194_304


def _grow(call: Callable[[Any, int], Any], ctype: type[_CT],
          start: int, hard_max: int) -> tuple[Any, int]:
    """
    Call ``call(buffer, capacity)`` with a buffer that doubles until it holds
    the whole result. Returns ``(buffer, count)``; a negative count from the
    engine is passed straight through for the caller to interpret.
    """
    cap = start
    while True:
        buf = (ctype * cap)()
        n = int(call(buf, cap))
        if n < 0 or n < cap or cap >= hard_max:
            return buf, n
        cap = min(cap * 2, hard_max)

_lib: ctypes.CDLL | None = None
_tried = False


def _load() -> ctypes.CDLL | None:
    global _lib, _tried
    if _tried:
        return _lib
    _tried = True
    lib = loader.load("aetheris_win", "aw_abi_version")
    if lib is not None:
        # The ABI check should already have rejected a library missing any of
        # these, but binding is the point where a mismatch would otherwise
        # surface as an AttributeError during import. Refuse the whole library
        # instead: a half-bound engine is worse than none.
        try:
            for sym, (argtypes, restype) in _SIGNATURES.items():
                fn = getattr(lib, sym)
                fn.argtypes = argtypes
                fn.restype = restype
        except AttributeError as exc:
            logbus.warn(SRC, "aetheris_win.dll is missing an expected export; "
                             "using Python fallbacks", str(exc))
            lib = None
    _lib = lib
    return _lib


def available() -> bool:
    """True when the native Win32 engine is loaded."""
    return _load() is not None


def reset() -> None:
    """Drop the cached handle. For tests that force the fallback path."""
    global _lib, _tried
    _lib, _tried = None, False
    loader.reset()


def reset_cache() -> None:
    """Release the engine's cached process handles. Call between sweeps: a
    cached handle pins its pid against reuse."""
    lib = _load()
    if lib is not None:
        lib.aw_reset_cache()


# --- processes -------------------------------------------------------------


def enum_processes() -> list[NativeProcess]:
    """Snapshot every visible process, or [] when the engine is absent."""
    lib = _load()
    if lib is None:
        return []
    buf, n = _grow(lib.aw_enum_processes, _AwProcess, PROCESSES_START, PROCESSES_MAX)
    if n < 0:
        return []
    return [
        NativeProcess(pid=buf[i].pid, ppid=buf[i].ppid, threads=buf[i].threads,
                      name=buf[i].name, exe=buf[i].exe)
        for i in range(n)
    ]


def process_mitigations(pid: int) -> tuple[str, str] | None:
    """(dep, aslr) as 'on' / 'off' / 'unknown', or None when unavailable."""
    lib = _load()
    if lib is None:
        return None
    dep, aslr = _U32(2), _U32(2)
    if int(lib.aw_process_mitigations(pid, ctypes.byref(dep), ctypes.byref(aslr))) < 0:
        return None
    return _MITIGATION.get(dep.value, "unknown"), _MITIGATION.get(aslr.value, "unknown")


# --- process memory --------------------------------------------------------


def memory_map(pid: int) -> list[NativeRegion] | None:
    """
    Committed/reserved regions of ``pid``.

    None means "no answer from here" — the engine is absent, or the OS refused
    the process — and the caller falls back to its own path, which reaches the
    same conclusion and logs it. Returning [] for a refusal instead would make
    a locked-down process look like an empty one.
    """
    lib = _load()
    if lib is None:
        return None
    buf, n = _grow(lambda b, c: lib.aw_memory_map(pid, b, c),
                   _AwRegion, REGIONS_START, REGIONS_MAX)
    if n < 0:
        return None
    return [
        NativeRegion(base=buf[i].base, size=buf[i].size, state=buf[i].state,
                     protect=buf[i].protect, type=buf[i].type)
        for i in range(n)
    ]


def read_memory(pid: int, address: int, size: int) -> bytes | None:
    """Read ``size`` bytes at ``address``. A short read is returned as-is —
    a partially readable region is still evidence."""
    lib = _load()
    if lib is None or size <= 0:
        return None
    buf = (ctypes.c_uint8 * size)()
    got = int(lib.aw_read_memory(pid, address, buf, size))
    if got < 0:
        return None
    return bytes(buf[:got])


# --- handles ---------------------------------------------------------------


def enum_handles(pid: int = 0) -> list[HandleEntry]:
    """
    The handle table. ``pid=0`` means every process — the system-wide view
    that has no Python equivalent. Returns [] when the engine is absent.
    """
    lib = _load()
    if lib is None:
        return []
    # A per-pid query needs a fraction of the system-wide table.
    start = HANDLES_START if pid == 0 else 8192
    buf, n = _grow(lambda b, c: lib.aw_enum_handles(pid, b, c),
                   _AwHandleRaw, start, HANDLES_MAX)
    if n < 0:
        return []
    return [
        HandleEntry(pid=buf[i].pid, handle=buf[i].handle, object=buf[i].object,
                    granted_access=buf[i].granted_access, attributes=buf[i].attributes,
                    type_index=buf[i].type_index)
        for i in range(n)
    ]


def handle_object_name(entry: HandleEntry, timeout_ms: int = 100) -> str | None:
    """
    Resolve an object's name. None means it could not be read — unnamed,
    refused, or abandoned after ``timeout_ms``; all three are ordinary.

    Every query is bounded by the engine's shared worker. Selecting a "safe
    path" by access mask, as the Python original did, is not sound: a
    system-wide sweep still meets handles that hang and the mask does not
    match.
    """
    lib = _load()
    if lib is None:
        return None
    buf = ctypes.create_unicode_buffer(520)
    rc = int(lib.aw_handle_object_name(entry.pid, entry.handle, buf, 520, timeout_ms))
    return buf.value if rc > 0 else None


def handle_type_name(entry: HandleEntry, timeout_ms: int = 100) -> str | None:
    """Resolve a handle's object *type* ('File', 'Key', 'Process'). Cached by
    type index inside the engine, so this costs a syscall only once per type."""
    lib = _load()
    if lib is None:
        return None
    buf = ctypes.create_unicode_buffer(64)
    rc = int(lib.aw_handle_type_name(entry.pid, entry.handle, entry.type_index,
                                     buf, 64, timeout_ms))
    return buf.value if rc > 0 else None


def find_handles_by_name(target: str, pids: set[int] | None = None,
                         timeout_ms: int = 150) -> list[HandleEntry] | None:
    """
    Every handle whose object name equals ``target`` (case-insensitive; give an
    NT device path such as ``\\Device\\HarddiskVolume3\\dir\\file``).

    None means the engine is absent so the caller should fall back. The search
    runs entirely inside the engine: doing it from Python costs one FFI call
    per handle across a table of six figures, which is why the Python original
    had to be given a PID set to stay tractable.

    ``pids=None`` searches every process. An *empty* set matches nothing, and
    the distinction matters: results from here feed
    :func:`close_handle_in_process`, so treating an empty filter as "no
    filter" would turn "restrict to these safe PIDs" into "every process on
    the machine, including the critical ones the caller just excluded".
    """
    lib = _load()
    if lib is None:
        return None
    if pids is not None and not pids:
        return []
    pid_arr, pid_count = None, 0
    if pids:
        pid_list = sorted(pids)
        pid_arr = (_U32 * len(pid_list))(*pid_list)
        pid_count = len(pid_list)
    buf, n = _grow(
        lambda b, c: lib.aw_find_handles_by_name(target, pid_arr, pid_count, b, c, timeout_ms),
        _AwHandleRaw, 256, 65536,
    )
    if n < 0:
        return []
    return [
        HandleEntry(pid=buf[i].pid, handle=buf[i].handle, object=buf[i].object,
                    granted_access=buf[i].granted_access, attributes=buf[i].attributes,
                    type_index=buf[i].type_index)
        for i in range(n)
    ]


def close_handle_in_process(pid: int, handle: int) -> bool | None:
    """
    Force a handle shut inside another process (DUPLICATE_CLOSE_SOURCE).

    Destructive: the caller is responsible for the critical-process and
    protected-path guardrails. None means the engine is absent.
    """
    lib = _load()
    if lib is None:
        return None
    return int(lib.aw_close_handle_in_process(pid, handle)) == 0


# --- code signing ----------------------------------------------------------


def verify_signature(path: str) -> int | None:
    """
    Authenticode verdict: SIG_EMBEDDED, SIG_CATALOG, SIG_NONE, or None when the
    engine is absent or the path is unusable.

    The engine holds one catalog admin context across calls; the Python
    implementation acquired and released one per file, which dominated the cost
    of signing a services or autoruns list.
    """
    lib = _load()
    if lib is None or not path:
        return None
    rc = int(lib.aw_verify_signature(path))
    return rc if rc >= 0 else None


# --- services and drivers --------------------------------------------------

#: SCM current-state codes → the labels services.py already emits.
_SERVICE_STATE = {
    1: "stopped", 2: "start_pending", 3: "stop_pending", 4: "running",
    5: "continue_pending", 6: "pause_pending", 7: "paused",
}
#: Start-type codes. Kept identical to core.services._START_TYPES — that module
#: spells automatic start "auto", and callers there should prefer its own
#: start_type_label() so the native and psutil paths cannot diverge.
_START_TYPE = {0: "boot", 1: "system", 2: "auto", 3: "manual", 4: "disabled"}


@dataclass
class NativeService:
    name: str
    display_name: str
    image_path: str
    account: str
    service_type: int
    start_type: int
    state: int

    @property
    def state_label(self) -> str:
        return _SERVICE_STATE.get(self.state, "unknown")

    @property
    def start_label(self) -> str:
        return _START_TYPE.get(self.start_type, "unknown")


#: Sentinel the engine writes for a registry DWORD that is absent entirely.
VALUE_ABSENT = 0xFFFFFFFF


def _services_from(fn: Callable[[Any, int], Any]) -> list[NativeService] | None:
    buf, n = _grow(fn, _AwService, 512, 8192)
    if n < 0:
        return None
    out = []
    for i in range(n):
        start = buf[i].start_type
        # An absent Start value must reach the caller as -1 so its label table
        # says "unknown"; passing 0 through would claim boot-start.
        out.append(NativeService(
            name=buf[i].name, display_name=buf[i].display_name,
            image_path=buf[i].image_path, account=buf[i].account,
            service_type=buf[i].service_type,
            start_type=-1 if start == VALUE_ABSENT else start,
            state=buf[i].state,
        ))
    return out


def enum_services() -> list[NativeService] | None:
    """Win32 services with live state and configuration. None when the engine
    is absent, so the caller falls back to psutil."""
    lib = _load()
    if lib is None:
        return None
    return _services_from(lib.aw_enum_services)


def enum_driver_services() -> list[NativeService] | None:
    """
    Driver entries from the Services registry key. ``state`` is always 0 —
    whether a driver is loaded is the caller's decision against the loaded
    module list.

    This is the call that most needed moving: the Python path walked ~700
    subkeys issuing five ``winreg.QueryValueEx`` calls each, roughly 4,900
    round-trips into Python. Here it is one.
    """
    lib = _load()
    if lib is None:
        return None
    return _services_from(lib.aw_enum_driver_services)


# --- sockets ---------------------------------------------------------------


@dataclass
class NativeConnection:
    pid: int
    state: int
    family: int          # 4 or 6
    proto: str           # "TCP" / "UDP"
    laddr: str
    lport: int
    raddr: str
    rport: int


#: TCP states from the IP-Helper tables → psutil's spelling, so either source
#: produces the same status text in the UI.
_TCP_STATE = {
    1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RECV", 5: "ESTABLISHED",
    6: "FIN_WAIT1", 7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING",
    10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB",
}


def _fmt_addr(raw: Any, family: int) -> str:
    import socket
    try:
        if family == 4:
            return socket.inet_ntop(socket.AF_INET, bytes(raw[:4]))
        return socket.inet_ntop(socket.AF_INET6, bytes(raw[:16]))
    except (OSError, ValueError):
        return ""


def enum_connections() -> list[NativeConnection] | None:
    """Every TCP and UDP socket with its owning pid, both address families.
    None when the engine is absent."""
    lib = _load()
    if lib is None:
        return None
    buf, n = _grow(lib.aw_enum_connections, _AwConnection, 1024, 262_144)
    if n < 0:
        return None
    out = []
    for i in range(n):
        c = buf[i]
        is_tcp = c.proto == 6
        # A UDP socket has no peer, and an unconnected TCP socket reports
        # 0.0.0.0:0 — reporting either as an address would be noise.
        remote = _fmt_addr(c.remote_addr, c.family) if is_tcp else ""
        if remote in ("0.0.0.0", "::") and c.remote_port == 0:
            remote = ""
        out.append(NativeConnection(
            pid=c.pid,
            state=c.state,
            family=c.family,
            proto="TCP" if is_tcp else "UDP",
            laddr=_fmt_addr(c.local_addr, c.family),
            lport=c.local_port,
            raddr=remote,
            rport=c.remote_port if remote else 0,
        ))
    return out


def tcp_state_label(state: int) -> str:
    """IP-Helper TCP state code → psutil's spelling ('NONE' for UDP)."""
    return _TCP_STATE.get(state, "NONE")


# --- registry --------------------------------------------------------------

_REG_HEAD_KEY = struct.Struct("<II")     # key_bytes, value_count
_REG_HEAD_VAL = struct.Struct("<III")    # name_bytes, type, data_bytes


def _utf16(data: bytes) -> str:
    """
    Decode UTF-16LE the way winreg does.

    Truncates to whole code units first: a value whose byte count is odd would
    otherwise leave a trailing U+FFFD from the error handler, where winreg
    simply never sees the stray byte.
    """
    return data[: len(data) & ~1].decode("utf-16-le", "replace")


def _multi_sz(data: bytes) -> list[str]:
    """
    Split REG_MULTI_SZ the way winreg does.

    Two traps here, both found by diffing 170k real values against winreg:
    splitting on NUL and dropping *every* trailing empty turns a value holding
    one empty string into ``[]`` when winreg reports ``['']``; keeping them all
    leaves a spurious ``''`` on every ordinary value. The rule that matches is
    to walk the buffer counting strings, then drop exactly one trailing empty —
    the list terminator, and only it.
    """
    units = len(data) // 2
    text = _utf16(data)
    out: list[str] = []
    i = 0
    while i < units and i < len(text):
        j = i
        while j < units and j < len(text) and text[j] != "\x00":
            j += 1
        out.append(text[i:j])
        i = j + 1
    if out and out[-1] == "":
        out.pop()
    return out


def _reg_value(data: bytes, vtype: int) -> Any:
    """
    Turn raw registry bytes into the object ``winreg.EnumValue`` would return.

    The conversions must match winreg exactly: the caller renders these with
    ``repr()`` into snapshots that are saved to disk and later diffed against
    ones taken through the pure-Python path, so any difference here would show
    up as a phantom "modified" row.
    """
    if vtype in (1, 2):                       # REG_SZ, REG_EXPAND_SZ
        # Truncate at the first NUL, not rstrip: values written with a wrong
        # length carry junk after their terminator ("...javon\0 "), and winreg
        # stops at the terminator. An empty buffer is '' here, not None.
        return _utf16(data).split("\x00", 1)[0]
    # For every other type a value that is present but carries no data reads
    # as None — the most common divergence when this is written the obvious
    # way, where an empty buffer becomes b'' or [] instead.
    if not data:
        return None
    if vtype == 4:                            # REG_DWORD
        return int.from_bytes(data[:4], "little") if len(data) >= 4 else 0
    if vtype == 5:                            # REG_DWORD_BIG_ENDIAN
        return int.from_bytes(data[:4], "big") if len(data) >= 4 else 0
    if vtype == 11:                           # REG_QWORD
        return int.from_bytes(data[:8], "little") if len(data) >= 8 else 0
    if vtype == 7:                            # REG_MULTI_SZ
        return _multi_sz(data)
    return bytes(data)                        # REG_BINARY, REG_NONE, anything else


def reg_snapshot(root: str, subkey: str, max_depth: int = 6
                 ) -> dict[str, dict[str, RegValue]] | None:
    """
    Walk a registry subtree, returning ``{key_path: {value_name: (data, type)}}``
    with ``data`` as the object winreg would have produced.

    None when the engine is absent. The walk is the whole cost — 57k keys and
    147k values measured 1.6 s through winreg, essentially all of it in the
    per-value round-trip rather than in formatting — so it runs natively and
    only the decoding stays here.
    """
    lib = _load()
    if lib is None:
        return None
    hive = HIVES.get(root.upper())
    if hive is None:
        return None

    ptr = ctypes.POINTER(ctypes.c_uint8)()
    n = int(lib.aw_reg_snapshot(hive, subkey, max_depth, ctypes.byref(ptr)))
    if n < 0:
        return None
    if n == 0 or not ptr:
        return {}
    try:
        blob = ctypes.string_at(ptr, n)
    finally:
        lib.aw_reg_free(ptr)

    out: dict[str, dict[str, RegValue]] = {}
    pos, end = 0, len(blob)
    unpack_key, unpack_val = _REG_HEAD_KEY.unpack_from, _REG_HEAD_VAL.unpack_from
    while pos + 8 <= end:
        key_bytes, count = unpack_key(blob, pos)
        pos += 8
        key = blob[pos:pos + key_bytes].decode("utf-16-le", "replace")
        pos += key_bytes
        values: dict[str, RegValue] = {}
        for _ in range(count):
            if pos + 12 > end:
                break
            name_bytes, vtype, data_bytes = unpack_val(blob, pos)
            pos += 12
            name = blob[pos:pos + name_bytes].decode("utf-16-le", "replace")
            pos += name_bytes
            data = blob[pos:pos + data_bytes]
            pos += data_bytes
            values[name] = (_reg_value(data, vtype), vtype)
        out[key] = values
    return out


# --- privileges ------------------------------------------------------------


def enable_privilege(name: str) -> tuple[bool, str] | None:
    """
    Enable a named privilege on this process token.

    Returns (ok, message) or None when the engine is absent. A token that
    simply does not hold the privilege reports ok=False with a specific
    message rather than an error — that is the ordinary case for several of
    the forensics privileges on a non-elevated session.
    """
    lib = _load()
    if lib is None:
        return None
    rc = int(lib.aw_enable_privilege(name))
    if rc == 0:
        return True, f"{name}: enabled"
    if rc == 1:
        return False, f"{name}: not held by this token (ERROR_NOT_ALL_ASSIGNED)"
    if rc == ERR_INVALID:
        return False, f"{name}: invalid privilege name"
    return False, f"{name}: token adjust failed"


def handle_process_target(entry: HandleEntry) -> int:
    """For a Process-type handle, the pid it points at (0 if undeterminable).

    This is what turns the handle table into a detection: a Process object has
    no name to report, only a target, and a handle into lsass.exe held by
    something with no business holding one is the classic credential-theft
    tell."""
    lib = _load()
    if lib is None:
        return 0
    return int(lib.aw_handle_process_target(entry.pid, entry.handle))
