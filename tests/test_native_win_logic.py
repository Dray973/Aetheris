"""
Python-side logic of the C++ engine bindings, driven by a fake engine.

``test_native_win.py`` exercises the real DLL and skips wherever it isn't
built. These cover what sits on the Python side of the boundary -- buffer
growth, error mapping, blob decoding, address formatting, loader concurrency
-- and run on every platform, because a mistake there would misread every row
the real engine produces.
"""
import ctypes
import socket
import struct
import threading
import time

import pytest

from aetheris.native import win


class FakeLib:
    """Stands in for the loaded CDLL; tests attach aw_* callables."""


@pytest.fixture
def fake(monkeypatch):
    lib = FakeLib()
    monkeypatch.setattr(win, "_lib", lib)
    monkeypatch.setattr(win, "_tried", True)
    return lib


@pytest.fixture
def warnings(monkeypatch):
    seen: list[str] = []
    monkeypatch.setattr(win.logbus, "warn", lambda src, msg, *a: seen.append(msg))
    return seen


# --- _grow -----------------------------------------------------------------


def _filler(total):
    """An engine call that fills min(total, cap) rows and reports how many."""
    caps: list[int] = []

    def call(buf, cap):
        caps.append(cap)
        n = min(total, cap)
        for i in range(n):
            buf[i].pid = i + 1
        return n
    return call, caps


def test_grow_doubles_until_the_result_fits():
    call, caps = _filler(300)
    buf, n = win._grow(call, win._AwProcess, 64, 4096)
    assert n == 300
    assert caps == [64, 128, 256, 512]
    assert [buf[i].pid for i in (0, 299)] == [1, 300]


def test_grow_retries_an_exact_fit_once():
    call, caps = _filler(128)
    _, n = win._grow(call, win._AwProcess, 128, 4096)
    assert n == 128 and caps == [128, 256]


def test_grow_passes_engine_errors_through_without_retrying():
    caps: list[int] = []

    def call(buf, cap):
        caps.append(cap)
        return win.ERR_DENIED
    _, n = win._grow(call, win._AwProcess, 64, 4096)
    assert n == win.ERR_DENIED and caps == [64]


def test_grow_warns_when_the_hard_cap_may_have_truncated(warnings):
    call, caps = _filler(10_000)
    _, n = win._grow(call, win._AwProcess, 64, 256)
    assert n == 256 and caps[-1] == 256
    assert len(warnings) == 1 and "cap" in warnings[0]


def test_grow_does_not_warn_below_the_cap(warnings):
    call, _ = _filler(100)
    win._grow(call, win._AwProcess, 64, 256)
    assert warnings == []


# --- loading ---------------------------------------------------------------


def test_concurrent_first_load_binds_once_and_nobody_sees_none(monkeypatch):
    calls: list[int] = []

    class Lib:
        def __getattr__(self, name):
            return type("Fn", (), {})()  # accepts argtypes/restype

    def slow_load(name, abi_symbol):
        calls.append(1)
        time.sleep(0.05)
        return Lib()

    monkeypatch.setattr(win, "_lib", None)
    monkeypatch.setattr(win, "_tried", False)
    monkeypatch.setattr(win.loader, "load", slow_load)

    results: list[object] = []
    threads = [threading.Thread(target=lambda: results.append(win._load()))
               for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(calls) == 1
    assert len(results) == 8 and all(r is not None for r in results)
    assert len({id(r) for r in results}) == 1


def test_missing_export_refuses_the_whole_library(monkeypatch, warnings):
    class Partial:
        def __getattr__(self, name):
            if name == "aw_reg_free":
                raise AttributeError(name)
            return type("Fn", (), {})()

    monkeypatch.setattr(win, "_lib", None)
    monkeypatch.setattr(win, "_tried", False)
    monkeypatch.setattr(win.loader, "load", lambda *a: Partial())
    assert win._load() is None
    assert warnings


def test_absent_engine_returns_documented_empties(monkeypatch):
    monkeypatch.setattr(win, "_lib", None)
    monkeypatch.setattr(win, "_tried", True)
    assert win.enum_processes() == []
    assert win.enum_handles() == []
    assert win.memory_map(4) is None
    assert win.find_handles_by_name(r"\Device\x", {4}) is None
    assert win.enum_connections() is None
    assert win.reg_snapshot("HKLM", "SOFTWARE") is None
    assert win.enable_privilege("SeDebugPrivilege") is None
    assert win.handle_process_target(win.HandleEntry(1, 2, 3, 4, 5, 6)) == 0


# --- handles ---------------------------------------------------------------


def test_find_handles_empty_pid_set_never_widens(fake):
    fake.aw_find_handles_by_name = lambda *a: pytest.fail("engine must not be called")
    assert win.find_handles_by_name(r"\Device\x", set()) == []


def test_find_handles_engine_error_is_not_an_empty_answer(fake):
    # Regression: an engine failure used to come back as [], which a caller
    # reads as "nothing holds this file" instead of falling back.
    fake.aw_find_handles_by_name = lambda *a: win.ERR_TIMEOUT
    assert win.find_handles_by_name(r"\Device\x", {4}) is None


def test_find_handles_passes_sorted_pids_and_decodes_rows(fake):
    seen = {}

    def call(target, pid_arr, pid_count, buf, cap, timeout):
        seen["pids"] = [pid_arr[i] for i in range(pid_count)]
        seen["target"] = target
        buf[0].pid, buf[0].handle, buf[0].type_index = 812, 0x1A4, 37
        return 1

    fake.aw_find_handles_by_name = call
    rows = win.find_handles_by_name(r"\Device\HarddiskVolume3\f.txt", {900, 812, 4})
    assert seen == {"pids": [4, 812, 900], "target": r"\Device\HarddiskVolume3\f.txt"}
    assert rows == [win.HandleEntry(812, 0x1A4, 0, 0, 0, 37)]


# --- registry blob ---------------------------------------------------------


def _key(path, values):
    raw_path = path.encode("utf-16-le")
    out = struct.pack("<II", len(raw_path), len(values)) + raw_path
    for name, vtype, data in values:
        raw_name = name.encode("utf-16-le")
        out += struct.pack("<III", len(raw_name), vtype, len(data)) + raw_name + data
    return out


_BLOB = (_key("SOFTWARE\\Vendor", [("Path", 1, "C:\\x\0".encode("utf-16-le")),
                                   ("Count", 4, (7).to_bytes(4, "little"))])
         + _key("SOFTWARE\\Vendor\\Empty", []))


def test_decode_reg_blob_round_trips():
    assert win._decode_reg_blob(_BLOB) == {
        "SOFTWARE\\Vendor": {"Path": ("C:\\x", 1), "Count": (7, 4)},
        "SOFTWARE\\Vendor\\Empty": {},
    }


@pytest.mark.parametrize("cut", [1, 5, 9, 20, len(_BLOB) - 1])
def test_decode_reg_blob_rejects_truncation(cut):
    # Half-decoding would diff as phantom "removed" keys; refuse instead.
    assert win._decode_reg_blob(_BLOB[:-cut]) is None


def test_decode_reg_blob_rejects_trailing_garbage():
    assert win._decode_reg_blob(_BLOB + b"\x01\x02") is None


def test_decode_reg_blob_rejects_oversized_lengths():
    bad = struct.pack("<II", 0xFFFFFF00, 0) + b"ab"
    assert win._decode_reg_blob(bad) is None


def _attach_blob(fake, blob, freed):
    arr = (ctypes.c_uint8 * len(blob)).from_buffer_copy(blob)
    fake._keepalive = arr

    def snap(hive, subkey, depth, ref):
        src = ctypes.cast(arr, ctypes.POINTER(ctypes.c_uint8))
        ctypes.memmove(ctypes.addressof(ref._obj), ctypes.addressof(src),
                       ctypes.sizeof(src))
        return len(blob)

    fake.aw_reg_snapshot = snap
    fake.aw_reg_free = lambda p: freed.append(1)


def test_reg_snapshot_decodes_and_frees_the_engine_buffer(fake):
    freed: list[int] = []
    _attach_blob(fake, _BLOB, freed)
    out = win.reg_snapshot("hklm", "SOFTWARE")
    assert out is not None and out["SOFTWARE\\Vendor"]["Count"] == (7, 4)
    assert freed == [1]


def test_reg_snapshot_malformed_falls_back(fake, warnings):
    freed: list[int] = []
    _attach_blob(fake, _BLOB[:-3], freed)
    assert win.reg_snapshot("HKLM", "SOFTWARE") is None
    assert freed == [1] and warnings


def test_reg_snapshot_unknown_hive_is_none(fake):
    fake.aw_reg_snapshot = lambda *a: pytest.fail("engine must not be called")
    assert win.reg_snapshot("HKXX", "SOFTWARE") is None


# --- services --------------------------------------------------------------


def test_absent_start_value_maps_to_unknown_not_boot(fake):
    def call(buf, cap):
        buf[0].name = "Weird"
        buf[0].start_type = win.VALUE_ABSENT
        buf[1].name = "BootDrv"
        buf[1].start_type = 0
        return 2

    fake.aw_enum_driver_services = call
    weird, boot = win.enum_driver_services()
    assert weird.start_type == -1 and weird.start_label == "unknown"
    assert boot.start_label == "boot"


# --- sockets ---------------------------------------------------------------


def _addr(family, text):
    af = socket.AF_INET if family == 4 else socket.AF_INET6
    raw = socket.inet_pton(af, text)
    return (ctypes.c_uint8 * 16)(*raw.ljust(16, b"\0"))


def test_connections_are_formatted_like_psutil(fake):
    def call(buf, cap):
        rows = [
            (4, 6, "10.0.0.5", 50000, "93.184.216.34", 443, 5),   # TCP established
            (4, 6, "0.0.0.0", 135, "0.0.0.0", 0, 2),              # TCP listen
            (4, 17, "0.0.0.0", 5353, "1.2.3.4", 99, 0),           # UDP: no peer
            (6, 6, "::1", 8080, "::1", 51000, 5),                 # TCP v6
        ]
        for i, (fam, proto, la, lp, ra, rp, st) in enumerate(rows):
            c = buf[i]
            c.pid, c.family, c.proto, c.state = 100 + i, fam, proto, st
            c.local_addr, c.local_port = _addr(fam, la), lp
            c.remote_addr, c.remote_port = _addr(fam, ra), rp
        return len(rows)

    fake.aw_enum_connections = call
    est, listen, udp, v6 = win.enum_connections()
    assert (est.proto, est.laddr, est.raddr, est.rport) == ("TCP", "10.0.0.5", "93.184.216.34", 443)
    assert win.tcp_state_label(est.state) == "ESTABLISHED"
    assert (listen.raddr, listen.rport) == ("", 0)
    assert (udp.proto, udp.raddr, udp.rport) == ("UDP", "", 0)
    assert (v6.laddr, v6.raddr, v6.rport) == ("::1", "::1", 51000)
    assert win.tcp_state_label(0) == "NONE"


# --- small mappings --------------------------------------------------------


def test_verify_signature_maps_errors_to_none(fake):
    fake.aw_verify_signature = lambda p: win.ERR_INVALID
    assert win.verify_signature(r"C:\x.exe") is None
    fake.aw_verify_signature = lambda p: win.SIG_CATALOG
    assert win.verify_signature(r"C:\x.exe") == win.SIG_CATALOG
    assert win.verify_signature("") is None


@pytest.mark.parametrize("rc,ok,fragment", [
    (0, True, "enabled"),
    (1, False, "not held"),
    (win.ERR_INVALID, False, "invalid"),
    (win.ERR_DENIED, False, "failed"),
])
def test_enable_privilege_messages(fake, rc, ok, fragment):
    fake.aw_enable_privilege = lambda name: rc
    got_ok, msg = win.enable_privilege("SeDebugPrivilege")
    assert got_ok is ok and fragment in msg


def test_memory_map_refusal_is_none_not_empty(fake):
    fake.aw_memory_map = lambda pid, buf, cap: win.ERR_DENIED
    assert win.memory_map(4) is None


def test_read_memory_returns_short_reads(fake):
    def call(pid, addr, buf, size):
        buf[0], buf[1] = 0x4D, 0x5A
        return 2
    fake.aw_read_memory = call
    assert win.read_memory(4, 0x1000, 64) == b"MZ"
    assert win.read_memory(4, 0x1000, 0) is None
