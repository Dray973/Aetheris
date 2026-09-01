"""ETW per-process bandwidth sampler — interface + graceful lifecycle.

Windows-only. Constructing the sampler attempts a real ETW session; without an
elevated token that fails cleanly (available=False), which is what CI exercises.
On an elevated dev box it starts and is immediately stopped here.
"""
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")

from aetheris.network import connections, etwbw


def test_sampler_interface_and_lifecycle():
    s = etwbw.EtwBandwidth()
    try:
        assert isinstance(s.available, bool)
        assert isinstance(s.status, str) and s.status
        rates = s.sample()
        assert isinstance(rates, dict)
        for pid, rate in rates.items():
            assert isinstance(pid, int)
            assert len(rate) == 2
    finally:
        s.stop()
    s.stop()


def test_struct_sizes_match_x64_abi():
    import ctypes
    assert ctypes.sizeof(etwbw.EVENT_RECORD) == 112
    assert ctypes.sizeof(etwbw._EVENT_HEADER) == 80
    assert ctypes.sizeof(etwbw.EVENT_TRACE_PROPERTIES) == 120
    assert ctypes.sizeof(etwbw.EVENT_TRACE_LOGFILEW) == 448


def test_per_process_sampler_selection_exposes_contract():
    s = connections.per_process_bandwidth_sampler()
    try:
        assert hasattr(s, "available") and hasattr(s, "status")
        assert isinstance(s.sample(), dict)
    finally:
        if hasattr(s, "stop"):
            s.stop()


def test_on_event_attributes_tcpip_opcodes_to_pid():
    """Deterministic: inject synthetic classic-TcpIp EVENT_RECORDs and prove the
    callback keys send/recv off the EVENT *opcode* (10/11/26/27) and reads
    (PID, size) from the payload head -- the exact fix, no elevation/network."""
    import ctypes
    import struct

    s = etwbw.EtwBandwidth()
    s.stop()
    with s._lock:
        s._totals.clear()
    sentinel = 0x00BEEF01
    held = []

    def inject(opcode: int, size: int) -> None:
        payload = struct.pack("<II", sentinel, size) + b"\x00" * 16
        bufc = ctypes.create_string_buffer(payload, len(payload))
        held.append(bufc)
        rec = etwbw.EVENT_RECORD()
        rec.EventHeader.EventDescriptor.Opcode = opcode
        rec.UserData = ctypes.cast(bufc, ctypes.c_void_p)
        rec.UserDataLength = len(payload)
        s._on_event(ctypes.pointer(rec))

    inject(10, 1500)
    inject(26, 500)
    inject(11, 4096)
    inject(12, 9999)
    sent, recv = s._totals[sentinel]
    assert sent == 1500 + 500
    assert recv == 4096


def test_live_capture_attributes_bytes_when_elevated():
    """When a real session starts (elevated) and external TCP flows, the sampler
    attributes bytes to PIDs. Skips cleanly when not elevated or the network is
    restricted, so CI never flakes."""
    import socket
    import threading
    import time

    s = etwbw.EtwBandwidth()
    try:
        if not s.available:
            pytest.skip("ETW system-logger session unavailable (needs elevation)")

        def net() -> None:
            for host in ("1.1.1.1", "8.8.8.8"):
                for port in (443, 80):
                    try:
                        c = socket.create_connection((host, port), timeout=1.5)
                        c.sendall(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
                        c.recv(2048)
                        c.close()
                    except OSError:
                        pass

        deadline = time.time() + 8
        while time.time() < deadline and not s._totals:
            threading.Thread(target=net, daemon=True).start()
            time.sleep(1.2)
        if not s._totals:
            pytest.skip("no external TCP events captured (restricted network?)")

        rates = s.sample()
        assert isinstance(rates, dict)
        for pid, rate in rates.items():
            assert isinstance(pid, int)
            up, down = rate
            assert up >= 0 and down >= 0
    finally:
        s.stop()
