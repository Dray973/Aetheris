"""ETW per-process bandwidth sampler — interface + graceful lifecycle.

Windows-only. Constructing the sampler attempts a real ETW session; without an
elevated token that fails cleanly (available=False), which is what CI exercises.
On an elevated dev box it starts and is immediately stopped here.
"""
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")

from aetheris.network import etwbw, connections  # noqa: E402


def test_sampler_interface_and_lifecycle():
    s = etwbw.EtwBandwidth()
    try:
        assert isinstance(s.available, bool)
        assert isinstance(s.status, str) and s.status
        rates = s.sample()
        assert isinstance(rates, dict)
        # sample() never raises whether or not the session is live.
        for pid, rate in rates.items():
            assert isinstance(pid, int)
            assert len(rate) == 2
    finally:
        s.stop()
    # stop() is idempotent.
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
