"""
Per-process TCP bandwidth via the IP Helper API.

Two native pieces:
  * GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL) — the authoritative
    connection -> owning-PID map (no psutil, no guesswork).
  * Get/SetPerTcpConnectionEStats — per-connection cumulative byte counters.
    EStats collection must be enabled per connection, which requires an elevated
    token; when that isn't available the sampler reports ``available=False`` and
    yields nothing rather than guessing.

``PerProcessBandwidth.sample()`` returns ``{pid: (up_bytes_per_s, down_bytes_per_s)}``.
The pure delta/attribution math lives in ``aggregate()`` so it can be unit-tested
without an elevated session or live traffic.
"""
from __future__ import annotations

import ctypes
import socket
import time
from ctypes import wintypes

from ..core import logbus
from ..core import winapi as W

SRC = "network.procbw"

AF_INET = 2
TCP_TABLE_OWNER_PID_ALL = 5
TcpConnectionEstatsData = 0
ERROR_INSUFFICIENT_BUFFER = 122

ConnKey = tuple  # (laddr, lport, raddr, rport)


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


class MIB_TCPROW(ctypes.Structure):
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
    ]


class TCP_ESTATS_DATA_RW_v0(ctypes.Structure):
    _fields_ = [("EnableCollection", ctypes.c_ubyte)]


class TCP_ESTATS_DATA_ROD_v0(ctypes.Structure):
    # Only the leading fields we need are named; the rest is padding.
    _fields_ = [
        ("DataBytesOut", ctypes.c_uint64),
        ("DataSegsOut", ctypes.c_uint64),
        ("DataBytesIn", ctypes.c_uint64),
        ("DataSegsIn", ctypes.c_uint64),
        ("_rest", ctypes.c_ubyte * 96),
    ]


def _fmt_addr(dw: int) -> str:
    return socket.inet_ntoa(dw.to_bytes(4, "little"))


def _port(dw: int) -> int:
    return socket.ntohs(dw & 0xFFFF)


def tcp_table() -> list[tuple[ConnKey, int, MIB_TCPROW_OWNER_PID]]:
    """Return [(conn_key, pid, raw_row), …] from GetExtendedTcpTable (IPv4)."""
    if not W.IS_WINDOWS:
        return []
    size = wintypes.DWORD(0)
    W.iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, AF_INET,
                                   TCP_TABLE_OWNER_PID_ALL, 0)
    buf = ctypes.create_string_buffer(size.value)
    if W.iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), False, AF_INET,
                                      TCP_TABLE_OWNER_PID_ALL, 0) != 0:
        return []
    n = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD))[0]
    arr = ctypes.cast(ctypes.byref(buf, ctypes.sizeof(wintypes.DWORD)),
                      ctypes.POINTER(MIB_TCPROW_OWNER_PID * n))[0]
    out = []
    for row in arr:
        key = (_fmt_addr(row.dwLocalAddr), _port(row.dwLocalPort),
               _fmt_addr(row.dwRemoteAddr), _port(row.dwRemotePort))
        # Copy the row into a standalone struct (buf is freed on return).
        out.append((key, int(row.dwOwningPid),
                    MIB_TCPROW_OWNER_PID.from_buffer_copy(row)))
    return out


def aggregate(prev: dict, cur: dict, owners: dict, dt: float) -> dict[int, tuple[float, float]]:
    """
    Pure attribution: given previous and current per-connection (out,in) byte
    counters, the connection->pid map, and elapsed seconds, return per-pid
    (up_bytes_per_s, down_bytes_per_s). Missing/rolled-back counters clamp to 0.
    """
    dt = max(dt, 1e-6)
    res: dict[int, tuple[float, float]] = {}
    for key, (o, i) in cur.items():
        po, pi = prev.get(key, (o, i))
        d_out = max(o - po, 0)
        d_in = max(i - pi, 0)
        pid = owners.get(key)
        if pid is None:
            continue
        up, down = res.get(pid, (0.0, 0.0))
        res[pid] = (up + d_out / dt, down + d_in / dt)
    return res


class PerProcessBandwidth:
    """Sampler that attributes per-connection EStats byte deltas to PIDs."""

    def __init__(self) -> None:
        self.available = False
        self.status = "not initialized"
        self._prev: dict[ConnKey, tuple[int, int]] = {}
        self._t = time.monotonic()
        if W.IS_WINDOWS:
            self._prime()

    def _enable(self, row: MIB_TCPROW_OWNER_PID) -> bool:
        mib = MIB_TCPROW(row.dwState, row.dwLocalAddr, row.dwLocalPort,
                         row.dwRemoteAddr, row.dwRemotePort)
        rw = TCP_ESTATS_DATA_RW_v0(1)
        rc = W.iphlpapi.SetPerTcpConnectionEStats(
            ctypes.byref(mib), TcpConnectionEstatsData,
            ctypes.byref(rw), 0, ctypes.sizeof(rw), 0)
        return rc == 0

    def _read(self, row: MIB_TCPROW_OWNER_PID) -> tuple[int, int] | None:
        mib = MIB_TCPROW(row.dwState, row.dwLocalAddr, row.dwLocalPort,
                         row.dwRemoteAddr, row.dwRemotePort)
        rod = TCP_ESTATS_DATA_ROD_v0()
        rc = W.iphlpapi.GetPerTcpConnectionEStats(
            ctypes.byref(mib), TcpConnectionEstatsData,
            None, 0, 0, None, 0, 0,
            ctypes.byref(rod), 0, ctypes.sizeof(rod))
        if rc != 0:
            return None
        return int(rod.DataBytesOut), int(rod.DataBytesIn)

    def _prime(self) -> None:
        established = enabled = 0
        last_rc = None
        snap: dict[ConnKey, tuple[int, int]] = {}
        for key, _pid, row in tcp_table():
            if row.dwState != 5:                 # MIB_TCP_STATE_ESTAB
                continue
            established += 1
            mib = MIB_TCPROW(row.dwState, row.dwLocalAddr, row.dwLocalPort,
                             row.dwRemoteAddr, row.dwRemotePort)
            rw = TCP_ESTATS_DATA_RW_v0(1)
            last_rc = W.iphlpapi.SetPerTcpConnectionEStats(
                ctypes.byref(mib), TcpConnectionEstatsData,
                ctypes.byref(rw), 0, ctypes.sizeof(rw), 0)
            if last_rc == 0:
                enabled += 1
                data = self._read(row)
                if data:
                    snap[key] = data
        self._prev = snap
        self._t = time.monotonic()
        self.available = enabled > 0
        if self.available:
            self.status = f"EStats collecting on {enabled}/{established} connections"
        elif not W.IS_WINDOWS:
            self.status = "not Windows"
        elif established == 0:
            self.status = "no established TCP connections to sample"
        else:
            self.status = (f"EStats enable unavailable on this system "
                           f"(SetPerTcpConnectionEStats rc={last_rc})")
        logbus.trace(SRC, self.status)

    def sample(self) -> dict[int, tuple[float, float]]:
        """Return {pid: (up_Bps, down_Bps)} since the previous sample."""
        if not self.available:
            return {}
        cur: dict[ConnKey, tuple[int, int]] = {}
        owners: dict[ConnKey, int] = {}
        for key, pid, row in tcp_table():
            owners[key] = pid
            data = self._read(row)
            if data is None:                      # newly seen conn: enable + seed
                if self._enable(row):
                    data = self._read(row)
            if data is not None:
                cur[key] = data
        now = time.monotonic()
        result = aggregate(self._prev, cur, owners, now - self._t)
        self._prev = cur
        self._t = now
        return result


if W.IS_WINDOWS:
    W.iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
    W.iphlpapi.GetExtendedTcpTable.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
        wintypes.ULONG, ctypes.c_int, wintypes.ULONG]
    W.iphlpapi.GetExtendedTcpTable.restype = wintypes.DWORD
    W.iphlpapi.SetPerTcpConnectionEStats.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
        wintypes.ULONG, wintypes.ULONG, wintypes.ULONG]
    W.iphlpapi.SetPerTcpConnectionEStats.restype = wintypes.ULONG
    W.iphlpapi.GetPerTcpConnectionEStats.argtypes = [
        ctypes.c_void_p, ctypes.c_int,
        ctypes.c_void_p, wintypes.ULONG, wintypes.ULONG,
        ctypes.c_void_p, wintypes.ULONG, wintypes.ULONG,
        ctypes.c_void_p, wintypes.ULONG, wintypes.ULONG]
    W.iphlpapi.GetPerTcpConnectionEStats.restype = wintypes.ULONG
