"""
Real-time connection interceptor.

Maps every socket to its owning process (pid → name → exe path) using psutil's
net_connections (backed by the IP Helper API on Windows). Adds optional reverse
DNS for remote endpoints and a system-wide bandwidth sampler.

Notes:
  * System-wide throughput comes from psutil.net_io_counters (BandwidthSampler).
  * True per-process B/s is provided by ``per_process_bandwidth_sampler``: it
    prefers the ETW Kernel-Network consumer (aetheris.network.etwbw — works on
    client Windows) and falls back to IP-Helper EStats (aetheris.network.procbw).
    Both need an elevated token; the sampler reports ``available`` / ``status``.
  * Geolocation is offline-only: address-range classification here, plus optional
    country/city from a local MaxMind GeoLite2 DB (see aetheris.network.geoip).
    We never call external APIs.
"""
from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass

import psutil

SRC = "network.connections"


@dataclass
class Connection:
    pid: int | None
    proc_name: str
    laddr: str
    lport: int
    raddr: str
    rport: int
    status: str
    family: str
    kind: str
    remote_class: str = ""   # loopback / private / reserved / public
    rdns: str = ""
    geo: str = ""            # e.g. "US · Ashburn" when a GeoLite2 DB is present


def _classify(ip: str) -> str:
    if not ip:
        return ""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    if addr.is_loopback:
        return "loopback"
    if addr.is_private:
        return "private"
    if addr.is_reserved or addr.is_link_local:
        return "reserved"
    return "public"


def snapshot(resolve_dns: bool = False, resolve_geo: bool = True) -> list[Connection]:
    """Return current sockets mapped to their owning processes."""
    conns: list[Connection] = []
    name_cache: dict[int, str] = {}
    geo = None
    if resolve_geo:
        from .geoip import get_resolver
        r = get_resolver()
        geo = r if r.available else None
    for c in psutil.net_connections(kind="inet"):
        pid = c.pid
        name = "?"
        if pid is not None:
            if pid not in name_cache:
                try:
                    name_cache[pid] = psutil.Process(pid).name()
                except Exception:
                    name_cache[pid] = "?"
            name = name_cache[pid]
        laddr = c.laddr.ip if c.laddr else ""
        lport = c.laddr.port if c.laddr else 0
        raddr = c.raddr.ip if c.raddr else ""
        rport = c.raddr.port if c.raddr else 0
        conn = Connection(
            pid=pid, proc_name=name,
            laddr=laddr, lport=lport, raddr=raddr, rport=rport,
            status=c.status,
            family="IPv6" if c.family == socket.AF_INET6 else "IPv4",
            kind="TCP" if c.type == socket.SOCK_STREAM else "UDP",
            remote_class=_classify(raddr),
        )
        if raddr and conn.remote_class == "public":
            if resolve_dns:
                try:
                    conn.rdns = socket.gethostbyaddr(raddr)[0]
                except Exception:
                    conn.rdns = ""
            if geo is not None:
                conn.geo = geo.lookup_str(raddr)
        conns.append(conn)
    return conns


class BandwidthSampler:
    """System-wide throughput sampler (bytes/sec) between successive polls."""

    def __init__(self) -> None:
        self._last = psutil.net_io_counters()
        self._t = time.monotonic()

    def sample(self) -> tuple[float, float]:
        now = psutil.net_io_counters()
        t = time.monotonic()
        dt = max(t - self._t, 1e-6)
        up = (now.bytes_sent - self._last.bytes_sent) / dt
        down = (now.bytes_recv - self._last.bytes_recv) / dt
        self._last, self._t = now, t
        return up, down


def per_process_bandwidth_sampler():
    """
    Build a per-process bandwidth sampler exposing ``.available``, ``.status`` and
    ``.sample() -> {pid: (up_Bps, down_Bps)}``.

    Prefers the ETW Kernel-Network consumer (works on client Windows, including
    builds where EStats is gated); falls back to the IP-Helper EStats sampler.
    Both need an elevated token.
    """
    try:
        from .etwbw import EtwBandwidth
        etw = EtwBandwidth()
        if etw.available:
            return etw
        etw.stop()
    except Exception:  # noqa: BLE001
        pass
    from .procbw import PerProcessBandwidth
    return PerProcessBandwidth()
