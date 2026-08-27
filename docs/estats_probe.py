#!/usr/bin/env python3
"""
Standalone EStats per-process bandwidth probe.

Run this on any Windows box (ELEVATED) to check whether TCP EStats collection
can be enabled there — the one environment-gated piece of the network module.
On a build where the enable call succeeds (e.g. Windows Server), it prints live
per-process byte rates.

    python docs/estats_probe.py            # sample once after 2 s
    python docs/estats_probe.py --secs 3   # gap between the two samples

Expected on a gated client build: available=False, status shows rc=1784.
Expected where EStats works: available=True, and PIDs with active traffic show
nonzero up/down.
"""
from __future__ import annotations

import sys
import time
import argparse
import ctypes
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aetheris.network import procbw                       # noqa: E402
from aetheris.core import privileges                      # noqa: E402


def _fmt(bps: float) -> str:
    for u in ("B/s", "KB/s", "MB/s"):
        if bps < 1024 or u == "MB/s":
            return f"{bps:,.1f} {u}"
        bps /= 1024
    return f"{bps:.1f} MB/s"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--secs", type=float, default=2.0)
    args = ap.parse_args()

    if sys.platform != "win32":
        print("Windows only.")
        return 2

    elevated = privileges.is_elevated()
    admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    print(f"elevated: {elevated} (IsUserAnAdmin={admin})")
    print(f"active TCP connections: {len(procbw.tcp_table())}")

    s = procbw.PerProcessBandwidth()
    print(f"EStats available: {s.available}")
    print(f"status: {s.status}")

    if not s.available:
        print("\nEStats enable is gated on this build/session.")
        print("Re-run elevated, or on a Windows Server / older client build.")
        print("(GetPerTcpConnectionEStats works here; only Set is gated — "
              "the app reports exactly this in the Network tab.)")
        return 1

    print(f"\nSampling per-process bandwidth over {args.secs:g}s "
          f"(generate some traffic — a download or video helps)…")
    s.sample()                       # prime
    time.sleep(args.secs)
    rates = s.sample()
    active = {pid: (up, down) for pid, (up, down) in rates.items() if up or down}
    if not active:
        print("No per-process traffic observed in the window.")
        return 0
    print(f"\n{'PID':>8}   {'up':>12}   {'down':>12}")
    for pid, (up, down) in sorted(active.items(), key=lambda kv: -sum(kv[1])):
        print(f"{pid:>8}   {_fmt(up):>12}   {_fmt(down):>12}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
