#!/usr/bin/env python3
"""
Native-vs-Python benchmark for every path the engines took over.

    python native\\bench.py            # everything
    python native\\bench.py handles    # only matching rows

Not a test. These numbers move with the machine, the load, and what the
registry happens to contain, so asserting on them in CI would produce flaky
failures. The point is to make a regression *visible*, and to keep the honest
numbers somewhere other than a commit message -- including the ones where
native loses.

That last part matters. Three ports during this migration were proposed on a
predicted speed-up that measurement did not support, and one (autoruns) turned
out to be 2.8x slower because the FFI overhead dominates when there is almost
no work to do. A ratio below 1.0 here is a finding, not a failure.

Every row times the same operation twice: once as shipped, once with the
native path forced off, so both halves run against identical inputs.
"""
from __future__ import annotations

import os
import statistics
import sys
import time
from collections.abc import Callable
from contextlib import contextmanager

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aetheris.native import core, win  # noqa: E402

REPEATS = 5


@contextmanager
def disabled(module, *names):
    """Force the Python fallback by blanking the engine entry points."""
    saved = {n: getattr(module, n) for n in names}
    for n in names:
        setattr(module, n, lambda *a, **k: None)
    try:
        yield
    finally:
        for n, v in saved.items():
            setattr(module, n, v)


def _best(fn: Callable[[], object]) -> float:
    """Best of REPEATS, in ms. Best rather than mean: we want the machine's
    capability, not its current background noise."""
    times = []
    for _ in range(REPEATS):
        t = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t) * 1000)
    return min(times)


ROWS: list[tuple[str, str, Callable[[], float], Callable[[], float]]] = []


def bench(name: str, unit: str):
    """Register a benchmark: the decorated function returns (native, python)."""
    def wrap(fn):
        ROWS.append((name, unit, fn, None))
        return fn
    return wrap


# --- Rust core --------------------------------------------------------------


@bench("entropy (8 MB)", "")
def _entropy():
    data = os.urandom(8 << 20)
    n = _best(lambda: core.entropy(data))
    with disabled(core, "_load"):
        p = _best(lambda: core.entropy(data))
    return n, p


@bench("byte search (8 MB)", "Python wins: two-way search")
def _find():
    # Compares the raw engine export against bytes.find, which is why this row
    # exists at all: it is the measurement that made core.find stop preferring
    # the native path. Not routed through core.find, since that now always
    # takes the Python route.
    data = os.urandom(8 << 20)
    needle = data[-32:]
    lib = core._load()
    if lib is None:
        return 0.0, 0.0
    n = _best(lambda: lib.aetheris_find(core._ptr(data), len(data),
                                        core._ptr(needle), len(needle)))
    return n, _best(lambda: data.find(needle))


@bench("PE carve (8 MB, 4k stride)", "")
def _carve():
    data = os.urandom(8 << 20)
    n = _best(lambda: core.pe_carve(data, 4096, 4096))
    with disabled(core, "_load"):
        p = _best(lambda: core.pe_carve(data, 4096, 4096))
    return n, p


@bench("sha256 (64 MB)", "counter-example")
def _sha():
    import hashlib
    data = os.urandom(64 << 20)
    lib = core._load()
    if lib is None:
        return 0.0, 0.0
    import ctypes
    out = (ctypes.c_ubyte * 32)()
    n = _best(lambda: lib.aetheris_sha256(core._ptr(data), len(data), out))
    p = _best(lambda: hashlib.sha256(data).digest())
    return n, p


@bench("MFT block parse (256 recs)", "")
def _mft():
    from tests.test_native_mft import synth_record  # reuse the fixture builder
    block = b"".join(synth_record(f"file{i}.dat", parent=5 + i) for i in range(256))

    def py():
        from aetheris.storage import mft
        out = []
        for i, off in enumerate(range(0, len(block) - 1024 + 1, 1024)):
            chunk = block[off:off + 1024]
            if chunk[0:4] != mft.FILE_SIGNATURE:
                continue
            buf = bytearray(chunk)
            if not mft._apply_fixups(buf, 512):
                continue
            r = mft._parse_record(bytes(buf), i)
            if r and r.name:
                out.append(r)
        return out

    n = _best(lambda: core.mft_parse_block(block, 1024, 512, 0))
    return n, _best(py)


# --- C++ Win32 engine -------------------------------------------------------


@bench("process enumeration", "")
def _procs():
    # Like-for-like: the engine returns pid, ppid, threads, name AND exe, so
    # psutil must be asked for the same. An earlier version of this row
    # compared against pid+name only and reported the native path as 12x
    # slower, which was the benchmark being wrong rather than the code.
    from aetheris.forensics.memvirt import LiveBackend
    be = LiveBackend()
    n = _best(be.list_processes)
    with disabled(win, "enum_processes"):
        p = _best(be.list_processes)
    return n, p


@bench("memory map (self)", "")
def _map():
    from aetheris.forensics.memvirt import LiveBackend
    be, pid = LiveBackend(), os.getpid()
    n = _best(lambda: be.memory_map(pid))
    with disabled(win, "memory_map"):
        p = _best(lambda: be.memory_map(pid))
    return n, p


@bench("handle table (system-wide)", "no Python equivalent")
def _handles():
    return _best(lambda: win.enum_handles(0)), 0.0


@bench("handle names (own process)", "")
def _names():
    entries = win.enum_handles(os.getpid())
    return _best(lambda: [win.handle_object_name(e) for e in entries]), 0.0


@bench("services", "")
def _services():
    from aetheris.core import services
    n = _best(lambda: services.enumerate_services(check_signature=False))
    with disabled(win, "enum_services"):
        p = _best(lambda: services.enumerate_services(check_signature=False))
    return n, p


@bench("drivers", "")
def _drivers():
    from aetheris.core import services
    n = _best(lambda: services.enumerate_drivers(check_signature=False))
    with disabled(win, "enum_driver_services"):
        p = _best(lambda: services.enumerate_drivers(check_signature=False))
    return n, p


@bench("connections", "")
def _conns():
    from aetheris.network import connections
    n = _best(lambda: connections.snapshot(resolve_geo=False))
    with disabled(win, "enum_connections"):
        p = _best(lambda: connections.snapshot(resolve_geo=False))
    return n, p


@bench("registry snapshot (~10k values)", "")
def _registry():
    from aetheris.core import registry
    args = ("HKCU", r"Software", 5)
    n = _best(lambda: registry.snapshot_tree(*args[:2], max_depth=args[2]))
    with disabled(win, "reg_snapshot"):
        p = _best(lambda: registry.snapshot_tree(*args[:2], max_depth=args[2]))
    return n, p


@bench("Authenticode (60 binaries)", "")
def _signing():
    from aetheris.core import signing
    root = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    paths = [os.path.join(root, f) for f in sorted(os.listdir(root))[:400]
             if f.lower().endswith((".exe", ".dll"))][:60]

    def run():
        signing._cache.clear()
        return [signing._verify(p) for p in paths]

    n = _best(run)
    with disabled(win, "verify_signature"):
        p = _best(run)
    signing._cache.clear()
    return n, p


@bench("autoruns (19 values)", "native loses: FFI > work")
def _autoruns():
    from aetheris.core import autoruns
    n = _best(lambda: [autoruns._read_run_values(r, s) for r, s in autoruns._RUN_KEYS])
    # The Python path is what ships here; the native column is what a port
    # would have cost. Kept as a standing reminder of why it was not done.
    nat = _best(lambda: [win.reg_snapshot(r, s, 0) for r, s in autoruns._RUN_KEYS])
    return nat, n


def main() -> int:
    if not (core.available() and win.available()):
        print("Both engines must be built: powershell -File native\\build.ps1")
        return 1
    pattern = sys.argv[1].lower() if len(sys.argv) > 1 else ""

    print(f"{'operation':34s} {'native':>10s} {'python':>10s} {'ratio':>8s}  note")
    print("-" * 78)
    ratios = []
    for name, note, fn, _ in ROWS:
        if pattern and pattern not in name.lower():
            continue
        try:
            nat, py = fn()
        except Exception as exc:  # noqa: BLE001 - a bench row must not stop the run
            print(f"{name:34s} {'—':>10s} {'—':>10s} {'—':>8s}  {type(exc).__name__}: {exc}")
            continue
        if py == 0.0:
            print(f"{name:34s} {nat:9.2f}m {'—':>10s} {'—':>8s}  {note}")
            continue
        ratio = py / nat if nat else 0.0
        ratios.append(ratio)
        flag = note or ("REGRESSION" if ratio < 1.0 else "")
        print(f"{name:34s} {nat:9.2f}m {py:9.2f}m {ratio:7.2f}x  {flag}")

    if ratios:
        print("-" * 78)
        print(f"{'median speed-up':34s} {'':>10s} {'':>10s} "
              f"{statistics.median(ratios):7.2f}x")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
