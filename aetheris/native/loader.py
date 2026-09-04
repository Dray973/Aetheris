"""
Shared discovery and loading for the native engines.

Search order matches the other optional engines in the suite:

  1. ``$AETHERIS_<NAME>_DLL`` (explicit path)
  2. next to / inside a frozen exe (PyInstaller bundles them)
  3. the repo's ``dist/`` (a local ``native/*/build.ps1`` run)

A loaded library must agree on an ABI version. Each engine exports a
``*_abi_version`` function; if the value is not one this host understands, the
library is refused and the caller falls back to Python. That is what makes a
stale DLL left in ``dist/`` safe: the structs it returns would be misread, so
we would rather not call it at all.
"""
from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path

from ..core import logbus

SRC = "native.loader"

#: ABI versions this host knows how to talk to, per library. A version is
#: listed only while this host can still bind every symbol it expects from it,
#: so dropping an old entry is how a stale DLL gets refused rather than
#: half-bound.
SUPPORTED_ABI: dict[str, tuple[int, ...]] = {
    "aetheris_core": (2,),
    "aetheris_win": (4,),
}

_cache: dict[str, ctypes.CDLL | None] = {}


def library_path(name: str) -> Path | None:
    """Locate ``<name>.dll``, or None if no candidate exists."""
    override = os.environ.get(f"AETHERIS_{name.upper()}_DLL")
    if override and Path(override).is_file():
        return Path(override)
    filename = f"{name}.dll"
    candidates: list[Path] = []
    if getattr(sys, "frozen", False):
        candidates.append(Path(sys.executable).with_name(filename))
        meipass = getattr(sys, "_MEIPASS", "")
        if meipass:
            candidates.append(Path(meipass) / filename)
    candidates.append(Path(__file__).resolve().parents[2] / "dist" / filename)
    for c in candidates:
        if c.is_file():
            return c
    return None


def load(name: str, abi_symbol: str | None = None) -> ctypes.CDLL | None:
    """
    Load a native engine once and cache the result (including the failure).

    ``abi_symbol`` defaults to ``<name>_abi_version``-style discovery: the Rust
    core exports ``aetheris_abi_version`` and the C++ engine ``aw_abi_version``,
    so callers pass the symbol explicitly rather than guessing.
    """
    if name in _cache:
        return _cache[name]
    _cache[name] = None  # cache the failure too; do not retry per call

    path = library_path(name)
    if path is None:
        logbus.trace(SRC, f"{name}.dll not present; using Python fallback")
        return None
    try:
        lib = ctypes.CDLL(str(path))
    except OSError as exc:
        logbus.warn(SRC, f"{name}.dll failed to load", str(exc))
        return None

    if abi_symbol:
        try:
            fn = getattr(lib, abi_symbol)
            fn.restype = ctypes.c_uint32
            fn.argtypes = []
            got = int(fn())
        except Exception as exc:  # noqa: BLE001 - a DLL without the symbol is stale
            logbus.warn(SRC, f"{name}.dll has no {abi_symbol}; refusing it", str(exc))
            return None
        want = SUPPORTED_ABI.get(name, ())
        if got not in want:
            logbus.warn(SRC, f"{name}.dll ABI {got} unsupported (want {want}); "
                             "using Python fallback")
            return None

    _cache[name] = lib
    logbus.trace(SRC, f"{name}.dll loaded", str(path))
    return lib


def reset() -> None:
    """Drop the load cache. For tests that manipulate the environment."""
    _cache.clear()
