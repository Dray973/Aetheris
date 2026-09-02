"""
Native scan helpers — entropy scoring + byte-pattern search, with a pure-Python
fallback.

An optional **Rust** cdylib (``native/entropy_rs`` → ``dist/aetheris_scan.dll``)
accelerates the hot byte-crunching used by the injection / YARA / threat-hunt
analysis — Shannon entropy (a packed/encrypted-region tell) and fast memmem.
When the library isn't present everything still works via the pure-Python
fallback (slower), so this is a speed-up, never a hard dependency. The native
side is memory-safe by construction and panic-guarded across the FFI boundary.
"""
from __future__ import annotations

import ctypes
import math
import os
import sys
from pathlib import Path

from ..core import logbus

SRC = "forensics.nativescan"
LIB = "aetheris_scan.dll"


def _lib_path() -> Path | None:
    override = os.environ.get("AETHERIS_SCAN_DLL")
    if override and Path(override).is_file():
        return Path(override)
    candidates: list[Path] = []
    if getattr(sys, "frozen", False):
        candidates.append(Path(sys.executable).with_name(LIB))
        meipass = getattr(sys, "_MEIPASS", "")
        if meipass:
            candidates.append(Path(meipass) / LIB)
    candidates.append(Path(__file__).resolve().parents[2] / "dist" / LIB)
    for c in candidates:
        if c.is_file():
            return c
    return None


_lib: ctypes.CDLL | None = None
_tried = False


def _load() -> ctypes.CDLL | None:
    global _lib, _tried
    if _tried:
        return _lib
    _tried = True
    path = _lib_path()
    if path is None:
        return None
    try:
        lib = ctypes.CDLL(str(path))
        lib.aetheris_entropy.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        lib.aetheris_entropy.restype = ctypes.c_double
        lib.aetheris_max_window_entropy.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                                    ctypes.c_size_t]
        lib.aetheris_max_window_entropy.restype = ctypes.c_double
        lib.aetheris_find.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                      ctypes.c_void_p, ctypes.c_size_t]
        lib.aetheris_find.restype = ctypes.c_ssize_t
        _lib = lib
        logbus.trace(SRC, f"native scan lib loaded: {path}")
    except OSError as exc:
        logbus.warn(SRC, "native scan lib failed to load", str(exc))
        _lib = None
    return _lib


def available() -> bool:
    """True when the native (Rust) acceleration is loaded."""
    return _load() is not None


# ---- pure-Python fallbacks -------------------------------------------------
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


def _py_max_window(data: bytes, window: int) -> float:
    if not data:
        return 0.0
    w = window or len(data)
    mx = 0.0
    for i in range(0, len(data), w):
        e = _py_entropy(data[i:i + w])
        if e > mx:
            mx = e
    return mx


# ---- public API (native when available, else fallback) ---------------------
def entropy(data: bytes) -> float:
    """Shannon entropy of ``data`` in bits/byte (0.0..8.0)."""
    lib = _load()
    if lib is None or not data:
        return _py_entropy(data)
    buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
    return float(lib.aetheris_entropy(buf, len(data)))


def max_window_entropy(data: bytes, window: int = 256) -> float:
    """Highest entropy over ``window``-byte tiles — catches a high-entropy blob
    hiding inside an otherwise low-entropy buffer."""
    lib = _load()
    if lib is None or not data:
        return _py_max_window(data, window)
    buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
    return float(lib.aetheris_max_window_entropy(buf, len(data), window))


def find(data: bytes, pattern: bytes) -> int:
    """First offset of ``pattern`` in ``data``, or -1."""
    if not pattern or len(pattern) > len(data):
        return -1
    lib = _load()
    if lib is None:
        return data.find(pattern)
    b = (ctypes.c_char * len(data)).from_buffer_copy(data)
    p = (ctypes.c_char * len(pattern)).from_buffer_copy(pattern)
    return int(lib.aetheris_find(b, len(data), p, len(pattern)))
