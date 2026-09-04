"""
Native scan helpers — entropy scoring + byte-pattern search.

This module is now a thin compatibility layer over :mod:`aetheris.native.core`,
which binds the Rust analysis core (``native/aetheris_core`` →
``dist/aetheris_core.dll``). That crate absorbed the original ``entropy_rs``
library and extends it with PE parsing/carving, region classification and
SHA-256; the three functions here keep their original names and behaviour so
existing callers and tests are unaffected.

As before this is a speed-up, never a hard dependency: with no DLL present
every call transparently uses the pure-Python implementation.
"""
from __future__ import annotations

from ..native import core as _core

SRC = "forensics.nativescan"

# Retained for callers that referenced them directly. The pure-Python
# implementations now live in aetheris.native.core alongside their native
# counterparts, so the two can be diffed in one place.
_py_entropy = _core._py_entropy


def _py_max_window(data: bytes, window: int) -> float:
    """Pure-Python maximum windowed entropy (the native path's reference)."""
    if not data:
        return 0.0
    w = window or len(data)
    return max((_py_entropy(data[i:i + w]) for i in range(0, len(data), w)), default=0.0)


def available() -> bool:
    """True when the native (Rust) acceleration is loaded."""
    return _core.available()


def entropy(data: bytes) -> float:
    """Shannon entropy of ``data`` in bits/byte (0.0..8.0)."""
    return _core.entropy(data)


def max_window_entropy(data: bytes, window: int = 256) -> float:
    """Highest entropy over ``window``-byte tiles — catches a high-entropy blob
    hiding inside an otherwise low-entropy buffer."""
    return _core.max_window_entropy(data, window)


def find(data: bytes, pattern: bytes) -> int:
    """First offset of ``pattern`` in ``data``, or -1."""
    return _core.find(data, pattern)
