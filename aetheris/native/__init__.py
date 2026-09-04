"""
Bindings to the Aetheris native engines.

Two libraries sit behind this package, both optional and both loaded through
:mod:`aetheris.native.loader`:

  * ``aetheris_core.dll`` (Rust, ``native/aetheris_core``) — pure computation:
    entropy, byte search, PE parsing and carving, region classification,
    SHA-256. No OS calls, so it is portable and dependency-free.

  * ``aetheris_win.dll`` (C++, ``native/aetheris_win``) — the Win32 layer:
    process enumeration, memory maps and reads, and the system-wide handle
    table with hang-safe object-name resolution.

Every binding degrades: when a library is absent or reports an ABI version the
host does not understand, the calling module falls back to its pure-Python
implementation. The app is always fully functional without either DLL — the
native engines are a speed and capability upgrade, never a hard dependency.
"""
from __future__ import annotations

from . import core, loader, win

__all__ = ["core", "loader", "win"]
