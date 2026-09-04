"""
In-memory injection / anomaly detection.

Flags the classic process-injection tells in a process's memory map:

  * ``rwx``           — a writable **and** executable region (shellcode staging);
  * ``unbacked-exec`` — executable memory not backed by an image file on disk;
  * ``private-pe``    — a PE image (``MZ``) mapped into private memory, i.e. a
                        module loaded without going through the loader (injected).

``classify_region`` is pure and unit-tested. ``scan_process`` walks a memvirt
backend's region map and reads two header bytes to promote an unbacked-exec
region to a private-PE finding.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..native import core as nativecore
from .memvirt import MemoryBackend

SRC = "forensics.injection"

SCORE = {"rwx": 55, "unbacked-exec": 55, "private-pe": 75}


@dataclass
class InjectionFinding:
    pid: int
    name: str
    base: int
    size: int
    kind: str
    protect: str
    region_type: str


def classify_region(protect: str, region_type: str) -> str | None:
    """Return an injection kind for a region, or None if it looks normal.

    Delegates to the Rust core when it is loaded; the crate's `classify::Kind`
    ports this logic verbatim, and both paths are pinned to the same table by
    ``tests/test_injection.py``."""
    return nativecore.classify_region(protect, region_type)


def scan_process(backend: MemoryBackend, pid: int, name: str = "") -> list[InjectionFinding]:
    """Classify every region of ``pid``; promote unbacked-exec to private-pe when
    the region starts with an ``MZ`` header."""
    out: list[InjectionFinding] = []
    for r in backend.memory_map(pid):
        kind = classify_region(r.protect, r.type)
        if kind is None:
            continue
        if kind == "unbacked-exec":
            head = backend.read(pid, r.base, 2)
            if head is not None:
                kind = nativecore.promote_kind(kind, head) or kind
        out.append(InjectionFinding(pid, name, r.base, r.size, kind, r.protect, r.type))
    return out
