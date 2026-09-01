"""
DMA physical-memory operations (PCILeech FPGA / MemProcFS backend).

Reading physical memory is provided by the ``memvirt`` backend directly. This
module adds the guarded write path: a DMA write edits a live machine's RAM from
outside its operating system, so it is wrapped in the same safety envelope as
the process memory-patch -- dry-run aware, audited (before/after bytes),
reversible via the Omega Rollback ledger, and UI-gated behind a confirmation.

Authorized use only: kernel debugging, driver development, and red-team on
systems you own or are explicitly cleared to test.
"""
from __future__ import annotations

from ..core import dryrun, logbus, safety
from .memvirt import MemoryBackend

SRC = "forensics.dma"


def write_capable(backend: MemoryBackend) -> bool:
    return bool(getattr(backend.capabilities, "physical_write", False))


def physical_write(
    backend: MemoryBackend,
    address: int,
    data: bytes,
    *,
    register_undo: bool = True,
    verify: bool = True,
) -> tuple[bool, str]:
    n = len(data)
    if n == 0:
        return False, "nothing to write (0 bytes)"

    if dryrun.skip(SRC, f"DMA-write @ 0x{address:x} ({n} bytes)", data.hex(" ")):
        return True, f"[dry-run] would write {n} bytes @ 0x{address:x}"

    if not write_capable(backend):
        return False, (f"active backend '{backend.name}' cannot write physical "
                       "memory — attach a PCILeech FPGA device")

    original = backend.physical_read(address, n)
    if original is None or len(original) != n:
        original = None
        logbus.warn(SRC, f"could not snapshot 0x{address:x} before write; "
                         "rollback will be unavailable")

    if not backend.physical_write(address, data):
        return False, f"DMA write failed @ 0x{address:x}"

    before = original.hex(" ") if original is not None else "<unreadable>"
    logbus.action(SRC, f"DMA-WROTE @ 0x{address:x}", f"{before} -> {data.hex(' ')}")

    if register_undo and original is not None:
        snap = original

        def _undo() -> None:
            backend.physical_write(address, snap)

        safety.ledger.register(f"DMA write @ 0x{address:x} ({n} bytes)", _undo)

    if verify:
        back = backend.physical_read(address, n)
        if back is not None and bytes(back) != bytes(data):
            return True, (f"wrote {n} bytes @ 0x{address:x} "
                          "(WARNING: read-back differs — volatile region?)")

    tail = "" if original is not None else " (no rollback — pre-read failed)"
    return True, f"wrote {n} bytes @ 0x{address:x}{tail}"
