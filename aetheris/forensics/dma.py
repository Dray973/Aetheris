"""
DMA physical-memory operations (PCILeech FPGA / MemProcFS backend).

*Reading* physical memory is provided by the ``memvirt`` backend directly. This
module adds the **guarded write** path, which is the single most invasive action
in the suite: a DMA write edits a live machine's RAM from outside its operating
system, bypassing OS memory protection, so a wrong address can instantly crash
or corrupt the target. It is therefore wrapped in the same safety envelope as
the process memory-patch, and then some:

  * **dry-run aware** — when dry-run is active it logs the intended address and
    bytes and writes nothing (and registers no undo);
  * **audited** — the address plus the *before* and *after* bytes are written to
    the tamper-evident audit log;
  * **reversible** — the original bytes are snapshotted (via a physical read)
    and registered with the Omega Rollback ledger, so PANIC restores them;
  * **UI-gated** — the UI only ever calls this behind an explicit confirmation.

Authorized use only: kernel debugging, driver development, and red-team on
systems you own or are explicitly cleared to test.
"""
from __future__ import annotations

from ..core import dryrun, logbus, safety
from .memvirt import MemoryBackend

SRC = "forensics.dma"


def write_capable(backend: MemoryBackend) -> bool:
    """True when the active acquisition backend can write physical memory
    (a live PCILeech FPGA / writable device — not a read-only dump or the
    software-only live backend)."""
    return bool(getattr(backend.capabilities, "physical_write", False))


def physical_write(
    backend: MemoryBackend,
    address: int,
    data: bytes,
    *,
    register_undo: bool = True,
    verify: bool = True,
) -> tuple[bool, str]:
    """
    Write ``data`` at physical ``address`` over the DMA backend, guarded.

    Returns ``(ok, message)``. Callers (the UI) must have already confirmed with
    the operator. On success the original bytes are registered with the rollback
    ledger so PANIC can restore them.
    """
    n = len(data)
    if n == 0:
        return False, "nothing to write (0 bytes)"

    # 1. Dry-run: log intent, touch nothing, register no undo.
    if dryrun.skip(SRC, f"DMA-write @ 0x{address:x} ({n} bytes)", data.hex(" ")):
        return True, f"[dry-run] would write {n} bytes @ 0x{address:x}"

    # 2. Only a writable acquisition device can do this.
    if not write_capable(backend):
        return False, (f"active backend '{backend.name}' cannot write physical "
                       "memory — attach a PCILeech FPGA device")

    # 3. Snapshot the original bytes so the write is reversible.
    original = backend.physical_read(address, n)
    if original is None or len(original) != n:
        original = None
        logbus.warn(SRC, f"could not snapshot 0x{address:x} before write; "
                         "rollback will be unavailable")

    # 4. Perform the write.
    if not backend.physical_write(address, data):
        return False, f"DMA write failed @ 0x{address:x}"

    # 5. Audit the exact change (before -> after).
    before = original.hex(" ") if original is not None else "<unreadable>"
    logbus.action(SRC, f"DMA-WROTE @ 0x{address:x}", f"{before} -> {data.hex(' ')}")

    # 6. Register the undo (restore the snapshotted bytes) for PANIC.
    if register_undo and original is not None:
        snap = original

        def _undo() -> None:
            backend.physical_write(address, snap)

        safety.ledger.register(f"DMA write @ 0x{address:x} ({n} bytes)", _undo)

    # 7. Optional read-back verification.
    if verify:
        back = backend.physical_read(address, n)
        if back is not None and bytes(back) != bytes(data):
            return True, (f"wrote {n} bytes @ 0x{address:x} "
                          "(WARNING: read-back differs — volatile region?)")

    tail = "" if original is not None else " (no rollback — pre-read failed)"
    return True, f"wrote {n} bytes @ 0x{address:x}{tail}"
