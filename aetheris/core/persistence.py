"""
Unified startup & persistence map.

One normalized view of everything that runs at boot/logon, merged from the
existing subsystems:

  * Run / RunOnce keys and Startup folders  (:mod:`aetheris.core.autoruns`)
  * services set to auto / boot / system start  (:mod:`aetheris.core.services`)
  * scheduled tasks with a logon/boot trigger  (:mod:`aetheris.core.taskaudit`)

Each row carries a signed/unsigned label and an ``enabled`` flag. ``set_enabled``
routes a reversible enable/disable back to the owning subsystem -- so the undo,
audit, and dry-run behaviour all come from the real op (no duplicate logic).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import logbus, services, signing

SRC = "core.persistence"


@dataclass
class PersistenceEntry:
    source: str
    name: str
    detail: str
    location: str
    binary: str = ""
    signed: str = "unknown"
    enabled: bool = True
    ref: Any = None


def _binary_of(command: str) -> str:
    return services.resolve_path(services.parse_binary(command))


def enumerate_all(check_signature: bool = True) -> list[PersistenceEntry]:
    """Merge autoruns + auto/boot services + logon/boot tasks into one list."""
    out: list[PersistenceEntry] = []

    from . import autoruns
    for e in autoruns.enumerate_entries():
        binary = _binary_of(e.command)
        out.append(PersistenceEntry(
            source=("Startup" if e.kind == "folder" else "Run"), name=e.name,
            detail=e.command, location=e.location, binary=binary,
            signed=signing.label(binary) if check_signature and binary else "unknown",
            enabled=e.enabled, ref=e))

    for s in services.enumerate_services(check_signature=check_signature):
        if s.start_type in ("auto", "boot", "system"):
            out.append(PersistenceEntry(
                source="Service", name=s.name, detail=s.image_path,
                location=f"Service ({s.start_type})", binary=s.binary,
                signed=s.signed, enabled=True, ref=s.name))

    from . import taskaudit
    for t in taskaudit.enumerate_tasks(check_signature=check_signature):
        if any(tr in ("logon", "boot") for tr in t.triggers):
            out.append(PersistenceEntry(
                source="Task", name=t.name,
                detail=(t.actions[0] if t.actions else ""), location=t.path,
                binary=(t.action_binaries[0] if t.action_binaries else ""),
                signed=t.signed, enabled=t.enabled, ref=t.path))

    logbus.trace(SRC, f"persistence map: {len(out)} autostart entries")
    return out


def set_enabled(entry: PersistenceEntry, enable: bool) -> tuple[bool, str]:
    """Enable/disable an entry via its owning subsystem (reversible there)."""
    if entry.source in ("Run", "Startup"):
        from . import autoruns
        return autoruns.enable(entry.ref) if enable else autoruns.disable(entry.ref)
    if entry.source == "Service":
        return services.set_start_type(entry.ref, "auto" if enable else "disabled")
    if entry.source == "Task":
        from . import taskaudit
        return (taskaudit.enable_task(entry.ref) if enable
                else taskaudit.disable_task(entry.ref))
    return False, f"cannot toggle a {entry.source!r} entry"
