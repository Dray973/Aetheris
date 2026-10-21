"""
Credential-theft tell: who holds a handle into lsass.exe that can read it?

Dumping credentials from LSASS (Mimikatz ``sekurlsa``, ProcDump, comsvcs
MiniDump, nanodump ...) needs a process handle to lsass.exe with
``PROCESS_VM_READ``. Very little on a healthy machine holds one, so the handle
table answers a question most free tools never ask.

Collection uses the native engine's system-wide handle table (no Python
equivalent: see ``native/win.py``). It stays cheap on a table of several
hundred thousand handles by resolving each object *type* once per type index,
filtering by access mask in Python, and only then asking the engine for the
target pid of the handful of candidates left.

:func:`collect` is the impure part (Windows + engine); the access-mask and
allow-list logic is pure and tested off-Windows.
"""
from __future__ import annotations

import ntpath
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from ..native import win as nativewin

SRC = "forensics.credaccess"

PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_DUP_HANDLE = 0x0040

#: Rights that let the holder read or tamper with LSASS memory.
DANGEROUS = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION

#: Windows components that legitimately hold such handles. Matched on the
#: image *path*, not just the name: malware named svchost.exe in a temp folder
#: must not inherit the exemption.
_SYSTEM_DIRS = ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\")
_ALLOWED_SYSTEM = {"lsass.exe", "csrss.exe", "wininit.exe", "services.exe", "smss.exe",
                   "svchost.exe", "lsm.exe", "wmiprvse.exe", "taskmgr.exe",
                   "werfault.exe", "wermgr.exe", "msmpeng.exe"}
#: Security products that read LSASS by design (Defender runs from ProgramData).
_ALLOWED_ANYWHERE_SIGNED = {"msmpeng.exe", "mssense.exe", "nissrv.exe",
                            "sensecncproxy.exe", "csfalconservice.exe",
                            "sentinelagent.exe", "cyserver.exe"}


@dataclass(frozen=True)
class LsassHandle:
    holder_pid: int
    holder_name: str
    holder_exe: str
    lsass_pid: int
    granted_access: int

    @property
    def can_read(self) -> bool:
        return bool(self.granted_access & PROCESS_VM_READ)

    def rights(self) -> list[str]:
        names = [(PROCESS_VM_READ, "VM_READ"), (PROCESS_VM_WRITE, "VM_WRITE"),
                 (PROCESS_VM_OPERATION, "VM_OPERATION"),
                 (PROCESS_CREATE_THREAD, "CREATE_THREAD"), (PROCESS_DUP_HANDLE, "DUP_HANDLE")]
        return [n for bit, n in names if self.granted_access & bit]


def is_dangerous(access: int) -> bool:
    return bool(access & DANGEROUS)


def is_expected(holder_exe: str, signature: str = "") -> bool:
    """True for Windows/security components that read LSASS legitimately."""
    exe = (holder_exe or "").lower()
    name = ntpath.basename(exe)
    if name in _ALLOWED_SYSTEM and exe.startswith(_SYSTEM_DIRS):
        return True
    return name in _ALLOWED_ANYWHERE_SIGNED and signature not in ("unsigned", "")


def _process_type_indexes(entries: Iterable[nativewin.HandleEntry]) -> set[int]:
    """Type indexes whose object type is 'Process' (one lookup per index)."""
    seen: dict[int, nativewin.HandleEntry] = {}
    for e in entries:
        seen.setdefault(e.type_index, e)
    return {idx for idx, sample in seen.items()
            if nativewin.handle_type_name(sample) == "Process"}


def collect(processes: Iterable[Any]) -> list[LsassHandle] | None:
    """Handles into lsass.exe with read/write-class rights.

    None when this can't be answered here (engine absent, non-Windows), which
    is distinct from [] -- "looked, found nothing".
    """
    if not nativewin.available():
        return None
    procs = list(processes)
    lsass = {getattr(p, "pid", 0) for p in procs
             if (getattr(p, "name", "") or "").lower() == "lsass.exe"}
    if not lsass:
        return None
    info = {getattr(p, "pid", 0): p for p in procs}
    table = nativewin.enum_handles(0)
    if not table:
        return None
    process_types = _process_type_indexes(table)
    out: list[LsassHandle] = []
    for e in table:
        if (e.type_index not in process_types or e.pid in lsass
                or not is_dangerous(e.granted_access)):
            continue
        target = nativewin.handle_process_target(e)
        if target not in lsass:
            continue
        p = info.get(e.pid)
        out.append(LsassHandle(holder_pid=e.pid,
                               holder_name=getattr(p, "name", "?") if p else "?",
                               holder_exe=getattr(p, "exe", "") if p else "",
                               lsass_pid=target, granted_access=e.granted_access))
    return out
