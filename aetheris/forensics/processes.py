"""
Process autopsy model.

psutil provides the reliable cross-cut (pid, name, user, cpu, memory, exe path,
connections). On top of that we layer best-effort Windows-only enrichment:

  * ASLR / DEP mitigation policy via GetProcessMitigationPolicy (``enrich=True``)
  * Authenticode signature state of the image via WinVerifyTrust + catalog,
    cached per path (``sign=True``)

Both enrichments degrade to "unknown" when the query is denied or unavailable,
so the process list is always populated even from a non-elevated session.
"""
from __future__ import annotations

import ctypes
from collections.abc import Iterator
from ctypes import wintypes
from dataclasses import asdict, dataclass
from typing import Any

import psutil

from ..core import dryrun, logbus, safety, signing
from ..core import winapi as W
from ..native import win as nativewin

SRC = "forensics.processes"


@dataclass
class ProcessInfo:
    pid: int
    name: str
    username: str
    exe: str
    cpu_percent: float
    mem_rss: int
    num_threads: int
    status: str
    dep: str = "unknown"
    aslr: str = "unknown"
    signature: str = "unchecked"
    # Lineage, for attack storylines ("chrome.exe started upd.exe at 14:02").
    ppid: int = 0
    create_time: float = 0.0
    cmdline: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class _PROCESS_MITIGATION_DEP_POLICY(ctypes.Structure):
    _fields_ = [("Flags", wintypes.DWORD)]


class _PROCESS_MITIGATION_ASLR_POLICY(ctypes.Structure):
    _fields_ = [("Flags", wintypes.DWORD)]


_ProcessDEPPolicy = 0
_ProcessASLRPolicy = 1


def _query_mitigations(pid: int) -> tuple[str, str]:
    if not W.IS_WINDOWS:
        return "unknown", "unknown"
    # The native engine does both policy queries behind one process handle.
    # It returns None only when it isn't loaded — a *denied* query still comes
    # back as ("unknown", "unknown"), same as the ctypes path below.
    native = nativewin.process_mitigations(pid)
    if native is not None:
        return native
    h = W.kernel32.OpenProcess(W.PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        h = W.kernel32.OpenProcess(W.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return "unknown", "unknown"
    try:
        dep = aslr = "unknown"
        try:
            dep_pol = _PROCESS_MITIGATION_DEP_POLICY()
            if W.kernel32.GetProcessMitigationPolicy(
                h, _ProcessDEPPolicy, ctypes.byref(dep_pol), ctypes.sizeof(dep_pol)
            ):
                dep = "on" if (dep_pol.Flags & 0x1) else "off"
        except Exception:
            pass
        try:
            aslr_pol = _PROCESS_MITIGATION_ASLR_POLICY()
            if W.kernel32.GetProcessMitigationPolicy(
                h, _ProcessASLRPolicy, ctypes.byref(aslr_pol), ctypes.sizeof(aslr_pol)
            ):
                aslr = "on" if (aslr_pol.Flags & 0x1) else "off"
        except Exception:
            pass
        return dep, aslr
    finally:
        W.kernel32.CloseHandle(h)


_CMDLINE_MAX = 2048


def _join_cmdline(parts: Any) -> str:
    """psutil gives argv as a list (or None when access is denied)."""
    if not parts:
        return ""
    text = " ".join(str(p) for p in parts)
    return text if len(text) <= _CMDLINE_MAX else text[: _CMDLINE_MAX - 1] + "…"


def snapshot(enrich: bool = False, sign: bool = False) -> list[ProcessInfo]:
    """
    Return a list of ProcessInfo for all visible processes.
    ``enrich=True`` adds mitigation queries (slower; opens each process).
    ``sign=True`` fills the Authenticode ``signature`` of each image (cached per
    path, so repeated snapshots only pay for images not seen before).
    """
    out: list[ProcessInfo] = []
    for p in psutil.process_iter(
        ["pid", "name", "username", "exe", "cpu_percent",
         "memory_info", "num_threads", "status", "ppid", "create_time", "cmdline"]
    ):
        try:
            info = p.info
            mem = info.get("memory_info")
            pi = ProcessInfo(
                pid=info["pid"],
                name=info.get("name") or "?",
                username=info.get("username") or "?",
                exe=info.get("exe") or "",
                cpu_percent=info.get("cpu_percent") or 0.0,
                mem_rss=getattr(mem, "rss", 0) if mem else 0,
                num_threads=info.get("num_threads") or 0,
                status=info.get("status") or "?",
                ppid=info.get("ppid") or 0,
                create_time=info.get("create_time") or 0.0,
                cmdline=_join_cmdline(info.get("cmdline")),
            )
            if enrich:
                pi.dep, pi.aslr = _query_mitigations(pi.pid)
            if sign and pi.exe:
                pi.signature = signing.label(pi.exe)
            out.append(pi)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return out


def kill(pid: int) -> tuple[bool, str]:
    """Terminate a process by pid (with a hard kill fallback)."""
    if dryrun.skip(SRC, f"terminate pid {pid}"):
        return True, f"[dry-run] would terminate pid {pid}"
    try:
        p = psutil.Process(pid)
        name = p.name()
        p.terminate()
        try:
            p.wait(timeout=3)
        except psutil.TimeoutExpired:
            p.kill()
        logbus.action(SRC, f"terminated pid {pid} ({name})")
        return True, f"terminated {name} (pid {pid})"
    except psutil.NoSuchProcess:
        return False, "no such process"
    except psutil.AccessDenied:
        return False, "access denied (need elevation / SeDebugPrivilege)"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def suspend(pid: int) -> tuple[bool, str]:
    """Freeze every thread of a process -- the reversible alternative to kill.

    Registers its own undo (resume) on the rollback ledger, guarded by the
    process start time so a recycled pid is never resumed by mistake.
    """
    if dryrun.skip(SRC, f"suspend pid {pid}"):
        return True, f"[dry-run] would suspend pid {pid}"
    try:
        p = psutil.Process(pid)
        name, started = p.name(), p.create_time()
        p.suspend()
    except psutil.NoSuchProcess:
        return False, "no such process"
    except psutil.AccessDenied:
        return False, "access denied (need elevation / SeDebugPrivilege)"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)
    safety.ledger.register(f"suspend {name} (pid {pid})",
                           lambda: _resume_checked(pid, started))
    logbus.action(SRC, f"suspended pid {pid} ({name})")
    return True, f"suspended {name} (pid {pid})"


def _resume_checked(pid: int, started: float) -> None:
    p = psutil.Process(pid)
    if abs(p.create_time() - started) > 0.01:
        raise RuntimeError(f"pid {pid} now belongs to a different process; not resuming")
    p.resume()
    logbus.action(SRC, f"resumed pid {pid}")


def resume(pid: int) -> tuple[bool, str]:
    """Resume a suspended process (for manual use; undo uses _resume_checked)."""
    if dryrun.skip(SRC, f"resume pid {pid}"):
        return True, f"[dry-run] would resume pid {pid}"
    try:
        p = psutil.Process(pid)
        p.resume()
        return True, f"resumed {p.name()} (pid {pid})"
    except psutil.NoSuchProcess:
        return False, "no such process"
    except psutil.AccessDenied:
        return False, "access denied"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def set_affinity(pid: int, cpus: list[int]) -> tuple[bool, str]:
    """Pin a process to a specific set of CPU cores."""
    try:
        p = psutil.Process(pid)
        p.cpu_affinity(cpus)
        logbus.action(SRC, f"pid {pid} affinity -> cores {cpus}")
        return True, f"affinity set to {cpus}"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def top_by_memory(threshold_bytes: int) -> Iterator[ProcessInfo]:
    """Yield processes whose RSS exceeds ``threshold_bytes``."""
    for pi in snapshot():
        if pi.mem_rss >= threshold_bytes:
            yield pi


if W.IS_WINDOWS:
    W.kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    W.kernel32.OpenProcess.restype = wintypes.HANDLE
    W.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    W.kernel32.CloseHandle.restype = wintypes.BOOL
    try:
        W.kernel32.GetProcessMitigationPolicy.argtypes = [
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t
        ]
        W.kernel32.GetProcessMitigationPolicy.restype = wintypes.BOOL
    except AttributeError:  # pragma: no cover - very old Windows
        pass
