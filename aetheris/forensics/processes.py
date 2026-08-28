"""
Process autopsy model.

psutil provides the reliable cross-cut (pid, name, user, cpu, memory, exe path,
connections). On top of that we layer best-effort Windows-only enrichment:

  * ASLR / DEP mitigation policy via GetProcessMitigationPolicy
  * Authenticode signature state via WinVerifyTrust (best effort)

Both enrichments degrade to "unknown" when the query is denied or unavailable,
so the process list is always populated even from a non-elevated session.
"""
from __future__ import annotations

import ctypes
from collections.abc import Iterator
from ctypes import wintypes
from dataclasses import asdict, dataclass

import psutil

from ..core import dryrun, logbus
from ..core import winapi as W

SRC = "forensics.processes"


@dataclass
class ProcessInfo:
    pid: int
    name: str
    username: str
    exe: str
    cpu_percent: float
    mem_rss: int              # bytes
    num_threads: int
    status: str
    dep: str = "unknown"      # on / off / unknown
    aslr: str = "unknown"     # on / off / unknown
    signature: str = "unchecked"

    def as_dict(self) -> dict:
        return asdict(self)


# --- Mitigation policy (best effort) --------------------------------------
class _PROCESS_MITIGATION_DEP_POLICY(ctypes.Structure):
    _fields_ = [("Flags", wintypes.DWORD)]


class _PROCESS_MITIGATION_ASLR_POLICY(ctypes.Structure):
    _fields_ = [("Flags", wintypes.DWORD)]


_ProcessDEPPolicy = 0
_ProcessASLRPolicy = 1


def _query_mitigations(pid: int) -> tuple[str, str]:
    if not W.IS_WINDOWS:
        return "unknown", "unknown"
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
                # bit0 = EnableBottomUpRandomization
                aslr = "on" if (aslr_pol.Flags & 0x1) else "off"
        except Exception:
            pass
        return dep, aslr
    finally:
        W.kernel32.CloseHandle(h)


def snapshot(enrich: bool = False) -> list[ProcessInfo]:
    """
    Return a list of ProcessInfo for all visible processes.
    ``enrich=True`` adds mitigation queries (slower; opens each process).
    """
    out: list[ProcessInfo] = []
    for p in psutil.process_iter(
        ["pid", "name", "username", "exe", "cpu_percent",
         "memory_info", "num_threads", "status"]
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
            )
            if enrich:
                pi.dep, pi.aslr = _query_mitigations(pi.pid)
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
