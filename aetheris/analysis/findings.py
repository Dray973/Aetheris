"""
Threat-hunting findings engine.

Correlates signals from the feature layers -- process autopsy (+ Authenticode),
network connections (+ GeoIP), the persistence map, scheduled tasks, services,
and in-memory injection -- into a single ranked list of **findings**, each tagged
with a MITRE ATT&CK technique and suggested reversible responses.

The detectors and the correlation are **pure**: ``analyze`` takes already-gathered
data and returns findings, so it unit-tests with synthetic objects and no OS.
``gather`` is the impure orchestrator that collects live data (lazily importing
the collectors) and calls ``analyze`` -- meant to run on a Worker. The real power
is correlation: when the same binary shows up as unsigned *and* running from temp
*and* talking to a public host *and* set to persist, the signals merge into one
high-severity finding instead of four scattered rows.
"""
from __future__ import annotations

import ntpath
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

SRC = "analysis.findings"

_SUSPICIOUS_DIRS = ("\\temp\\", "\\tmp\\", "\\downloads\\",
                    "\\appdata\\local\\temp\\", "\\users\\public\\")

_INJECTION_TITLES = {
    "rwx": "Writable + executable memory region",
    "unbacked-exec": "Executable memory not backed by a file (possible shellcode)",
    "private-pe": "PE image in private memory (possible injected module)",
}
_INJECTION_SCORE = {"rwx": 55, "unbacked-exec": 55, "private-pe": 75}


@dataclass
class Finding:
    key: str
    subject: str
    title: str
    score: int
    category: str
    technique: str
    technique_name: str
    evidence: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)

    @property
    def severity(self) -> str:
        s = self.score
        if s >= 80:
            return "critical"
        if s >= 60:
            return "high"
        if s >= 35:
            return "medium"
        return "low"


def _in_suspicious_dir(path: str | None) -> bool:
    low = (path or "").lower()
    return any(d in low for d in _SUSPICIOUS_DIRS)


def _key(path: str | None, fallback: str = "") -> str:
    # Paths here are always Windows paths: ntpath splits on "\\" on any host,
    # so offline analysis correlates exactly as it does on the live machine.
    if path:
        return ntpath.basename(path).lower() or path.lower()
    return (fallback or "?").lower()


# --- detectors (pure) ------------------------------------------------------
def detect_processes(processes: Iterable[Any]) -> list[Finding]:
    out: list[Finding] = []
    for p in processes:
        exe = getattr(p, "exe", "") or ""
        if not exe:
            continue
        unsigned = getattr(p, "signature", "") == "unsigned"
        in_temp = _in_suspicious_dir(exe)
        if not (unsigned or in_temp):
            continue
        score = 45 if (unsigned and in_temp) else (30 if unsigned else 20)
        bits = []
        if unsigned:
            bits.append("unsigned")
        if in_temp:
            bits.append("temp/download directory")
        out.append(Finding(
            key=_key(exe, getattr(p, "name", "")),
            subject=f"{getattr(p, 'name', '?')} (pid {getattr(p, 'pid', 0)})",
            title="Suspicious process: " + " + ".join(bits),
            score=score, category="masquerading",
            technique="T1036", technique_name="Masquerading",
            evidence=[f"exe: {exe}", f"Authenticode: {getattr(p, 'signature', '?')}"],
            actions=[f"kill pid {getattr(p, 'pid', 0)}"]))
    return out


def detect_network(connections: Iterable[Any], processes: Iterable[Any]) -> list[Finding]:
    exe = {getattr(p, "pid", 0): getattr(p, "exe", "") for p in processes}
    sig = {getattr(p, "pid", 0): getattr(p, "signature", "") for p in processes}
    by_pid: dict[int, list[Any]] = defaultdict(list)
    for c in connections:
        if getattr(c, "remote_class", "") == "public" and getattr(c, "raddr", ""):
            by_pid[getattr(c, "pid", 0) or 0].append(c)
    out: list[Finding] = []
    for pid, conns in by_pid.items():
        unsigned = sig.get(pid) == "unsigned"
        name = getattr(conns[0], "proc_name", "?")
        remotes = [f"{getattr(c, 'raddr', '')}:{getattr(c, 'rport', 0)}"
                   f" ({getattr(c, 'geo', '') or getattr(c, 'rdns', '') or 'public'})"
                   for c in conns[:4]]
        out.append(Finding(
            key=_key(exe.get(pid), name),
            subject=f"{name} (pid {pid})",
            title=("Public outbound connection from an unsigned process" if unsigned
                   else "Public outbound connection"),
            score=45 if unsigned else 20, category="c2",
            technique="T1071", technique_name="Application Layer Protocol",
            evidence=[f"{len(conns)} public remote(s):"] + remotes,
            actions=[f"isolate {name}", f"kill pid {pid}"]))
    return out


def detect_persistence(entries: Iterable[Any]) -> list[Finding]:
    out: list[Finding] = []
    for e in entries:
        if not getattr(e, "enabled", True):
            continue
        binary = getattr(e, "binary", "") or ""
        unsigned = getattr(e, "signed", "") == "unsigned"
        in_temp = _in_suspicious_dir(binary)
        if not (unsigned or in_temp):
            continue
        out.append(Finding(
            key=_key(binary, getattr(e, "name", "")),
            subject=f"{getattr(e, 'name', '?')} ({getattr(e, 'source', '?')})",
            title="Autostart persistence" + (" (unsigned)" if unsigned else "")
                  + (" from temp" if in_temp else ""),
            score=50 if (unsigned and in_temp) else 35, category="persistence",
            technique="T1547", technique_name="Boot or Logon Autostart Execution",
            evidence=[f"location: {getattr(e, 'location', '')}", f"binary: {binary}",
                      f"signed: {getattr(e, 'signed', '?')}"],
            actions=[f"disable {getattr(e, 'name', '?')}"]))
    return out


def detect_tasks(tasks: Iterable[Any]) -> list[Finding]:
    strong = {"temp/download/public-dir action", "obfuscated/encoded shell command",
              "unsigned action binary"}
    out: list[Finding] = []
    for t in tasks:
        flags = list(getattr(t, "flags", []))
        if not (strong & set(flags)):
            continue
        binaries = list(getattr(t, "action_binaries", []))
        actions_list = list(getattr(t, "actions", []))
        out.append(Finding(
            key=_key(binaries[0] if binaries else None, getattr(t, "name", "")),
            subject=f"{getattr(t, 'name', '?')} (task)",
            title="Suspicious scheduled task: " + "; ".join(flags),
            score=45, category="persistence",
            technique="T1053.005", technique_name="Scheduled Task",
            evidence=[f"task: {getattr(t, 'path', '')}",
                      f"triggers: {', '.join(getattr(t, 'triggers', []))}",
                      f"action: {actions_list[0] if actions_list else ''}"],
            actions=[f"disable task {getattr(t, 'path', '')}"]))
    return out


def detect_services(services: Iterable[Any]) -> list[Finding]:
    out: list[Finding] = []
    for s in services:
        if not getattr(s, "unquoted_path", False):
            continue
        out.append(Finding(
            key=_key(getattr(s, "binary", ""), getattr(s, "name", "")),
            subject=f"{getattr(s, 'name', '?')} (service)",
            title="Unquoted service path (privilege-escalation candidate)",
            score=40, category="privesc",
            technique="T1574.009", technique_name="Path Interception (Unquoted Path)",
            evidence=[f"ImagePath: {getattr(s, 'image_path', '')}",
                      f"start: {getattr(s, 'start_type', '')}",
                      f"account: {getattr(s, 'account', '')}"],
            actions=[]))
    return out


def detect_injection(injections: Iterable[Any], pid_to_exe: dict[int, str] | None = None) -> list[Finding]:
    pid_to_exe = pid_to_exe or {}
    out: list[Finding] = []
    for inj in injections:
        pid = getattr(inj, "pid", 0)
        kind = getattr(inj, "kind", "")
        out.append(Finding(
            key=_key(pid_to_exe.get(pid), getattr(inj, "name", "")),
            subject=f"{getattr(inj, 'name', '?')} (pid {pid})",
            title=_INJECTION_TITLES.get(kind, f"Injection: {kind}"),
            score=_INJECTION_SCORE.get(kind, 50), category="injection",
            technique="T1055", technique_name="Process Injection",
            evidence=[f"region: 0x{getattr(inj, 'base', 0):x} +0x{getattr(inj, 'size', 0):x}",
                      f"protect/type: {getattr(inj, 'protect', '')} / {getattr(inj, 'region_type', '')}"],
            actions=[f"kill pid {pid}"]))
    return out


def detect_yara(matches: Iterable[Any], pid_to_exe: dict[int, str] | None = None) -> list[Finding]:
    pid_to_exe = pid_to_exe or {}
    out: list[Finding] = []
    for m in matches:
        pid = getattr(m, "pid", 0)
        desc = getattr(m, "description", "")
        rule = getattr(m, "rule", "?")
        evidence = [f"rule: {rule}"]
        if pid:
            evidence.append(f"region: 0x{getattr(m, 'address', 0):x}")
        out.append(Finding(
            key=_key(pid_to_exe.get(pid), getattr(m, "name", "")),
            subject=f"{getattr(m, 'name', '?')}" + (f" (pid {pid})" if pid else ""),
            title=f"YARA match: {rule}" + (f" — {desc}" if desc else ""),
            score=70, category="yara",
            technique=getattr(m, "technique", "") or "T1027",
            technique_name="YARA rule match",
            evidence=evidence,
            actions=[f"kill pid {pid}"] if pid else []))
    return out


def detect_credential_access(handles: Iterable[Any],
                             processes: Iterable[Any] = ()) -> list[Finding]:
    """Handles into lsass.exe that can read or write its memory (T1003.001).

    ``handles`` are ``forensics.credaccess.LsassHandle``-shaped. Windows and
    security components that do this by design are skipped by image path, so
    a look-alike name in the wrong folder still fires.
    """
    from ..forensics import credaccess
    sig = {getattr(p, "pid", 0): getattr(p, "signature", "") for p in processes}
    by_holder: dict[int, list[Any]] = defaultdict(list)
    for h in handles:
        by_holder[getattr(h, "holder_pid", 0)].append(h)
    out: list[Finding] = []
    for pid, hs in by_holder.items():
        first = hs[0]
        exe = getattr(first, "holder_exe", "") or ""
        signature = sig.get(pid, "")
        if credaccess.is_expected(exe, signature):
            continue
        access = 0
        for h in hs:
            access |= int(getattr(h, "granted_access", 0))
        reads = bool(access & credaccess.PROCESS_VM_READ)
        unsigned = signature == "unsigned"
        score = (90 if unsigned else 70) if reads else (60 if unsigned else 45)
        rights = [n for bit, n in ((credaccess.PROCESS_VM_READ, "VM_READ"),
                                   (credaccess.PROCESS_VM_WRITE, "VM_WRITE"),
                                   (credaccess.PROCESS_VM_OPERATION, "VM_OPERATION"),
                                   (credaccess.PROCESS_CREATE_THREAD, "CREATE_THREAD"))
                  if access & bit]
        name = getattr(first, "holder_name", "?")
        out.append(Finding(
            key=_key(exe, name),
            subject=f"{name} (pid {pid})",
            title=("Process can read LSASS memory (credential dumping)" if reads
                   else "Process holds a write-class handle to LSASS"),
            score=score, category="credential-access",
            technique="T1003.001", technique_name="OS Credential Dumping: LSASS Memory",
            evidence=[f"handle(s) into lsass.exe (pid {getattr(first, 'lsass_pid', 0)}): "
                      f"{len(hs)}",
                      f"granted access: 0x{access:08x} ({', '.join(rights) or 'other'})",
                      f"exe: {exe or '?'}",
                      f"Authenticode: {signature or '?'}"],
            actions=[f"suspend pid {pid}", f"kill pid {pid}"]))
    return out


def detect_downloads(processes: Iterable[Any],
                     origins: dict[str, Any] | None = None) -> list[Finding]:
    """Running images that carry an internet Mark-of-the-Web (T1204.002).

    Alone this is weak -- people run installers -- so it scores low and
    exists mainly to correlate: an unsigned temp binary that was also just
    downloaded, then persists, reads as one story.
    """
    origins = origins or {}
    out: list[Finding] = []
    seen: set[str] = set()
    for p in processes:
        exe = getattr(p, "exe", "") or ""
        origin = origins.get(exe.lower())
        if origin is None or not getattr(origin, "from_internet", False):
            continue
        if exe.lower() in seen:
            continue
        seen.add(exe.lower())
        unsigned = getattr(p, "signature", "") == "unsigned"
        evidence = [f"exe: {exe}", f"origin: {origin.describe()}"]
        if getattr(origin, "host", ""):
            evidence.append(f"download host: {origin.host}")
        out.append(Finding(
            key=_key(exe, getattr(p, "name", "")),
            subject=f"{getattr(p, 'name', '?')} (pid {getattr(p, 'pid', 0)})",
            title="Running a file downloaded from the internet"
                  + (" (unsigned)" if unsigned else ""),
            score=30 if unsigned else 10, category="execution",
            technique="T1204.002", technique_name="User Execution: Malicious File",
            evidence=evidence,
            actions=[f"suspend pid {getattr(p, 'pid', 0)}"]))
    return out


# --- correlation + entry points --------------------------------------------
def correlate(findings: list[Finding]) -> list[Finding]:
    """Merge findings that share a key into one boosted finding; sort by score."""
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        grouped[f.key].append(f)
    out: list[Finding] = []
    for key, group in grouped.items():
        if len(group) == 1:
            out.append(group[0])
            continue
        score = min(100, sum(f.score for f in group) + 10 * (len(group) - 1))
        techniques = sorted({f"{f.technique} {f.technique_name}" for f in group})
        categories = sorted({f.category for f in group})
        evidence: list[str] = []
        actions: list[str] = []
        for f in sorted(group, key=lambda f: f.score, reverse=True):
            evidence.append(f"• {f.title} [{f.technique}]")
            evidence.extend(f"    {e}" for e in f.evidence)
            for a in f.actions:
                if a not in actions:
                    actions.append(a)
        out.append(Finding(
            key=key, subject=group[0].subject,
            title=f"Correlated ({len(group)} signals): {', '.join(categories)}",
            score=score, category="correlated",
            technique=", ".join(f.technique for f in group[:1]) or "multiple",
            technique_name="; ".join(techniques),
            evidence=evidence, actions=actions))
    out.sort(key=lambda f: f.score, reverse=True)
    return out


def analyze(processes: Iterable[Any] = (), connections: Iterable[Any] = (),
            persistence: Iterable[Any] = (), tasks: Iterable[Any] = (),
            services: Iterable[Any] = (), injections: Iterable[Any] = (),
            yara_matches: Iterable[Any] = (),
            pid_to_exe: dict[int, str] | None = None,
            lsass_handles: Iterable[Any] = (),
            origins: dict[str, Any] | None = None) -> list[Finding]:
    """Run every detector over the supplied data and return ranked, correlated
    findings. All inputs optional so each detector is testable in isolation."""
    processes = list(processes)
    signals: list[Finding] = []
    signals += detect_processes(processes)
    signals += detect_network(connections, processes)
    signals += detect_persistence(persistence)
    signals += detect_tasks(tasks)
    signals += detect_services(services)
    signals += detect_injection(injections, pid_to_exe)
    signals += detect_yara(yara_matches, pid_to_exe)
    signals += detect_credential_access(lsass_handles, processes)
    signals += detect_downloads(processes, origins)
    return correlate(signals)


def collect_origins(processes: Iterable[Any],
                    read: Any) -> dict[str, Any]:
    """Mark-of-the-Web for each distinct non-system image (lower-cased path)."""
    out: dict[str, Any] = {}
    for p in processes:
        exe = (getattr(p, "exe", "") or "").lower()
        if not exe or exe in out or exe.startswith("c:\\windows\\"):
            continue
        try:
            origin = read(getattr(p, "exe", ""))
        except Exception:  # noqa: BLE001
            origin = None
        if origin is not None:
            out[exe] = origin
    return out


@dataclass
class HuntResult:
    """A hunt's findings plus the raw data they came from, so follow-up
    actions (containment, the analyst) act on the same evidence."""
    findings: list[Finding] = field(default_factory=list)
    processes: list[Any] = field(default_factory=list)
    connections: list[Any] = field(default_factory=list)
    persistence: list[Any] = field(default_factory=list)
    origins: dict[str, Any] = field(default_factory=dict)
    ts: float = 0.0


def gather(scan_injection: bool = True, scan_yara: bool = False,
           max_scans: int = 40) -> list[Finding]:
    """Collect live data and analyze it (impure; run on a Worker)."""
    return gather_context(scan_injection, scan_yara, max_scans).findings


def gather_context(scan_injection: bool = True, scan_yara: bool = False,
                   max_scans: int = 40) -> HuntResult:
    """Like :func:`gather` but also returns the data behind the findings."""
    import time

    from ..core import logbus, taskaudit
    from ..core import persistence as persist_mod
    from ..core import services as services_mod
    from ..forensics import injection as inj_mod
    from ..forensics import processes as proc_mod
    from ..forensics import yarascan
    from ..forensics.memvirt import get_backend
    from ..network import connections as conn_mod

    procs = proc_mod.snapshot(sign=True)
    conns = conn_mod.snapshot(resolve_geo=True)
    try:
        pmap = persist_mod.enumerate_all()
    except Exception:  # noqa: BLE001
        pmap = []
    try:
        tasks = taskaudit.enumerate_tasks()
    except Exception:  # noqa: BLE001
        tasks = []
    try:
        svcs = services_mod.enumerate_services()
    except Exception:  # noqa: BLE001
        svcs = []

    pid_to_exe = {p.pid: p.exe for p in procs}
    suspects = [p for p in procs if p.signature == "unsigned" or _in_suspicious_dir(p.exe)]
    backend = get_backend() if (scan_injection or scan_yara) else None

    injections: list[Any] = []
    if scan_injection and backend is not None:
        for p in suspects[:max_scans]:
            try:
                injections += inj_mod.scan_process(backend, p.pid, p.name)
            except Exception:  # noqa: BLE001
                continue

    yara_matches: list[Any] = []
    if scan_yara and backend is not None and yarascan.available():
        rules = yarascan.load_rules()
        for p in suspects[:max_scans]:
            try:
                yara_matches += yarascan.scan_process(rules, backend, p.pid, p.name)
            except Exception:  # noqa: BLE001
                continue

    from ..forensics import credaccess, motw
    try:
        lsass_handles = credaccess.collect(procs) or []
    except Exception:  # noqa: BLE001
        lsass_handles = []
    origins = collect_origins(procs, motw.read)

    findings = analyze(processes=procs, connections=conns, persistence=pmap,
                       tasks=tasks, services=svcs, injections=injections,
                       yara_matches=yara_matches, pid_to_exe=pid_to_exe,
                       lsass_handles=lsass_handles, origins=origins)
    logbus.trace(SRC, f"hunt: {len(findings)} finding(s) from "
                      f"{len(procs)} proc / {len(conns)} conn")
    return HuntResult(findings=findings, processes=procs, connections=conns,
                      persistence=pmap, origins=origins, ts=time.time())
