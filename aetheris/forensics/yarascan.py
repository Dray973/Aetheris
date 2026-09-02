"""
YARA scanning of process memory and files.

Optional (needs ``yara-python``; degrades to ``available() == False`` otherwise).
Compiles a ruleset -- a few built-in demo rules plus any ``.yar`` / ``.yara``
files the user drops in ``%APPDATA%\\AetherisQuantumCore\\yara`` -- and scans a
process's committed memory regions (via the memvirt backend) or a file on disk.
Each match becomes a ``YaraMatch`` carrying the rule's ATT&CK technique (from its
``mitre_attack`` metadata), so matches flow straight into the threat-hunt engine.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..core import logbus
from ..core.settings import config_dir
from .memvirt import MemoryBackend

SRC = "forensics.yarascan"

try:
    import yara  # type: ignore
    _HAS_YARA = True
except Exception:
    yara = None  # type: ignore
    _HAS_YARA = False

_MAX_REGION = 16 * 1024 * 1024

_BUILTIN_RULES = r"""
rule Aetheris_Injection_APIs {
    meta:
        description = "Cluster of process-injection API names"
        mitre_attack = "T1055"
    strings:
        $a = "VirtualAllocEx" nocase
        $b = "WriteProcessMemory" nocase
        $c = "CreateRemoteThread" nocase
        $d = "NtUnmapViewOfSection" nocase
        $e = "QueueUserAPC" nocase
    condition:
        3 of them
}

rule Aetheris_Encoded_PowerShell {
    meta:
        description = "Encoded / download-and-run PowerShell"
        mitre_attack = "T1059.001"
    strings:
        $a = "FromBase64String" nocase
        $b = "DownloadString" nocase
        $c = "-enc" nocase
        $d = "IEX" nocase
        $e = "Invoke-Expression" nocase
    condition:
        2 of them
}
"""


@dataclass
class YaraMatch:
    rule: str
    pid: int = 0
    name: str = ""
    address: int = 0
    tags: list[str] = field(default_factory=list)
    technique: str = ""
    description: str = ""


def available() -> bool:
    return _HAS_YARA


def rules_dir() -> Path:
    return config_dir() / "yara"


def load_rules(extra_source: str | None = None) -> Any:
    """Compile the built-in rules + any user rule files. A bad user rule falls
    back to the built-ins rather than disabling scanning. Returns None if yara
    is unavailable or nothing compiles."""
    if not _HAS_YARA:
        return None
    sources: dict[str, str] = {"aetheris_builtin": _BUILTIN_RULES}
    if extra_source:
        sources["session"] = extra_source
    d = rules_dir()
    if d.is_dir():
        for f in sorted(d.glob("*.yar")) + sorted(d.glob("*.yara")):
            try:
                sources[f.stem] = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
    try:
        return yara.compile(sources=sources)
    except yara.Error as exc:
        logbus.warn(SRC, f"YARA compile failed ({exc}); using built-ins only")
        try:
            return yara.compile(source=_BUILTIN_RULES)
        except yara.Error:
            return None


def _to_match(m: Any, pid: int, name: str, address: int) -> YaraMatch:
    meta = getattr(m, "meta", {}) or {}
    return YaraMatch(
        rule=getattr(m, "rule", "?"), pid=pid, name=name, address=address,
        tags=list(getattr(m, "tags", []) or []),
        technique=str(meta.get("mitre_attack", "")),
        description=str(meta.get("description", "")))


def scan_bytes(rules: Any, data: bytes, pid: int = 0, name: str = "",
               address: int = 0) -> list[YaraMatch]:
    if rules is None or not data:
        return []
    try:
        return [_to_match(m, pid, name, address) for m in rules.match(data=bytes(data))]
    except Exception as exc:  # noqa: BLE001
        logbus.trace(SRC, f"scan_bytes failed: {exc}")
        return []


def scan_process(rules: Any, backend: MemoryBackend, pid: int, name: str = "",
                 skip_image: bool = True) -> list[YaraMatch]:
    """Scan a process's committed regions. By default image-backed regions are
    skipped -- injected code lives in private/mapped memory, and scanning mapped
    DLL images just matches their export-name strings (noisy + slow)."""
    if rules is None:
        return []
    out: list[YaraMatch] = []
    for r in backend.memory_map(pid):
        if r.size <= 0 or r.size > _MAX_REGION:
            continue
        if skip_image and r.type == "image":
            continue
        data = backend.read(pid, r.base, r.size)
        if data:
            out += scan_bytes(rules, data, pid, name, r.base)
    return out


def scan_file(rules: Any, path: str) -> list[YaraMatch]:
    if rules is None:
        return []
    try:
        return [_to_match(m, 0, path, 0) for m in rules.match(filepath=path)]
    except Exception as exc:  # noqa: BLE001
        logbus.trace(SRC, f"scan_file failed for {path}: {exc}")
        return []
