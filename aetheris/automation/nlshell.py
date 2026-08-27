"""
Auto-Shell Engine — natural language → reviewed PowerShell.

A deterministic intent router (not an LLM) turns a bounded set of plain-English
instructions into PowerShell scripts. The design contract is:

  1. compile(text) -> CompiledCommand   (never executes anything)
  2. UI shows CompiledCommand.script + .explanation
  3. only after explicit user validation does the UI call run(cmd)

This keeps a human in the loop for every state change, and keeps generation
auditable and testable. Unmatched inputs return a safe "no intent matched"
result rather than guessing.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from typing import Callable

from ..core import logbus

SRC = "automation.nlshell"

_DRIVES = {
    "desktop": r"$([Environment]::GetFolderPath('Desktop'))",
    "documents": r"$([Environment]::GetFolderPath('MyDocuments'))",
    "downloads": r"$env:USERPROFILE\Downloads",
}
_BROWSERS = ("chrome", "msedge", "firefox", "brave", "opera")


@dataclass
class CompiledCommand:
    intent: str
    explanation: str
    script: str
    risk: str = "medium"       # low / medium / high
    requires_confirm: bool = True
    matched: bool = True
    warnings: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Intent handlers. Each returns a CompiledCommand or None (no match).
# --------------------------------------------------------------------------
def _find_and_move(text: str) -> CompiledCommand | None:
    m = re.search(
        r"find .*?(?P<ext>\b\w{2,5}\b)\s+(?:archives?|files?).*?"
        r"(?:move|copy).*?to\s+(?:my\s+)?(?P<dest>desktop|documents|downloads)",
        text, re.IGNORECASE,
    )
    if not m:
        return None
    ext = m.group("ext").lower().lstrip(".")
    if ext in {"zip", "archive"}:
        ext = "zip"
    # Drive is extracted independently so a lazy quantifier can't skip it;
    # accepts "on drive E", "drive E:", or "E:".
    drive = "C"
    dm = re.search(r"\bdrive\s+([a-zA-Z])\b|\b([a-zA-Z]):", text, re.IGNORECASE)
    if dm:
        drive = (dm.group(1) or dm.group(2)).upper()
    dest = _DRIVES[m.group("dest").lower()]
    verb = "Copy" if re.search(r"\bcopy\b", text, re.IGNORECASE) else "Move"
    time_filter = ""
    explain_time = ""
    if re.search(r"this morning|today", text, re.IGNORECASE):
        time_filter = " | Where-Object { $_.CreationTime.Date -eq (Get-Date).Date }"
        explain_time = " created today"
    script = (
        f"Get-ChildItem -Path '{drive}:\\' -Recurse -File -Filter '*.{ext}' "
        f"-ErrorAction SilentlyContinue{time_filter} | "
        f"{verb}-Item -Destination \"{dest}\" -Verbose"
    )
    return CompiledCommand(
        intent="find_and_move_files",
        explanation=(f"{verb} every *.{ext} file{explain_time} found on drive "
                     f"{drive}: to your {m.group('dest').lower()}."),
        script=script,
        risk="medium",
        warnings=["Recursive filesystem scan can be slow on large drives."],
    )


def _kill_by_memory(text: str) -> CompiledCommand | None:
    m = re.search(
        r"(?:terminate|kill|close|stop).*?(?:more than|over|above|>)\s*"
        r"(?P<n>\d+)\s*(?P<unit>gb|mb|kb)",
        text, re.IGNORECASE,
    )
    if not m:
        return None
    n = int(m.group("n"))
    unit = m.group("unit").lower()
    factor = {"kb": 1024, "mb": 1024 ** 2, "gb": 1024 ** 3}[unit]
    threshold = n * factor
    script = (
        f"Get-Process | Where-Object {{ $_.WorkingSet64 -gt {threshold} }} | "
        f"Sort-Object WorkingSet64 -Descending | "
        f"ForEach-Object {{ Write-Host ('Stopping ' + $_.ProcessName + ' (' + "
        f"[math]::Round($_.WorkingSet64/1MB) + ' MB)'); "
        f"Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }}"
    )
    return CompiledCommand(
        intent="terminate_by_memory",
        explanation=f"Force-terminate every process using more than {n} {unit.upper()} "
                    f"of working-set memory.",
        script=script,
        risk="high",
        warnings=["This can close apps with unsaved work and may hit system services."],
    )


def _set_affinity(text: str) -> CompiledCommand | None:
    if not re.search(r"isolate|affinity|pin|cores?", text, re.IGNORECASE):
        return None
    cores = [int(x) for x in re.findall(r"\b(\d{1,2})\b", text)]
    if not cores:
        return None
    target = "chrome"
    for b in _BROWSERS:
        if b in text.lower() or (b == "chrome" and "browser" in text.lower()):
            target = b
            break
    mask = 0
    for c in cores:
        mask |= (1 << c)
    script = (
        f"Get-Process -Name '{target}' -ErrorAction SilentlyContinue | "
        f"ForEach-Object {{ $_.ProcessorAffinity = [IntPtr]{mask}; "
        f"Write-Host ('Pinned ' + $_.ProcessName + ' -> mask 0x{mask:X}') }}"
    )
    return CompiledCommand(
        intent="set_cpu_affinity",
        explanation=f"Pin '{target}' processes to CPU cores {cores} "
                    f"(affinity mask 0x{mask:X}).",
        script=script,
        risk="low",
        warnings=[],
    )


_STOP_NAMES = {"processes", "process", "background", "tasks", "apps",
               "programs", "everything", "things", "them"}


def _kill_by_name(text: str) -> CompiledCommand | None:
    # Let the memory-threshold handler own size-based phrasing.
    if re.search(r"more than|less than|\b\d+\s*(gb|mb|kb)\b", text, re.IGNORECASE):
        return None
    m = re.search(
        r"(?:kill|terminate|close|stop|end)\s+(?:all|every)\s+(?P<name>[a-zA-Z][\w.-]*)",
        text, re.IGNORECASE,
    )
    if not m:
        return None
    name = m.group("name")
    if name.lower() in _STOP_NAMES:
        return None                      # refuse "kill all processes" style
    proc = name[:-4] if name.lower().endswith(".exe") else name
    script = (f"Get-Process -Name '{proc}' -ErrorAction SilentlyContinue | "
              f"Stop-Process -Force -Verbose")
    return CompiledCommand(
        intent="terminate_by_name",
        explanation=f"Force-terminate every '{proc}' process.",
        script=script, risk="high",
        warnings=["Closes all matching windows; unsaved work may be lost."],
    )


def _flush_dns(text: str) -> CompiledCommand | None:
    if not re.search(r"\b(flush|clear|reset)\b.*\bdns\b", text, re.IGNORECASE):
        return None
    return CompiledCommand(
        intent="flush_dns",
        explanation="Flush the Windows DNS resolver cache.",
        script="ipconfig /flushdns", risk="low",
    )


def _empty_recycle_bin(text: str) -> CompiledCommand | None:
    if not re.search(r"\b(empty|clear|clean)\b.*\brecycle\s*bin\b", text, re.IGNORECASE):
        return None
    return CompiledCommand(
        intent="empty_recycle_bin",
        explanation="Permanently empty the Recycle Bin on all drives.",
        script="Clear-RecycleBin -Force -ErrorAction SilentlyContinue",
        risk="medium", warnings=["Recycled items cannot be recovered afterwards."],
    )


def _clear_temp(text: str) -> CompiledCommand | None:
    if not re.search(r"\b(clear|clean|delete|remove|purge)\b.*\btemp(orary)?\b",
                     text, re.IGNORECASE):
        return None
    script = ("Get-ChildItem -Path $env:TEMP -Recurse -Force -ErrorAction SilentlyContinue | "
              "Remove-Item -Recurse -Force -ErrorAction SilentlyContinue -Verbose")
    return CompiledCommand(
        intent="clear_temp_files",
        explanation="Delete the contents of your per-user TEMP folder.",
        script=script, risk="medium",
        warnings=["Files currently in use are skipped."],
    )


_SERVICE_ALIASES = {
    "print spooler": "Spooler", "spooler": "Spooler",
    "windows update": "wuauserv", "dns client": "Dnscache",
    "diagtrack": "DiagTrack", "connected user experiences": "DiagTrack",
    "windows search": "WSearch", "superfetch": "SysMain", "sysmain": "SysMain",
}


def _restart_service(text: str) -> CompiledCommand | None:
    m = re.search(r"restart\s+(?:the\s+)?(?P<svc>[\w .-]+?)\s+service", text, re.IGNORECASE)
    if not m:
        return None
    svc = m.group("svc").strip()
    name = _SERVICE_ALIASES.get(svc.lower(), svc)
    return CompiledCommand(
        intent="restart_service",
        explanation=f"Restart the '{name}' Windows service.",
        script=f"Restart-Service -Name '{name}' -Force -Verbose",
        risk="medium",
        warnings=["Dependent services may restart too."],
    )


def _largest_files(text: str) -> CompiledCommand | None:
    if not re.search(r"\b(largest|biggest|top)\b.*\bfiles?\b", text, re.IGNORECASE):
        return None
    dm = re.search(r"\bin\s+(?:my\s+)?(desktop|documents|downloads)\b", text, re.IGNORECASE)
    if dm:
        path = _DRIVES[dm.group(1).lower()]
    else:
        drv = re.search(r"\bdrive\s+([a-zA-Z])\b|\b([a-zA-Z]):", text, re.IGNORECASE)
        path = (f"{(drv.group(1) or drv.group(2)).upper()}:\\" if drv else "C:\\")
    nm = re.search(r"\btop\s+(\d{1,3})\b|\b(\d{1,3})\s+(?:largest|biggest)\b", text, re.IGNORECASE)
    n = int((nm.group(1) or nm.group(2))) if nm else 20
    script = (
        f"Get-ChildItem -Path \"{path}\" -Recurse -File -ErrorAction SilentlyContinue | "
        f"Sort-Object Length -Descending | Select-Object -First {n} "
        f"FullName, @{{N='SizeMB';E={{[math]::Round($_.Length/1MB,1)}}}} | Format-Table -AutoSize"
    )
    return CompiledCommand(
        intent="largest_files",
        explanation=f"List the {n} largest files under {path} (read-only report).",
        script=script, risk="low",
    )


_HANDLERS: tuple[Callable[[str], "CompiledCommand | None"], ...] = (
    _find_and_move,
    _kill_by_memory,
    _kill_by_name,
    _set_affinity,
    _flush_dns,
    _empty_recycle_bin,
    _clear_temp,
    _restart_service,
    _largest_files,
)


def compile(text: str) -> CompiledCommand:
    """Translate plain English into a reviewed (not executed) PowerShell command."""
    text = text.strip()
    for handler in _HANDLERS:
        result = handler(text)
        if result is not None:
            logbus.trace(SRC, f"intent matched: {result.intent}")
            return result
    logbus.trace(SRC, "no intent matched")
    return CompiledCommand(
        intent="unmatched",
        explanation="No known intent matched this instruction. "
                    "Nothing will run. Try rephrasing.",
        script="",
        risk="low",
        requires_confirm=False,
        matched=False,
    )


def run(cmd: CompiledCommand, timeout: int = 120) -> tuple[bool, str]:
    """Execute a compiled command's script. UI calls this only post-confirmation."""
    if not cmd.matched or not cmd.script:
        return False, "nothing to run"
    logbus.action(SRC, f"executing intent {cmd.intent}")
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd.script],
            capture_output=True, text=True, timeout=timeout,
        )
        out = (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr else "")
        ok = proc.returncode == 0
        logbus.success(SRC, f"intent {cmd.intent} finished rc={proc.returncode}")
        return ok, out.strip() or f"(exit {proc.returncode})"
    except subprocess.TimeoutExpired:
        return False, "timed out"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)
