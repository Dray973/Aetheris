"""
Scheduled-task auditor (defensive / forensic).

Read-only enumeration of *all* Windows scheduled tasks by parsing the task XML
under ``%WINDIR%\\System32\\Tasks``: name, author, triggers, actions, enabled
state, hidden flag, and the Authenticode status of the action binary. Suspicious
tasks are flagged -- actions launched from temp/download/public directories,
unsigned action binaries, obfuscated/encoded shell commands, and logon/boot
persistence.

This is an audit view, not a persistence tool (creation lives in
:mod:`aetheris.core.scheduler`, for the app's own capture task only). Reversible
enable/disable of a task is provided for remediating a flagged entry.

The XML parser and the suspicion heuristics are pure and unit-tested off-Windows.
"""
from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from . import logbus, signing

SRC = "core.taskaudit"

# Lowercased path fragments that make an action binary worth a second look.
_BAD_DIRS = ("\\temp\\", "\\tmp\\", "\\downloads\\", "\\appdata\\local\\temp\\",
             "\\users\\public\\", "\\programdata\\")
# Lowercased tokens that betray an obfuscated / download-and-run shell action.
_BAD_SHELL = ("-enc", "-encodedcommand", "downloadstring", "downloadfile",
              "iex", "invoke-expression", "frombase64", "-w hidden",
              "-windowstyle hidden", "-nop", "bypass")
# The strong signals that make a task "suspicious" (logon/boot alone is noisy).
_STRONG = frozenset({"temp/download/public-dir action",
                     "obfuscated/encoded shell command", "unsigned action binary"})


@dataclass
class TaskInfo:
    path: str                   # \Microsoft\Windows\...\TaskName
    name: str
    author: str
    description: str
    enabled: bool
    hidden: bool
    triggers: list[str]         # e.g. ["logon", "boot", "calendar"]
    actions: list[str]          # e.g. ["C:\\x.exe --arg", "COM:{...}"]
    action_binaries: list[str]  # parsed executable paths (unresolved)
    signed: str = "unknown"     # signature of the first action binary
    flags: list[str] = field(default_factory=list)


# -- pure XML parsing (no OS dependency) -----------------------------------
def _lname(elem) -> str:
    return elem.tag.rsplit("}", 1)[-1] if isinstance(elem.tag, str) else ""


def _child(parent, name: str):
    if parent is None:
        return None
    for c in parent:
        if _lname(c) == name:
            return c
    return None


def _text(parent, name: str, default: str = "") -> str:
    c = _child(parent, name)
    return (c.text or default).strip() if c is not None and c.text is not None else default


def parse_task_xml(xml_text: str, path: str = "") -> TaskInfo | None:
    """Parse one task's XML into a TaskInfo (namespace-agnostic). None if invalid."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    if _lname(root) != "Task":
        return None
    reg = _child(root, "RegistrationInfo")
    author = _text(reg, "Author")
    desc = _text(reg, "Description")

    settings = _child(root, "Settings")
    enabled = _text(settings, "Enabled", "true").lower() != "false"
    hidden = _text(settings, "Hidden", "false").lower() == "true"

    triggers: list[str] = []
    trig = _child(root, "Triggers")
    if trig is not None:
        for c in trig:
            triggers.append(_lname(c).replace("Trigger", "").lower())

    actions: list[str] = []
    action_binaries: list[str] = []
    acts = _child(root, "Actions")
    if acts is not None:
        for c in acts:
            ln = _lname(c)
            if ln == "Exec":
                cmd = _text(c, "Command")
                args = _text(c, "Arguments")
                if cmd:
                    action_binaries.append(cmd)
                    actions.append((cmd + " " + args).strip())
            elif ln == "ComHandler":
                actions.append("COM:" + _text(c, "ClassId"))

    name = path.rsplit("\\", 1)[-1] if path else (_text(reg, "URI").rsplit("\\", 1)[-1])
    return TaskInfo(path=path, name=name, author=author, description=desc,
                    enabled=enabled, hidden=hidden, triggers=triggers,
                    actions=actions, action_binaries=action_binaries)


def suspicion_flags(task: TaskInfo) -> list[str]:
    """Human-readable flags for a task (pure; ``signed`` must be set first)."""
    flags: list[str] = []
    if any(any(d in b.lower() for d in _BAD_DIRS) for b in task.action_binaries):
        flags.append("temp/download/public-dir action")
    if any(any(s in a.lower() for s in _BAD_SHELL) for a in task.actions):
        flags.append("obfuscated/encoded shell command")
    if task.signed == "unsigned":
        flags.append("unsigned action binary")
    if any(t in ("logon", "boot") for t in task.triggers):
        flags.append("runs at logon/boot")
    return flags


def is_suspicious(task: TaskInfo) -> bool:
    """True if a task carries at least one *strong* suspicion signal."""
    return any(f in _STRONG for f in task.flags)


def resolve_binary(command: str) -> str:
    return os.path.expandvars((command or "").strip().strip('"'))


# -- enumeration (Windows) --------------------------------------------------
def _read_task_xml(path: str) -> str | None:
    """Task XML files are UTF-16; fall back to UTF-8 for hand-placed ones."""
    try:
        raw = open(path, "rb").read()
    except OSError:
        return None
    for enc in ("utf-16", "utf-8-sig", "utf-8"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, UnicodeError):
            continue
    return None


def enumerate_tasks(check_signature: bool = True) -> list[TaskInfo]:
    """Parse every scheduled task under %WINDIR%\\System32\\Tasks."""
    root = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Tasks")
    out: list[TaskInfo] = []
    if not os.path.isdir(root):
        return out
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            full = os.path.join(dirpath, fn)
            xml = _read_task_xml(full)
            if not xml:
                continue
            rel = "\\" + os.path.relpath(full, root).replace("/", "\\")
            task = parse_task_xml(xml, rel)
            if task is None:
                continue
            if check_signature and task.action_binaries:
                task.signed = signing.label(resolve_binary(task.action_binaries[0]))
            task.flags = suspicion_flags(task)
            out.append(task)
    logbus.trace(SRC, f"audited {len(out)} scheduled tasks")
    return out


def suspicious_tasks(tasks: list[TaskInfo]) -> list[TaskInfo]:
    return [t for t in tasks if is_suspicious(t)]


def render_markdown(tasks: list[TaskInfo], only_suspicious: bool = True) -> str:
    """A Markdown table for the forensic report."""
    rows = suspicious_tasks(tasks) if only_suspicious else tasks
    title = "Suspicious scheduled tasks" if only_suspicious else "Scheduled tasks"
    if not rows:
        return f"## {title}\n\n_None flagged._\n"
    lines = [f"## {title} ({len(rows)})", "",
             "| Task | Enabled | Triggers | Signed | Flags | Action |",
             "|---|---|---|---|---|---|"]
    for t in rows:
        action = (t.actions[0] if t.actions else "").replace("|", "\\|")[:80]
        lines.append(
            f"| {t.path} | {'yes' if t.enabled else 'no'} | "
            f"{', '.join(t.triggers)} | {t.signed} | {'; '.join(t.flags)} | {action} |")
    return "\n".join(lines) + "\n"
