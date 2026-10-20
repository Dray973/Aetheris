"""
Export threat-hunt findings: SARIF 2.1.0, JSON, and Markdown.

SARIF is the interchange format security tooling already reads -- GitHub code
scanning, Azure DevOps, VS Code's SARIF viewer, and most SIEM importers -- so a
hunt can be archived, diffed between machines, or fed into an existing triage
pipeline instead of living only in the GUI.

Pure: every function takes ``Finding`` objects and returns data or text, so the
whole module tests without an OS. Mapping choices worth knowing:

* One SARIF **rule** per ATT&CK technique + category (``AQC-T1036``,
  ``AQC-persistence-T1547``...), so a consumer groups results the way an
  analyst would. Correlated findings get a single ``AQC-correlated`` rule and
  carry every merged technique in their tags.
* ``level`` follows severity (critical/high -> error, medium -> warning,
  low -> note), and ``security-severity`` is score / 10 -- the property GitHub
  uses to rank security alerts.
* A finding's correlation key goes into ``partialFingerprints`` so the same
  binary flagged on two runs is recognised as the same result.
* A location is emitted only when the evidence names a real path; a socket or
  a memory region is described logically instead of inventing a file.
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable, Sequence
from typing import Any

from .findings import Finding

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "Aetheris Quantum Core"
TOOL_URI = "https://github.com/Dray973/Aetheris"

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
# Evidence lines that carry the subject's file path, in preference order.
_PATH_PREFIXES = ("exe: ", "binary: ", "ImagePath: ")
_WIN_PATH_RE = re.compile(r'^"?([A-Za-z]:\\[^"]+?)"?(?:\s+-|\s+/|$)')


def attack_url(technique: str) -> str:
    """ATT&CK page for ``T1053.005`` -> .../techniques/T1053/005/."""
    return "https://attack.mitre.org/techniques/" + technique.replace(".", "/") + "/"


def techniques_of(f: Finding) -> list[str]:
    """Every ATT&CK id a finding carries (correlated ones carry several)."""
    seen: dict[str, None] = {}
    for t in _TECHNIQUE_RE.findall(f"{f.technique} {f.technique_name}"):
        seen.setdefault(t, None)
    return list(seen)


def rule_id(f: Finding) -> str:
    if f.category == "correlated":
        return "AQC-correlated"
    tech = techniques_of(f)
    return f"AQC-{f.category}-{tech[0]}" if tech else f"AQC-{f.category}"


def file_path_of(f: Finding) -> str | None:
    """The Windows file path the evidence names for this subject, if any.

    Takes the first path-bearing line and strips quoting and trailing
    arguments (an ImagePath like ``C:\\Program Files\\x.exe -k svc``).
    """
    for line in f.evidence:
        text = line.strip().lstrip("•").strip()
        for prefix in _PATH_PREFIXES:
            if text.startswith(prefix):
                m = _WIN_PATH_RE.match(text[len(prefix):].strip())
                if m:
                    return m.group(1).strip()
    return None


def _file_uri(path: str) -> str:
    # file:///C:/dir/x%20y.exe -- the form SARIF viewers resolve on Windows.
    from urllib.parse import quote
    return "file:///" + quote(path.replace("\\", "/"), safe="/:")


def _rule(f: Finding) -> dict[str, Any]:
    techs = techniques_of(f)
    if f.category == "correlated":
        name = "CorrelatedSignals"
        short = "Several independent signals point at the same binary"
        full = ("Multiple detectors (process, network, persistence, tasks, services, "
                "memory, YARA) flagged the same subject; their scores were combined.")
    else:
        name = re.sub(r"[^A-Za-z0-9]+", "", f.technique_name.title()) or f.category
        short = f"{f.technique_name} ({f.category})"
        full = f"Aetheris {f.category} detector mapped to ATT&CK {', '.join(techs)}."
    rule: dict[str, Any] = {
        "id": rule_id(f),
        "name": name,
        "shortDescription": {"text": short},
        "fullDescription": {"text": full},
        "properties": {"tags": ["security", "attack", f.category, *techs]},
    }
    if techs and f.category != "correlated":
        rule["helpUri"] = attack_url(techs[0])
    return rule


def _result(f: Finding, rule_index: int) -> dict[str, Any]:
    location: dict[str, Any] = {
        "logicalLocations": [{"name": f.subject, "kind": "module"}],
    }
    path = file_path_of(f)
    if path:
        location["physicalLocation"] = {"artifactLocation": {"uri": _file_uri(path)}}
    return {
        "ruleId": rule_id(f),
        "ruleIndex": rule_index,
        "level": _LEVEL.get(f.severity, "warning"),
        "message": {"text": f"{f.title} -- {f.subject}"},
        "locations": [location],
        "partialFingerprints": {"aetherisFindingKey/v1": f"{f.category}:{f.key}"},
        "properties": {
            "score": f.score,
            "severity": f.severity,
            "security-severity": f"{f.score / 10:.1f}",
            "category": f.category,
            "techniques": techniques_of(f),
            "evidence": list(f.evidence),
            "suggestedResponses": list(f.actions),
        },
    }


def to_sarif(findings: Iterable[Finding], tool_version: str = "",
             host: str = "") -> dict[str, Any]:
    """Build a SARIF 2.1.0 log (as a dict) for one hunt."""
    findings = list(findings)
    rules: list[dict[str, Any]] = []
    index: dict[str, int] = {}
    results: list[dict[str, Any]] = []
    for f in findings:
        rid = rule_id(f)
        if rid not in index:
            index[rid] = len(rules)
            rules.append(_rule(f))
        results.append(_result(f, index[rid]))
    driver: dict[str, Any] = {"name": TOOL_NAME, "informationUri": TOOL_URI,
                              "rules": rules}
    if tool_version:
        driver["version"] = tool_version
    run: dict[str, Any] = {"tool": {"driver": driver}, "results": results}
    if host:
        run["properties"] = {"host": host}
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}


def render_sarif(findings: Iterable[Finding], tool_version: str = "",
                 host: str = "") -> str:
    return json.dumps(to_sarif(findings, tool_version, host), indent=2)


def to_rows(findings: Iterable[Finding]) -> list[dict[str, Any]]:
    """Plain dicts, one per finding -- for JSON export."""
    return [{
        "severity": f.severity, "score": f.score, "category": f.category,
        "technique": f.technique, "technique_name": f.technique_name,
        "techniques": techniques_of(f), "subject": f.subject, "title": f.title,
        "key": f.key, "evidence": list(f.evidence), "actions": list(f.actions),
    } for f in findings]


def render_json(findings: Iterable[Finding]) -> str:
    return json.dumps(to_rows(findings), indent=2)


def _md_cell(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def render_markdown(findings: Sequence[Finding], title: str = "Threat Hunt") -> str:
    counts = {s: sum(1 for f in findings if f.severity == s)
              for s in ("critical", "high", "medium", "low")}
    out = [f"# {title}", "",
           f"{len(findings)} finding(s): " + ", ".join(f"{n} {s}" for s, n in counts.items()),
           ""]
    if not findings:
        out.append("No findings -- nothing correlated as suspicious.")
        return "\n".join(out) + "\n"
    out += ["| Severity | Score | ATT&CK | Subject | Finding |",
            "|---|---:|---|---|---|"]
    for f in findings:
        out.append(f"| {f.severity.upper()} | {f.score} | {', '.join(techniques_of(f))} "
                   f"| {_md_cell(f.subject)} | {_md_cell(f.title)} |")
    for i, f in enumerate(findings, 1):
        out += ["", f"## {i}. {f.title}", "",
                f"- **Subject:** {f.subject}",
                f"- **Severity:** {f.severity} (score {f.score})",
                "- **ATT&CK:** " + ", ".join(
                    f"[{t}]({attack_url(t)})" for t in techniques_of(f)),
                "", "Evidence:", "", "```"]
        out += [e for e in f.evidence] + ["```"]
        if f.actions:
            out += ["", "Suggested responses:", ""]
            out += [f"- {a}" for a in f.actions]
    return "\n".join(out) + "\n"
