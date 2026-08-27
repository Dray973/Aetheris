"""
Forensic report generation.

Pure, dependency-free serializers so any tab can export its current view, plus a
styled self-contained HTML session report. Everything here is a deterministic
string transform (no I/O, no Qt), which keeps it unit-testable.

  * rows_to_csv / rows_to_json — generic table serializers
  * process_rows / connection_rows — dataclass → row dicts
  * system_summary — host/OS/CPU/RAM snapshot (best effort)
  * html_document — a dark-themed, self-contained HTML page from sections
  * session_markdown — a Markdown session report
"""
from __future__ import annotations

import io
import csv
import json
import time
import platform
from typing import Any, Iterable, Sequence

APP = "Aetheris Quantum Core"


# --------------------------------------------------------------------------
# Generic serializers
# --------------------------------------------------------------------------
def rows_to_csv(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(headers)
    for r in rows:
        w.writerow(r)
    return buf.getvalue()


def rows_to_json(rows: Iterable[dict]) -> str:
    return json.dumps(list(rows), indent=2, default=str)


def escape_html(s: Any) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


# --------------------------------------------------------------------------
# Domain row builders
# --------------------------------------------------------------------------
def process_rows(procs: Iterable) -> list[dict]:
    out = []
    for p in procs:
        out.append({
            "pid": p.pid, "name": p.name, "user": p.username,
            "cpu_percent": p.cpu_percent, "mem_rss": p.mem_rss,
            "threads": p.num_threads, "status": p.status, "exe": p.exe,
            "dep": p.dep, "aslr": p.aslr, "signature": p.signature,
        })
    return out


def connection_rows(conns: Iterable) -> list[dict]:
    out = []
    for c in conns:
        out.append({
            "pid": c.pid, "process": c.proc_name, "proto": c.kind,
            "family": c.family, "local": f"{c.laddr}:{c.lport}",
            "remote": c.raddr, "rport": c.rport, "status": c.status,
            "class": c.remote_class, "rdns": c.rdns, "geo": c.geo,
        })
    return out


# --------------------------------------------------------------------------
# System summary
# --------------------------------------------------------------------------
def system_summary() -> dict[str, Any]:
    info: dict[str, Any] = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "host": platform.node(),
        "os": f"{platform.system()} {platform.release()} ({platform.version()})",
        "machine": platform.machine(),
        "python": platform.python_version(),
    }
    try:
        import psutil
        vm = psutil.virtual_memory()
        info["cpu_logical"] = psutil.cpu_count()
        info["cpu_percent"] = psutil.cpu_percent(interval=None)
        info["ram_total"] = vm.total
        info["ram_used_percent"] = vm.percent
    except Exception:
        pass
    return info


# --------------------------------------------------------------------------
# HTML report
# --------------------------------------------------------------------------
_HTML_HEAD = """<!doctype html><html><head><meta charset="utf-8">
<title>{title}</title><style>
body{{background:#0b0e14;color:#c8d3f5;font-family:Segoe UI,Arial,sans-serif;margin:24px}}
h1{{color:#7dd3fc}} h2{{color:#7dd3fc;border-bottom:1px solid #1c2333;padding-bottom:4px;margin-top:28px}}
table{{border-collapse:collapse;width:100%;font-size:13px}}
th{{background:#131a28;color:#7dd3fc;text-align:left;padding:6px;border-bottom:1px solid #24304a}}
td{{padding:5px 6px;border-bottom:1px solid #12161f}}
tr:nth-child(even) td{{background:#0d111a}}
pre{{background:#0d111a;border:1px solid #1c2333;padding:12px;overflow:auto;white-space:pre-wrap}}
.kv td:first-child{{color:#6b7699;width:180px}} .sub{{color:#6b7699}}
</style></head><body>"""


def html_document(title: str, sections: list[tuple[str, str, Any]]) -> str:
    """
    Build a self-contained HTML report. Each section is (heading, kind, data):
      kind 'kv'    -> data is a dict
      kind 'table' -> data is (headers, rows)
      kind 'pre'   -> data is preformatted text
    """
    parts = [_HTML_HEAD.format(title=escape_html(title))]
    parts.append(f"<h1>{escape_html(title)}</h1>")
    parts.append(f"<div class='sub'>{escape_html(APP)} · "
                 f"{escape_html(time.strftime('%Y-%m-%d %H:%M:%S'))}</div>")
    for heading, kind, data in sections:
        parts.append(f"<h2>{escape_html(heading)}</h2>")
        if kind == "kv":
            parts.append("<table class='kv'>")
            for k, v in data.items():
                parts.append(f"<tr><td>{escape_html(k)}</td>"
                             f"<td>{escape_html(v)}</td></tr>")
            parts.append("</table>")
        elif kind == "table":
            headers, rows = data
            parts.append("<table><tr>"
                         + "".join(f"<th>{escape_html(h)}</th>" for h in headers)
                         + "</tr>")
            for r in rows:
                parts.append("<tr>" + "".join(f"<td>{escape_html(c)}</td>"
                             for c in r) + "</tr>")
            parts.append("</table>")
        elif kind == "pre":
            parts.append(f"<pre>{escape_html(data)}</pre>")
    parts.append("</body></html>")
    return "\n".join(parts)


def session_html(procs: Iterable, conns: Iterable) -> str:
    """Full session report as a self-contained HTML document."""
    top = sorted(process_rows(procs), key=lambda r: r["mem_rss"], reverse=True)[:30]
    crows = [c for c in connection_rows(conns) if c["remote"]]
    return html_document("Session Report", [
        ("System", "kv", system_summary()),
        ("Top processes by memory", "table",
         (["PID", "Name", "Mem (MB)", "CPU %", "Threads", "Exe"],
          [[r["pid"], r["name"], f"{r['mem_rss'] / 1048576:,.1f}",
            f"{r['cpu_percent']:.1f}", r["threads"], r["exe"]] for r in top])),
        (f"Active remote connections ({len(crows)})", "table",
         (["PID", "Process", "Remote", "Port", "Class", "Geo", "rDNS"],
          [[c["pid"], c["process"], c["remote"], c["rport"], c["class"],
            c["geo"], c["rdns"]] for c in crows])),
    ])


def session_markdown(procs: Iterable, conns: Iterable, extra: str = "") -> str:
    info = system_summary()
    lines = [f"# {APP} — Session Report", ""]
    for k, v in info.items():
        lines.append(f"- **{k}:** {v}")
    lines += ["", "## Top processes by memory", "",
              "| PID | Name | Mem (MB) | CPU % | Threads |",
              "|----:|------|---------:|------:|--------:|"]
    top = sorted(process_rows(procs), key=lambda r: r["mem_rss"], reverse=True)[:20]
    for r in top:
        lines.append(f"| {r['pid']} | {r['name']} | "
                     f"{r['mem_rss'] / 1048576:,.1f} | {r['cpu_percent']:.1f} | "
                     f"{r['threads']} |")
    crows = [c for c in connection_rows(conns) if c["remote"]]
    lines += ["", f"## Active remote connections ({len(crows)})", "",
              "| PID | Process | Remote | Port | Class | Geo |",
              "|----:|---------|--------|-----:|-------|-----|"]
    for c in crows[:50]:
        lines.append(f"| {c['pid']} | {c['process']} | {c['remote']} | "
                     f"{c['rport']} | {c['class']} | {c['geo']} |")
    if extra:
        lines += ["", extra]
    return "\n".join(lines)
