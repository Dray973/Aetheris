#!/usr/bin/env python3
"""
Aetheris headless CLI — dump forensic reports without the GUI.

    aetheris-cli report --format html --out session.html
    aetheris-cli processes --format csv --out procs.csv
    aetheris-cli connections --format json
    aetheris-cli plugins
    aetheris-cli run top-memory --out top.txt

Scheduled capture: repeat any command on an interval, writing timestamped files.

    aetheris-cli report --format html --out session.html --interval 300 --count 12

No Qt is imported — this runs anywhere the core deps (psutil) are installed, so
it's suitable for cron / Task Scheduler.
"""
from __future__ import annotations

import sys
import time
import argparse
from pathlib import Path

from .core import report, plugins


def _gen(cmd: str, fmt: str) -> tuple[str, str]:
    """Return (content, default_extension) for a command + format."""
    from .forensics import processes
    from .network import connections

    if cmd == "report":
        procs = processes.snapshot()
        conns = connections.snapshot(resolve_geo=True)
        if fmt == "md":
            return report.session_markdown(procs, conns), "md"
        return report.session_html(procs, conns), "html"

    if cmd == "processes":
        rows = report.process_rows(processes.snapshot())
        if fmt == "json":
            return report.rows_to_json(rows), "json"
        headers = list(rows[0].keys()) if rows else []
        return report.rows_to_csv(headers, [[r[h] for h in headers] for r in rows]), "csv"

    if cmd == "connections":
        rows = report.connection_rows(connections.snapshot(resolve_geo=True))
        if fmt == "json":
            return report.rows_to_json(rows), "json"
        headers = list(rows[0].keys()) if rows else []
        return report.rows_to_csv(headers, [[r[h] for h in headers] for r in rows]), "csv"

    raise ValueError(f"unknown command {cmd!r}")


def _timestamped(path: str) -> str:
    p = Path(path)
    base = f"{p.stem}-{time.strftime('%Y%m%d-%H%M%S')}"
    cand = p.with_name(f"{base}{p.suffix}")
    i = 1
    while cand.exists():                      # avoid collisions on rapid captures
        cand = p.with_name(f"{base}-{i}{p.suffix}")
        i += 1
    return str(cand)


def _emit(content: str, out: str | None, stamp: bool) -> None:
    if not out:
        sys.stdout.write(content + ("\n" if not content.endswith("\n") else ""))
        return
    path = _timestamped(out) if stamp else out
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(content)
    print(f"wrote {path} ({len(content):,} bytes)")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="aetheris-cli",
                                 description="Aetheris headless forensic capture")
    ap.add_argument("--format", "-f", default="html",
                    choices=["html", "md", "csv", "json"])
    ap.add_argument("--out", "-o", help="output file (stdout if omitted)")
    ap.add_argument("--interval", type=float, default=0,
                    help="seconds between repeats (scheduled capture)")
    ap.add_argument("--count", type=int, default=1,
                    help="number of captures (with --interval)")

    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("report", help="full session report (html/md)")
    sub.add_parser("processes", help="process table (csv/json)")
    sub.add_parser("connections", help="connection table (csv/json)")
    sub.add_parser("plugins", help="list available plugins")
    runp = sub.add_parser("run", help="run a plugin by name")
    runp.add_argument("plugin")

    args = ap.parse_args(argv)

    if args.command == "plugins":
        for p in plugins.discover():
            src = f"  [{p.source}]" if p.source else ""
            print(f"{p.name:<22} {p.description}{src}")
        return 0

    def one_capture() -> None:
        if args.command == "run":
            ok, content = plugins.run_plugin(args.plugin)
            if not ok:
                print(content, file=sys.stderr)
                return
            _emit(content, args.out, stamp=args.count > 1)
        else:
            content, _ext = _gen(args.command, args.format)
            _emit(content, args.out, stamp=args.count > 1)

    count = max(args.count, 1)
    for i in range(count):
        one_capture()
        if i < count - 1 and args.interval > 0:
            time.sleep(args.interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
