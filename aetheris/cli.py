#!/usr/bin/env python3
"""
Aetheris headless CLI — dump forensic reports without the GUI.

    aetheris-cli report --format html --out session.html
    aetheris-cli processes --format csv --out procs.csv
    aetheris-cli connections --format json
    aetheris-cli plugins
    aetheris-cli run top-memory --out top.txt
    aetheris-cli hunt --format sarif --out hunt.sarif

Scheduled capture: repeat any command on an interval, writing timestamped files.

    aetheris-cli report --format html --out session.html --interval 300 --count 12

No Qt is imported — this runs anywhere the core deps (psutil) are installed, so
it's suitable for cron / Task Scheduler.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from .core import plugins, report


def _hunt(fmt: str, scan_injection: bool, scan_yara: bool,
          baseline_path: str | None = None, new_only: bool = False,
          save_baseline: str | None = None) -> tuple[str, str]:
    """Run the threat hunt and render it. SARIF is the default machine format.

    ``baseline_path`` ("default" = the one saved from the GUI) tags every
    finding new / escalated / known; ``new_only`` then drops the known ones.
    ``save_baseline`` writes this hunt as the new known-good state.
    """
    import platform

    from . import __version__
    from .analysis import baseline as bl
    from .analysis import export, findings

    found = findings.gather(scan_injection=scan_injection, scan_yara=scan_yara)
    host = platform.node()

    base: bl.Baseline | None = None
    if baseline_path:
        path = bl.default_path() if baseline_path == "default" else baseline_path
        try:
            base = bl.load(path)
        except (OSError, ValueError, KeyError) as exc:
            raise ValueError(f"cannot read baseline {path}: {exc}") from exc
    elif new_only:
        raise ValueError("--new-only needs --baseline")
    if base is not None and new_only:
        found = [f for f in found if base.status(f) != bl.KNOWN]
    if save_baseline:
        target = bl.default_path() if save_baseline == "default" else save_baseline
        bl.Baseline.from_findings(found, host=host).save(target)
        print(f"baseline saved: {target} ({len(found)} finding(s) accepted)",
              file=sys.stderr)

    if fmt == "sarif":
        return export.render_sarif(found, __version__, host, base), "sarif"
    if fmt == "json":
        return export.render_json(found, base), "json"
    if fmt == "csv":
        rows = export.to_rows(found, base)
        headers = ["severity", "score", "category", "technique", "subject", "title"]
        if base is not None:
            headers.append("baseline")
        return report.rows_to_csv(headers, [[r[h] for h in headers] for r in rows]), "csv"
    md = export.render_markdown(found, baseline=base)
    if fmt == "md":
        return md, "md"
    return report.html_document("Threat Hunt", [("Findings", "pre", md)]), "html"


def _gen(cmd: str, fmt: str) -> tuple[str, str]:
    """Return (content, default_extension) for a command + format."""
    from .forensics import processes
    from .network import connections

    if fmt == "sarif":
        raise ValueError("--format sarif applies to the hunt command")

    if cmd == "report":
        procs = processes.snapshot(sign=True)
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


def _timestamped(path: str, index: int = 0, count: int = 1) -> str:
    """Unique output name for capture `index` (0-based) of a `count`-long run.

    The capture index makes each name distinct *without* relying on the previous
    file already being on disk, so rapid same-second captures never collide (and
    it works for zero-length or not-yet-flushed writes too). A trailing
    existence check is kept only as a backstop for collisions across separate
    runs that happen to land in the same second.
    """
    p = Path(path)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    seq = f"-{index + 1:0{len(str(max(count, 1)))}d}" if count > 1 else ""
    base = f"{p.stem}-{stamp}{seq}"
    cand = p.with_name(f"{base}{p.suffix}")
    i = 1
    while cand.exists():
        cand = p.with_name(f"{base}-{i}{p.suffix}")
        i += 1
    return str(cand)


def _emit(content: str, out: str | None, index: int = 0, count: int = 1) -> None:
    if not out:
        sys.stdout.write(content + ("\n" if not content.endswith("\n") else ""))
        return
    path = _timestamped(out, index, count) if count > 1 else out
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(content)
    print(f"wrote {path} ({len(content):,} bytes)")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="aetheris-cli",
                                 description="Aetheris headless forensic capture")
    ap.add_argument("--format", "-f", default="html",
                    choices=["html", "md", "csv", "json", "sarif"])
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
    huntp = sub.add_parser("hunt", help="threat hunt: correlated ATT&CK findings "
                                        "(sarif/json/csv/md/html)")
    huntp.add_argument("--no-injection", action="store_true",
                       help="skip the memory-injection scan (faster)")
    huntp.add_argument("--yara", action="store_true",
                       help="also scan suspect processes with YARA rules")
    huntp.add_argument("--baseline", metavar="PATH",
                       help="compare against a saved baseline ('default' = the "
                            "GUI's); tags findings new/escalated/known")
    huntp.add_argument("--new-only", action="store_true",
                       help="with --baseline, drop findings already accepted")
    huntp.add_argument("--save-baseline", metavar="PATH",
                       help="accept this hunt as known-good ('default' = the GUI's)")

    args = ap.parse_args(argv)

    if args.command == "plugins":
        for p in plugins.discover():
            src = f"  [{p.source}]" if p.source else ""
            print(f"{p.name:<22} {p.description}{src}")
        return 0

    count = max(args.count, 1)

    def one_capture(index: int) -> None:
        if args.command == "hunt":
            try:
                content, _ext = _hunt(args.format, not args.no_injection, args.yara,
                                      args.baseline, args.new_only, args.save_baseline)
            except ValueError as exc:
                print(f"aetheris-cli: {exc}", file=sys.stderr)
                raise SystemExit(2) from exc
            _emit(content, args.out, index, count)
        elif args.command == "run":
            ok, content = plugins.run_plugin(args.plugin)
            if not ok:
                print(content, file=sys.stderr)
                return
            _emit(content, args.out, index, count)
        else:
            try:
                content, _ext = _gen(args.command, args.format)
            except ValueError as exc:
                print(f"aetheris-cli: {exc}", file=sys.stderr)
                raise SystemExit(2) from exc
            _emit(content, args.out, index, count)

    for i in range(count):
        one_capture(i)
        if i < count - 1 and args.interval > 0:
            time.sleep(args.interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
