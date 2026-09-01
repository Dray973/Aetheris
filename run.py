#!/usr/bin/env python3
"""
Aetheris Quantum Core — Advanced Systems Instrumentation Suite
Entry point / elevation bootstrap.

This launcher checks for administrative rights and (optionally) relaunches the
application elevated via the standard UAC "runas" verb. It intentionally does
*not* impersonate TrustedInstaller or spawn a hidden SYSTEM daemon — the
inspection features in this suite only require an elevated token with a small
set of privileges enabled (see aetheris/core/privileges.py).

Usage:
    python run.py                # launch, prompt for elevation if not admin
    python run.py --no-elevate   # launch with whatever token we already have
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main() -> int:
    argv = sys.argv[1:]
    if argv and argv[0] == "cli":
        from aetheris.cli import main as cli_main
        return cli_main(argv[1:])

    no_elevate = "--no-elevate" in sys.argv

    if sys.platform == "win32" and not no_elevate:
        from aetheris.core import privileges

        if not privileges.is_elevated():
            print("[bootstrap] Not elevated — requesting UAC elevation…")
            if privileges.relaunch_as_admin(extra_args=["--no-elevate"]):
                return 0
            print("[bootstrap] Elevation declined or failed; continuing "
                  "with current rights (many features will be limited).")

    try:
        from aetheris.core import updater
        if updater.apply_pending():
            print("[bootstrap] Applying staged update; relaunching…")
            return 0
    except Exception:
        pass

    from aetheris.main import run_app
    return run_app()


if __name__ == "__main__":
    raise SystemExit(main())
