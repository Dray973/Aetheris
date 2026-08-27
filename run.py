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

import sys
import os

# Make the package importable when run as a loose script.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main() -> int:
    no_elevate = "--no-elevate" in sys.argv

    # Only meaningful on Windows; the app still imports/tests on other OSes.
    if sys.platform == "win32" and not no_elevate:
        from aetheris.core import privileges

        if not privileges.is_elevated():
            print("[bootstrap] Not elevated — requesting UAC elevation…")
            if privileges.relaunch_as_admin(extra_args=["--no-elevate"]):
                # A new elevated process was spawned; this one exits.
                return 0
            print("[bootstrap] Elevation declined or failed; continuing "
                  "with current rights (many features will be limited).")

    # Apply a previously-staged auto-update before the GUI loads. If one was
    # pending, this relaunches the new version and we exit now.
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
