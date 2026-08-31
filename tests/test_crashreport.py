"""Crash reporter: scrubbed report + excepthook install."""
import os
import sys
from pathlib import Path

from aetheris.core import crashreport


def test_write_report_scrubs_account_name(tmp_path, monkeypatch):
    monkeypatch.setattr(crashreport, "crash_dir", lambda: tmp_path)
    monkeypatch.setenv("USERNAME", "alice")
    try:
        raise ValueError("boom near C:/Users/alice/secret/notes.txt")
    except ValueError:
        path = crashreport.write_report(*sys.exc_info())
    assert path
    text = Path(path).read_text(encoding="utf-8")
    assert "ValueError" in text and "boom" in text
    assert "crash report" in text.lower()
    assert "alice" not in text                       # account name redacted
    assert "<USER>" in text


def test_scrub_redacts_home_and_user(monkeypatch):
    monkeypatch.setenv("USERNAME", "bob")
    home = os.path.expanduser("~")
    out = crashreport._scrub(f"{home}\\Desktop and user bob and BOB")
    assert home not in out
    assert "bob" not in out.lower()


def test_install_is_idempotent_and_hooks_excepthook():
    prev = sys.excepthook
    try:
        crashreport._installed = False
        crashreport.install()
        assert sys.excepthook is not prev
        after = sys.excepthook
        crashreport.install()                        # idempotent
        assert sys.excepthook is after
    finally:
        sys.excepthook = prev
        crashreport._installed = False
