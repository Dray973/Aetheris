"""Task Scheduler integration — command building + safe queries."""
import sys

from aetheris.core import scheduler


def test_capture_command_uses_cli_and_output():
    cmd = scheduler.capture_command(r"C:\out\report.html", "html")
    assert "aetheris.cli" in cmd
    assert "report.html" in cmd
    assert cmd.strip().endswith("report")     # the CLI subcommand
    assert "--format html" in cmd


def test_capture_command_uses_exe_cli_dispatch_when_frozen(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", r"C:\App\AetherisQuantumCore.exe")
    cmd = scheduler.capture_command(r"C:\out\r.html", "html")
    assert '"C:\\App\\AetherisQuantumCore.exe" cli ' in cmd   # frozen dispatch path
    assert "-m aetheris.cli" not in cmd
    assert cmd.strip().endswith("report")


def test_capture_command_respects_format():
    assert "--format md" in scheduler.capture_command("x.md", "md")


def test_task_exists_returns_bool_for_missing_task():
    assert scheduler.task_exists("AetherisNoSuchTask_UnitTest_zzz") is False
