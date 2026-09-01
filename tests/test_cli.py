"""Headless CLI — report/table generation, plugins, scheduled capture."""
import json

from aetheris import cli


def test_cli_lists_plugins(capsys):
    assert cli.main(["plugins"]) == 0
    assert "top-memory" in capsys.readouterr().out


def test_cli_processes_json_to_file(tmp_path):
    out = tmp_path / "p.json"
    assert cli.main(["--format", "json", "--out", str(out), "processes"]) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert isinstance(data, list) and data and "pid" in data[0]


def test_cli_report_markdown_stdout(capsys):
    assert cli.main(["--format", "md", "report"]) == 0
    assert "Session Report" in capsys.readouterr().out


def test_cli_run_plugin_stdout(capsys):
    assert cli.main(["run", "top-memory"]) == 0
    assert "Top processes by memory" in capsys.readouterr().out


def test_cli_scheduled_capture_writes_timestamped_files(tmp_path):
    out = tmp_path / "r.md"
    rc = cli.main(["--format", "md", "--out", str(out),
                   "--count", "2", "--interval", "0", "report"])
    assert rc == 0
    assert len(list(tmp_path.glob("r-*.md"))) == 2


def test_cli_rapid_captures_are_all_distinct(tmp_path):
    n = 5
    out = tmp_path / "cap.md"
    rc = cli.main(["--format", "md", "--out", str(out),
                   "--count", str(n), "--interval", "0", "report"])
    assert rc == 0
    files = list(tmp_path.glob("cap-*.md"))
    assert len(files) == n
    assert len({f.name for f in files}) == n
    assert all(f.stat().st_size > 0 for f in files)
