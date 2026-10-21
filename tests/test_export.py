"""Threat-hunt export: SARIF 2.1.0 (schema-validated), JSON, Markdown, CLI."""
import json
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from aetheris import cli
from aetheris.analysis import export, findings

SCHEMA = Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json"


def _hunt():
    """A realistic mixed hunt: one correlated binary plus standalone findings."""
    evil = r"C:\Users\bob\AppData\Local\Temp\upd.exe"
    procs = [NS(pid=4242, name="upd.exe", exe=evil, signature="unsigned"),
             NS(pid=10, name="explorer.exe", exe=r"C:\Windows\explorer.exe",
                signature="signed")]
    conns = [NS(pid=4242, proc_name="upd.exe", raddr="203.0.113.9", rport=443,
                remote_class="public", geo="NL", rdns="")]
    persist = [NS(name="Updater", source="Run", enabled=True, binary=evil,
                  signed="unsigned", location=r"HKCU\...\Run")]
    services = [NS(name="VulnSvc", unquoted_path=True, binary=r"C:\Program Files\Vendor\svc.exe",
                   image_path=r"C:\Program Files\Vendor Tool\svc.exe -k run",
                   start_type="auto", account="LocalSystem")]
    tasks = [NS(name="Sync", path=r"\Sync", flags=["obfuscated/encoded shell command"],
                action_binaries=[], actions=["powershell -enc AAAA"], triggers=["logon"])]
    return findings.analyze(processes=procs, connections=conns, persistence=persist,
                            services=services, tasks=tasks)


@pytest.fixture
def hunt():
    return _hunt()


# --- SARIF -----------------------------------------------------------------


def test_sarif_validates_against_the_official_schema(hunt):
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    log = json.loads(export.render_sarif(hunt, "0.3.1", "WORKSTATION"))
    jsonschema.validate(log, schema)


def test_sarif_empty_hunt_is_valid(hunt):
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    log = export.to_sarif([])
    jsonschema.validate(log, schema)
    assert log["runs"][0]["results"] == []


def test_sarif_one_result_per_finding_with_matching_rules(hunt):
    run = export.to_sarif(hunt, "0.3.1")["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert len(run["results"]) == len(hunt)
    assert len({r["id"] for r in rules}) == len(rules)
    for res in run["results"]:
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]
    assert run["tool"]["driver"]["version"] == "0.3.1"


def test_correlated_finding_maps_to_error_and_carries_all_techniques(hunt):
    run = export.to_sarif(hunt)["runs"][0]
    top = run["results"][0]
    assert top["ruleId"] == "AQC-correlated"
    assert top["level"] == "error"
    techs = set(top["properties"]["techniques"])
    assert {"T1036", "T1071", "T1547"} <= techs
    assert float(top["properties"]["security-severity"]) >= 8.0


def test_levels_follow_severity():
    def f(score):
        return findings.Finding("k", "s", "t", score, "privesc", "T1574.009", "Path")
    levels = [export.to_sarif([f(s)])["runs"][0]["results"][0]["level"]
              for s in (90, 65, 40, 10)]
    assert levels == ["error", "error", "warning", "note"]


def test_location_uses_the_evidence_path_and_strips_arguments(hunt):
    svc = next(f for f in hunt if f.category == "privesc")
    assert export.file_path_of(svc) == r"C:\Program Files\Vendor Tool\svc.exe"
    run = export.to_sarif([svc])["runs"][0]
    uri = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "file:///C:/Program%20Files/Vendor%20Tool/svc.exe"


def test_no_physical_location_is_invented_without_a_path():
    net = findings.Finding("x", "x (pid 1)", "Public outbound connection", 20, "c2",
                           "T1071", "Application Layer Protocol",
                           evidence=["1 public remote(s):", "203.0.113.9:443 (NL)"])
    loc = export.to_sarif([net])["runs"][0]["results"][0]["locations"][0]
    assert "physicalLocation" not in loc
    assert loc["logicalLocations"][0]["name"] == "x (pid 1)"


def test_fingerprint_is_stable_across_runs():
    a = export.to_sarif(_hunt())["runs"][0]["results"]
    b = export.to_sarif(_hunt())["runs"][0]["results"]
    assert [r["partialFingerprints"] for r in a] == [r["partialFingerprints"] for r in b]


def test_attack_urls_handle_subtechniques():
    assert export.attack_url("T1053.005") == "https://attack.mitre.org/techniques/T1053/005/"
    assert export.attack_url("T1055") == "https://attack.mitre.org/techniques/T1055/"


# --- JSON / Markdown -------------------------------------------------------


def test_json_round_trips(hunt):
    rows = json.loads(export.render_json(hunt))
    assert [r["score"] for r in rows] == [f.score for f in hunt]
    assert rows[0]["severity"] == hunt[0].severity


def test_markdown_escapes_table_pipes():
    f = findings.Finding("k", "a|b", "title|x", 50, "yara", "T1027", "YARA")
    md = export.render_markdown([f])
    assert "a\\|b" in md and "title\\|x" in md


def test_markdown_empty():
    assert "No findings" in export.render_markdown([])


# --- CLI -------------------------------------------------------------------


def test_cli_hunt_writes_sarif(tmp_path, monkeypatch):
    monkeypatch.setattr(findings, "gather", lambda **kw: _hunt())
    out = tmp_path / "hunt.sarif"
    assert cli.main(["--format", "sarif", "--out", str(out), "hunt", "--no-injection"]) == 0
    log = json.loads(out.read_text(encoding="utf-8"))
    assert log["version"] == "2.1.0" and log["runs"][0]["results"]


def test_cli_hunt_passes_scan_flags(monkeypatch, capsys):
    seen = {}

    def fake_gather(**kw):
        seen.update(kw)
        return []
    monkeypatch.setattr(findings, "gather", fake_gather)
    cli.main(["--format", "md", "hunt", "--no-injection", "--yara"])
    assert seen == {"scan_injection": False, "scan_yara": True}
    assert "No findings" in capsys.readouterr().out


def test_cli_sarif_is_rejected_for_other_commands(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--format", "sarif", "processes"])
    assert exc.value.code == 2
    assert "hunt" in capsys.readouterr().err


# --- Threat Hunt tab -------------------------------------------------------


def test_findings_tab_export_picks_format(qtbot, tmp_path, monkeypatch):
    from PySide6.QtWidgets import QFileDialog

    from aetheris.ui.tabs.findings_tab import FindingsTab

    tab = FindingsTab()
    qtbot.addWidget(tab)
    assert not tab.export_btn.isEnabled()
    tab._populate(_hunt())
    assert tab.export_btn.isEnabled()

    assert json.loads(tab._render_export("h.sarif"))["version"] == "2.1.0"
    assert isinstance(json.loads(tab._render_export("h.json")), list)
    assert tab._render_export("h.md").startswith("# Threat Hunt")
    # No extension: the chosen filter decides.
    assert tab._render_export("h", "JSON (*.json)").lstrip().startswith("[")

    out = tmp_path / "hunt.sarif"
    monkeypatch.setattr(QFileDialog, "getSaveFileName",
                        lambda *a, **k: (str(out), "SARIF 2.1.0 (*.sarif)"))
    tab._export()
    assert json.loads(out.read_text(encoding="utf-8"))["runs"][0]["results"]
