"""Hunt baselines: classification, persistence, export tagging, CLI, tab."""
import json

import pytest

from aetheris import cli
from aetheris.analysis import baseline as BL
from aetheris.analysis import export, findings
from aetheris.analysis.findings import Finding


def _f(key, technique="T1036", name="Masquerading", score=30, category="masquerading"):
    return Finding(key=key, subject=f"{key} (pid 1)", title=f"t {key}", score=score,
                   category=category, technique=technique, technique_name=name)


def _corr(key, *techs):
    return Finding(key=key, subject=key, title="Correlated", score=90, category="correlated",
                   technique=techs[0], technique_name="; ".join(f"{t} X" for t in techs))


def test_classifies_new_known_and_escalated():
    base = BL.Baseline.from_findings([_f("updater.exe"), _f("tool.exe")])
    assert base.status(_f("updater.exe")) == BL.KNOWN
    assert base.status(_f("dropper.exe")) == BL.NEW
    # Known subject, new behaviour: it started talking to a public host.
    grown = _corr("updater.exe", "T1036", "T1071")
    assert base.status(grown) == BL.ESCALATED
    assert base.new_techniques(grown) == ["T1071"]


def test_score_change_alone_is_not_escalation():
    base = BL.Baseline.from_findings([_f("a.exe", score=30)])
    assert base.status(_f("a.exe", score=45)) == BL.KNOWN


def test_resolved_lists_subjects_no_longer_seen():
    base = BL.Baseline.from_findings([_f("gone.exe"), _f("here.exe")])
    assert [e.key for e in base.resolved([_f("here.exe")])] == ["gone.exe"]


def test_accept_merges_techniques_and_forget_removes():
    base = BL.Baseline()
    base.accept(_f("a.exe", "T1036"))
    base.accept(_f("a.exe", "T1071", "App Layer", category="c2"))
    assert base.entries["a.exe"].techniques == {"T1036", "T1071"}
    assert base.forget("a.exe") and not base.forget("a.exe")


def test_save_load_round_trip(tmp_path):
    base = BL.Baseline.from_findings([_corr("x.exe", "T1036", "T1547")], host="PC1", now=123.0)
    path = tmp_path / "sub" / "b.json"
    base.save(path)
    again = BL.load(path)
    assert again.host == "PC1" and again.created_at == 123.0
    assert again.entries["x.exe"].techniques == {"T1036", "T1547"}
    assert not list(tmp_path.rglob("*.tmp")), "atomic write left a temp file"


def test_load_rejects_foreign_and_future_files(tmp_path):
    p = tmp_path / "b.json"
    p.write_text(json.dumps({"hello": 1}))
    with pytest.raises(ValueError, match="not an Aetheris"):
        BL.load(p)
    p.write_text(json.dumps({"format": "aetheris-hunt-baseline", "version": 99}))
    with pytest.raises(ValueError, match="newer"):
        BL.load(p)


def test_load_default_ignores_a_corrupt_file():
    p = BL.default_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{truncated")
    assert BL.load_default() is None


def test_sarif_carries_baseline_state():
    pytest.importorskip("jsonschema")
    from pathlib import Path

    import jsonschema
    schema = json.loads((Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json")
                        .read_text(encoding="utf-8"))
    base = BL.Baseline.from_findings([_f("known.exe"), _f("up.exe")])
    hunt = [_f("known.exe"), _f("new.exe"), _corr("up.exe", "T1036", "T1071")]
    log = export.to_sarif(hunt, baseline=base)
    jsonschema.validate(log, schema)
    states = [r["baselineState"] for r in log["runs"][0]["results"]]
    assert states == ["unchanged", "new", "updated"]


def test_json_and_markdown_carry_status():
    base = BL.Baseline.from_findings([_f("known.exe")])
    hunt = [_f("known.exe"), _f("new.exe")]
    rows = json.loads(export.render_json(hunt, base))
    assert [r["baseline"] for r in rows] == ["known", "new"]
    md = export.render_markdown(hunt, baseline=base)
    assert "1 new, 0 escalated, 1 known" in md and "| Baseline |" in md
    assert "baseline" not in json.loads(export.render_json(hunt))[0]


# --- CLI -------------------------------------------------------------------


def test_cli_save_then_new_only(tmp_path, monkeypatch, capsys):
    first = [_f("updater.exe"), _f("tool.exe")]
    monkeypatch.setattr(findings, "gather", lambda **kw: first)
    bpath = tmp_path / "base.json"
    cli.main(["--format", "json", "hunt", "--save-baseline", str(bpath)])
    assert "baseline saved" in capsys.readouterr().err

    later = [_f("updater.exe"), _f("dropper.exe"), _corr("tool.exe", "T1036", "T1071")]
    monkeypatch.setattr(findings, "gather", lambda **kw: later)
    cli.main(["--format", "json", "hunt", "--baseline", str(bpath), "--new-only"])
    rows = json.loads(capsys.readouterr().out)
    assert {(r["key"], r["baseline"]) for r in rows} == {
        ("dropper.exe", "new"), ("tool.exe", "escalated")}


def test_cli_default_baseline_alias(monkeypatch, capsys):
    monkeypatch.setattr(findings, "gather", lambda **kw: [_f("a.exe")])
    cli.main(["--format", "md", "hunt", "--save-baseline", "default"])
    assert BL.default_path().exists()
    capsys.readouterr()
    cli.main(["--format", "md", "hunt", "--baseline", "default"])
    assert "0 new, 0 escalated, 1 known" in capsys.readouterr().out


@pytest.mark.parametrize("argv,needle", [
    (["hunt", "--new-only"], "needs --baseline"),
    (["hunt", "--baseline", "/nonexistent/b.json"], "cannot read baseline"),
])
def test_cli_baseline_errors(monkeypatch, capsys, argv, needle):
    monkeypatch.setattr(findings, "gather", lambda **kw: [])
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    assert exc.value.code == 2 and needle in capsys.readouterr().err


# --- Threat Hunt tab -------------------------------------------------------


def test_tab_baseline_flow(qtbot, monkeypatch):
    from PySide6.QtWidgets import QMessageBox

    from aetheris.ui.tabs.findings_tab import FindingsTab

    monkeypatch.setattr(QMessageBox, "question",
                        lambda *a, **k: QMessageBox.StandardButton.Yes)
    tab = FindingsTab()
    qtbot.addWidget(tab)
    assert tab._baseline is None and not tab.new_only_cb.isEnabled()

    tab._populate([_f("updater.exe"), _f("tool.exe")])
    tab._accept_all()
    assert BL.default_path().exists() and tab.new_only_cb.isEnabled()

    tab._populate([_f("updater.exe"), _f("dropper.exe")])
    assert tab.table.item(1, 3).text() == "new"
    assert "1 new" in tab.summary.text() and "1 resolved" in tab.summary.text()
    tab.new_only_cb.setChecked(True)
    assert [f.key for f in tab._findings] == ["dropper.exe"]

    tab.table.selectRow(0)
    tab._accept_selected()
    assert tab._findings == [] and "No new findings" in tab.detail.toPlainText()

    # A fresh tab picks the saved baseline back up.
    again = FindingsTab()
    qtbot.addWidget(again)
    assert set(again._baseline.entries) == {"updater.exe", "tool.exe", "dropper.exe"}

    again._clear_baseline()
    assert again._baseline is None and not BL.default_path().exists()
