"""Trusted-certificate audit: FILETIME/JSON parse, flags, snapshot, the tab."""
import json
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from aetheris.core import certstore as cs  # noqa: E402
from aetheris.core.certstore import Certificate  # noqa: E402

# 2020-01-01 and 2030-01-01 as FILETIME (100-ns ticks since 1601).
FT_2020 = int((1577836800 + 11644473600) * 1e7)
FT_2030 = int((1893456000 + 11644473600) * 1e7)
NOW_2025 = 1735689600  # 2025-01-01


def _cert(subject, store=r"LocalMachine\Root", tp="AA", issuer=None,
          nb=FT_2020 / 1e7 - 11644473600, na=FT_2030 / 1e7 - 11644473600):
    return Certificate(subject=subject, issuer=issuer or subject, thumbprint=tp,
                       not_before=nb, not_after=na, store=store)


# --- parsing ---------------------------------------------------------------


def test_parse_powershell_array_and_filetime():
    out = cs.parse_powershell(json.dumps([
        {"s": "CN=DigiCert Root", "i": "CN=DigiCert Root", "t": "abc123",
         "nb": FT_2020, "na": FT_2030}]), r"LocalMachine\Root")
    assert len(out) == 1
    c = out[0]
    assert c.thumbprint == "ABC123" and c.common_name == "DigiCert Root"
    assert abs(c.not_after - 1893456000) < 2       # 2030-01-01
    assert c.is_root


def test_parse_handles_single_object_and_empty():
    one = cs.parse_powershell(json.dumps({"s": "CN=X", "i": "CN=X", "t": "f",
                                          "nb": FT_2020, "na": FT_2030}), r"CurrentUser\CA")
    assert len(one) == 1 and not one[0].is_root
    assert cs.parse_powershell("", r"LocalMachine\Root") == []
    assert cs.parse_powershell("not json", r"LocalMachine\Root") == []


# --- flags -----------------------------------------------------------------


def test_known_ca_recognition():
    assert cs.looks_like_known_ca(_cert("CN=DigiCert Global Root"))
    assert cs.looks_like_known_ca(_cert("CN=Microsoft Root Authority"))
    assert not cs.looks_like_known_ca(_cert("CN=Totally Legit MITM CA"))


def test_flags_new_expired_future_uncommon():
    known = {"AA"}
    # Known public root, in snapshot, valid -> no flags.
    assert cs.flags(_cert("CN=DigiCert", tp="AA"), NOW_2025, known) == []
    # Not in snapshot -> new; uncommon subject -> uncommon-root.
    f = cs.flags(_cert("CN=Rogue CA", tp="BB"), NOW_2025, known)
    assert cs.F_NEW in f and cs.F_UNCOMMON in f
    # Expired.
    old = _cert("CN=DigiCert", tp="AA", na=1000.0)
    assert cs.F_EXPIRED in cs.flags(old, NOW_2025, known)
    # Intermediate (not root) uncommon subject is NOT flagged uncommon.
    inter = _cert("CN=Rogue", store=r"LocalMachine\CA", tp="AA")
    assert cs.F_UNCOMMON not in cs.flags(inter, NOW_2025, known)


def test_no_snapshot_means_nothing_is_new():
    f = cs.flags(_cert("CN=Rogue CA", tp="ZZ"), NOW_2025, None)
    assert cs.F_NEW not in f and cs.F_UNCOMMON in f


def test_report_orders_flagged_new_first():
    certs = [_cert("CN=DigiCert", tp="AA"),
             _cert("CN=Rogue", tp="BB"),
             _cert("CN=Old", tp="CC", na=1000.0)]
    report = cs.build_report(certs, known={"AA", "CC"}, now=NOW_2025)
    flagged = report.flagged()
    assert flagged[0].thumbprint == "BB"            # new+uncommon ranks first
    assert "AA" not in report.flags                 # known, valid -> unflagged


# --- snapshot --------------------------------------------------------------


def test_save_and_load_thumbprints(tmp_path):
    p = tmp_path / "snap.json"
    cs.save([_cert("CN=A", tp="AA"), _cert("CN=B", tp="BB")], p)
    assert cs.load_thumbprints(p) == {"AA", "BB"}
    assert cs.load_thumbprints(tmp_path / "none.json") is None
    assert not list(tmp_path.glob("*.tmp"))


def test_collect_empty_off_windows():
    import sys
    if sys.platform != "win32":
        assert cs.collect() == []


# --- tab -------------------------------------------------------------------


def test_cert_tab_flags_and_filter(qtbot, tmp_path, monkeypatch):
    from aetheris.ui.tabs.cert_tab import CertTab

    monkeypatch.setattr(cs, "default_path", lambda: tmp_path / "snap.json")
    tab = CertTab()
    qtbot.addWidget(tab)
    qtbot.waitUntil(lambda: tab._worker is None or not tab._worker.isRunning(),
                    timeout=5000)
    certs = [_cert("CN=DigiCert Global Root", tp="AA"),
             _cert("CN=Rogue MITM CA", tp="BB")]
    tab._loaded(cs.build_report(certs, known=None))
    assert tab.table.rowCount() == 2
    # Flagged (uncommon root) sorts first.
    assert "Rogue MITM CA" in tab.table.item(0, 1).text()
    tab.flagged_only.setChecked(True)
    assert tab.table.rowCount() == 1
