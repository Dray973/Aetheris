"""Auto-updater: version compare, manifest check, staging (via file:// URLs)."""
import json

from aetheris.core import updater
from aetheris.core.settings import Settings


def test_version_parse_and_compare():
    assert updater.parse_version("v1.2.3") == (1, 2, 3)
    assert updater.is_newer("0.2.0", "0.1.9")
    assert updater.is_newer("0.1.10", "0.1.9")
    assert not updater.is_newer("0.1.0", "0.1.0")
    assert not updater.is_newer("0.0.9", "0.1.0")


def test_check_finds_newer(tmp_path):
    newexe = tmp_path / "new.exe"
    newexe.write_bytes(b"EXE")
    manifest = tmp_path / "version.json"
    manifest.write_text(json.dumps(
        {"version": "9.9.9", "url": newexe.as_uri(), "notes": "big update"}))
    info = updater.check(manifest.as_uri(), current="0.1.0")
    assert info is not None
    assert info.version == "9.9.9" and info.notes == "big update"


def test_check_not_newer_returns_none(tmp_path):
    manifest = tmp_path / "v.json"
    manifest.write_text(json.dumps({"version": "0.0.1", "url": "x"}))
    assert updater.check(manifest.as_uri(), current="0.1.0") is None


def test_check_empty_url_returns_none():
    assert updater.check("", current="0.1.0") is None


def test_check_bad_url_is_graceful():
    assert updater.check("file:///no/such/manifest.json", current="0.1.0") is None


def test_stage_downloads_and_records_pending(tmp_path, monkeypatch):
    newexe = tmp_path / "new.exe"
    newexe.write_bytes(b"NEW-EXE-DATA")
    dest = tmp_path / "staged.exe"
    s = Settings(tmp_path / "settings.json")
    monkeypatch.setattr(updater, "settings", lambda: s)

    ok, _msg = updater.stage(updater.UpdateInfo("9.9.9", newexe.as_uri()), dest=dest)
    assert ok
    assert dest.read_bytes() == b"NEW-EXE-DATA"
    assert s.get("pending_update_version") == "9.9.9"


def test_check_github_finds_newer_and_picks_exe(monkeypatch):
    fake = {
        "tag_name": "v0.2.0", "body": "release notes",
        "assets": [
            {"name": "AetherisSetup.exe", "browser_download_url": "http://x/setup.exe"},
            {"name": "AetherisQuantumCore.exe", "browser_download_url": "http://x/app.exe"},
        ],
    }
    monkeypatch.setattr(updater, "_fetch_json", lambda url, headers=None: fake)
    info = updater.check("github:owner/repo", current="0.1.0")
    assert info is not None
    assert info.version == "0.2.0"
    assert info.url == "http://x/app.exe"        # skipped the setup.exe
    assert info.notes == "release notes"


def test_check_github_not_newer(monkeypatch):
    monkeypatch.setattr(updater, "_fetch_json",
                        lambda url, headers=None: {"tag_name": "v0.1.0", "assets": []})
    assert updater.check("github:owner/repo", current="0.1.0") is None


def test_check_github_no_exe_asset(monkeypatch):
    monkeypatch.setattr(updater, "_fetch_json", lambda url, headers=None:
                        {"tag_name": "v9.0.0",
                         "assets": [{"name": "notes.txt", "browser_download_url": "x"}]})
    assert updater.check("github:owner/repo", current="0.1.0") is None


def test_stage_rejects_checksum_mismatch(tmp_path, monkeypatch):
    newexe = tmp_path / "new.exe"
    newexe.write_bytes(b"DATA")
    dest = tmp_path / "staged.exe"
    s = Settings(tmp_path / "settings.json")
    monkeypatch.setattr(updater, "settings", lambda: s)

    info = updater.UpdateInfo("9.9.9", newexe.as_uri(), sha256="deadbeef")
    ok, msg = updater.stage(info, dest=dest)
    assert not ok and "checksum" in msg
    assert not dest.exists()
