"""Auto-updater: version compare, manifest check, staging (via file:// URLs)."""
import json
import zipfile
from pathlib import Path

from aetheris.core import updater
from aetheris.core.settings import Settings


def _make_source_zip(zip_path: Path, version: str = "9.9.9",
                     top: str = "Aetheris", *, valid: bool = True) -> Path:
    """Build a GitHub-style source zip (everything nested under <top>-<ver>/)."""
    root = f"{top}-{version}"
    with zipfile.ZipFile(zip_path, "w") as zf:
        if valid:
            zf.writestr(f"{root}/run.py", "print('new')\n")
            zf.writestr(f"{root}/aetheris/__init__.py", f'__version__ = "{version}"\n')
            zf.writestr(f"{root}/requirements.txt", "PyQt6\n")
            zf.writestr(f"{root}/README.md", "# Aetheris\n")
            zf.writestr(f"{root}/pyproject.toml", f'version = "{version}"\n')
        else:
            zf.writestr(f"{root}/notes.txt", "no app tree here\n")
    return zip_path


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
    assert info.url == "http://x/app.exe"
    assert info.notes == "release notes"


def test_check_github_not_newer(monkeypatch):
    monkeypatch.setattr(updater, "_fetch_json",
                        lambda url, headers=None: {"tag_name": "v0.1.0", "assets": []})
    assert updater.check("github:owner/repo", current="0.1.0") is None


def test_check_github_no_exe_asset_still_offers_source(monkeypatch):
    """A release with no exe asset is still a valid *source* update: check()
    returns it with a constructed source archive URL and an empty exe url."""
    monkeypatch.setattr(updater, "_fetch_json", lambda url, headers=None:
                        {"tag_name": "v9.0.0",
                         "assets": [{"name": "notes.txt", "browser_download_url": "x"}]})
    info = updater.check("github:owner/repo", current="0.1.0")
    assert info is not None
    assert info.url == "" and info.version == "9.0.0"
    assert info.source_url.endswith("/archive/refs/tags/v9.0.0.zip")


def test_check_github_populates_source_url(monkeypatch):
    fake = {"tag_name": "v0.2.0", "body": "notes",
            "assets": [{"name": "AetherisQuantumCore.exe",
                        "browser_download_url": "http://x/app.exe"}]}
    monkeypatch.setattr(updater, "_fetch_json", lambda url, headers=None: fake)
    info = updater.check("github:owner/repo", current="0.1.0")
    assert info is not None
    assert info.url == "http://x/app.exe"
    assert info.source_url == "https://github.com/owner/repo/archive/refs/tags/v0.2.0.zip"


def test_find_app_tree_direct_and_nested(tmp_path):
    direct = tmp_path / "direct"
    (direct / "aetheris").mkdir(parents=True)
    (direct / "run.py").write_text("x")
    assert updater._find_app_tree(direct) == direct

    nested = tmp_path / "nested"
    inner = nested / "Aetheris-1.0"
    (inner / "aetheris").mkdir(parents=True)
    (inner / "run.py").write_text("x")
    assert updater._find_app_tree(nested) == inner

    empty = tmp_path / "empty"
    empty.mkdir()
    assert updater._find_app_tree(empty) is None


def test_stage_source_extracts_and_records_pending(tmp_path, monkeypatch):
    zip_path = _make_source_zip(tmp_path / "src.zip", "9.9.9")
    root = tmp_path / "install"
    (root / "aetheris").mkdir(parents=True)
    (root / "run.py").write_text("old")
    staging = tmp_path / "stage" / "staged-src"
    s = Settings(tmp_path / "settings.json")
    monkeypatch.setattr(updater, "settings", lambda: s)

    info = updater.UpdateInfo("9.9.9", "", source_url=zip_path.as_uri())
    ok, msg = updater.stage_source(info, root=root, staging=staging)
    assert ok, msg
    assert (staging / "aetheris" / "__init__.py").is_file()
    assert (staging / "run.py").is_file()
    assert s.get("pending_source_version") == "9.9.9"


def test_stage_source_rejects_archive_without_app_tree(tmp_path, monkeypatch):
    zip_path = _make_source_zip(tmp_path / "bad.zip", "9.9.9", valid=False)
    root = tmp_path / "install"
    (root / "aetheris").mkdir(parents=True)
    (root / "run.py").write_text("old")
    staging = tmp_path / "stage" / "staged-src"
    s = Settings(tmp_path / "settings.json")
    monkeypatch.setattr(updater, "settings", lambda: s)

    info = updater.UpdateInfo("9.9.9", "", source_url=zip_path.as_uri())
    ok, msg = updater.stage_source(info, root=root, staging=staging)
    assert not ok and "missing" in msg
    assert not staging.exists()
    assert s.get("pending_source_version") == ""


def test_stage_source_needs_install_root(tmp_path, monkeypatch):
    s = Settings(tmp_path / "settings.json")
    monkeypatch.setattr(updater, "settings", lambda: s)
    monkeypatch.setattr(updater, "install_root", lambda: None)
    info = updater.UpdateInfo("9.9.9", "", source_url="file:///x.zip")
    ok, msg = updater.stage_source(info)
    assert not ok and "source install" in msg


def test_has_pending_source_and_discard(tmp_path, monkeypatch):
    staging = tmp_path / "staged-src"
    (staging / "aetheris").mkdir(parents=True)
    (staging / "run.py").write_text("x")
    s = Settings(tmp_path / "settings.json")
    s.update(pending_source_version="9.9.9")
    monkeypatch.setattr(updater, "settings", lambda: s)
    monkeypatch.setattr(updater, "source_staging_dir", lambda: staging)

    assert updater.has_pending_source() is True
    assert updater.pending_source_version() == "9.9.9"
    updater._discard_source("test")
    assert updater.has_pending_source() is False
    assert not staging.exists()
    assert s.get("pending_source_version") == ""


def test_source_swap_script_mirrors_dirs_and_copies_files(tmp_path):
    root = tmp_path / "install"
    staged = tmp_path / "staged-src"
    (staged / "aetheris").mkdir(parents=True)
    (staged / "run.py").write_text("x")
    (staged / "README.md").write_text("x")
    script = updater._source_swap_script("py.exe", root, staged)
    assert "robocopy" in script and "aetheris" in script and "/MIR" in script
    assert "copy /y" in script and "run.py" in script
    assert 'start "" "py.exe"' in script
    assert script.rstrip().endswith('del "%~f0"')
    assert "-m pip install" not in script  # no dep refresh unless asked


def test_requirements_changed(tmp_path):
    root = tmp_path / "install"
    staged = tmp_path / "staged"
    root.mkdir()
    staged.mkdir()
    # staged has no requirements -> nothing to refresh
    assert updater.requirements_changed(root, staged) is False
    # install has none, staged adds one -> refresh
    (staged / "requirements.txt").write_text("PyQt6\npsutil\n")
    assert updater.requirements_changed(root, staged) is True
    # identical (modulo comments/whitespace) -> no refresh
    (root / "requirements.txt").write_text("# deps\nPyQt6\n  psutil  \n")
    assert updater.requirements_changed(root, staged) is False
    # a genuine change -> refresh
    (staged / "requirements.txt").write_text("PyQt6\npsutil\nyara-python\n")
    assert updater.requirements_changed(root, staged) is True


def test_source_swap_script_refreshes_deps_when_requested(tmp_path):
    root = tmp_path / "install"
    staged = tmp_path / "staged-src"
    (staged / "aetheris").mkdir(parents=True)
    (staged / "run.py").write_text("x")
    (staged / "requirements.txt").write_text("PyQt6\n")
    log = tmp_path / "pip.log"
    script = updater._source_swap_script(
        str(tmp_path / "pythonw.exe"), root, staged,
        refresh_deps=True, pip_python=str(tmp_path / "python.exe"), log=log)
    assert "-m pip install -r" in script
    assert "requirements.txt" in script
    assert str(log) in script
    # the pip line must run after the copy but before relaunch
    assert script.index("-m pip install") < script.index('start ""')


def test_console_python_prefers_python_exe(tmp_path):
    (tmp_path / "python.exe").write_text("x")
    pyw = tmp_path / "pythonw.exe"
    pyw.write_text("x")
    assert updater._console_python(str(pyw)) == str(tmp_path / "python.exe")
    # no sibling python.exe -> unchanged
    lone = tmp_path / "sub" / "pythonw.exe"
    lone.parent.mkdir()
    lone.write_text("x")
    assert updater._console_python(str(lone)) == str(lone)


def test_check_and_stage_source_stages_source(tmp_path, monkeypatch):
    """A source install now self-updates: check_and_stage stages the new source."""
    zip_path = _make_source_zip(tmp_path / "src.zip", "9.9.9")
    root = tmp_path / "install"
    (root / "aetheris").mkdir(parents=True)
    (root / "run.py").write_text("old")
    s = Settings(tmp_path / "settings.json")
    monkeypatch.setattr(updater, "settings", lambda: s)
    monkeypatch.setattr(updater, "is_frozen", lambda: False)
    monkeypatch.setattr(updater, "install_root", lambda: root)
    monkeypatch.setattr(updater, "source_staging_dir",
                        lambda: tmp_path / "stage" / "staged-src")
    monkeypatch.setattr(updater, "check",
                        lambda url=None: updater.UpdateInfo(
                            "9.9.9", "", source_url=zip_path.as_uri()))

    ok, msg = updater.check_and_stage("github:owner/repo")
    assert ok, msg
    assert s.get("pending_source_version") == "9.9.9"


def test_check_and_stage_pip_or_dev_reports_only(tmp_path, monkeypatch):
    """No install_root (pip / git checkout) → report the version, stage nothing."""
    s = Settings(tmp_path / "settings.json")
    monkeypatch.setattr(updater, "settings", lambda: s)
    monkeypatch.setattr(updater, "is_frozen", lambda: False)
    monkeypatch.setattr(updater, "install_root", lambda: None)
    monkeypatch.setattr(updater, "check",
                        lambda url=None: updater.UpdateInfo("9.9.9", "", source_url="x"))

    ok, msg = updater.check_and_stage("github:owner/repo")
    assert not ok and "9.9.9" in msg
    assert s.get("pending_source_version") == ""


def test_apply_pending_source_install_discards_stale_stage(tmp_path, monkeypatch):
    """A stale staged exe on a source install self-heals: apply_pending() deletes
    it and clears the flag so the UI stops claiming an update is pending."""
    staged = tmp_path / "AetherisQuantumCore.exe.new"
    staged.write_bytes(b"STALE-FROZEN-EXE")
    s = Settings(tmp_path / "settings.json")
    s.update(pending_update_version="0.1.4")
    monkeypatch.setattr(updater, "settings", lambda: s)
    monkeypatch.setattr(updater, "staging_path", lambda: staged)
    monkeypatch.setattr(updater, "current_exe", lambda: None)

    assert updater.has_pending() is True
    assert updater.apply_pending() is False
    assert not staged.exists()
    assert s.get("pending_update_version") == ""
    assert updater.has_pending() is False


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
