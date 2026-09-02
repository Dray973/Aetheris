"""
Auto-updater.

Model: the app checks a small JSON manifest (``version.json``) hosted anywhere
reachable — an https URL, or even a synced-folder ``file://`` path — that names
the latest version and a download URL for the new one-file exe:

    { "version": "0.1.1", "url": "https://.../AetherisQuantumCore.exe",
      "notes": "what changed", "sha256": "optional hex digest" }

On startup (background) it compares versions; if newer, it downloads the exe to
a staging file next to the running one. It does **not** interrupt the session —
the update is *applied on the next launch*: ``apply_pending()`` (called early at
startup, before the GUI) swaps the staged exe in and relaunches.

Two install shapes self-update:

* The frozen one-file **exe** downloads the new exe to a ``.new`` staging file
  and a detached swapper replaces it on next launch (``stage`` / the exe branch
  of ``apply_pending``).
* A **source install** — the per-user installer's venv layout, where ``run.py``
  sits next to the ``aetheris`` package under ``%LOCALAPPDATA%`` — downloads the
  new *source* (the release's ``…/archive/refs/tags/vX.zip``) into a staging dir,
  and a detached helper mirrors it over the install (keeping the ``.venv``) and
  relaunches (``stage_source`` / ``apply_pending_source``). ``install_root``
  returns ``None`` for a frozen exe, a pip/site-packages install, or a git dev
  checkout (a ``.git`` working tree updates via git, never by self-overwrite), so
  those are left alone.

Everything is verifiable with a ``file://`` manifest / zip + local files (no
server needed).
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .. import __version__ as CURRENT_VERSION
from . import logbus
from .settings import DEFAULTS, config_dir, settings


def effective_update_url() -> str:
    """The configured update source, falling back to the baked-in default when a
    stored value is blank (e.g. saved empty by an older build)."""
    return str(settings().get("update_url", "") or DEFAULTS.get("update_url", ""))

SRC = "core.updater"
DETACHED_PROCESS = 0x00000008


@dataclass
class UpdateInfo:
    version: str
    url: str
    notes: str = ""
    sha256: str = ""
    source_url: str = ""


def parse_version(s: str) -> tuple[int, ...]:
    nums = [int(x) for x in re.findall(r"\d+", str(s))[:4]]
    return tuple(nums) or (0,)


def is_newer(remote: str, local: str) -> bool:
    return parse_version(remote) > parse_version(local)


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def current_exe() -> Path | None:
    return Path(sys.executable) if is_frozen() else None


def staging_path() -> Path:
    exe = current_exe()
    if exe is not None:
        return exe.with_name(exe.name + ".new")
    return config_dir() / "update" / "AetherisQuantumCore.exe.new"


GITHUB_PREFIX = "github:"


def _fetch_json(url: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data: dict[str, Any] = json.loads(resp.read().decode("utf-8"))
        return data


def fetch_manifest(url: str) -> dict[str, Any]:
    return _fetch_json(url)


def _check_github(owner_repo: str, current: str) -> UpdateInfo | None:
    """Check a GitHub repo's latest release (spec: 'owner/repo')."""
    if "/" not in owner_repo:
        return None
    owner, repo = owner_repo.split("/", 1)
    api = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
    try:
        data = _fetch_json(api, {"Accept": "application/vnd.github+json",
                                 "User-Agent": "Aetheris-Updater"})
    except Exception as exc:  # noqa: BLE001
        logbus.trace(SRC, f"github update check failed: {exc}")
        return None
    tag = str(data.get("tag_name", "")).strip()
    if not tag or not is_newer(tag, current):
        return None
    exe_url = ""
    for asset in data.get("assets", []):
        name = str(asset.get("name", "")).lower()
        if name.endswith(".exe") and "setup" not in name:
            exe_url = str(asset.get("browser_download_url", ""))
            break
    source_url = f"https://github.com/{owner}/{repo}/archive/refs/tags/{tag}.zip"
    if not exe_url and not source_url:
        return None
    return UpdateInfo(tag.lstrip("vV"), exe_url, str(data.get("body", "")),
                      source_url=source_url)


def check(url: str | None = None, current: str = CURRENT_VERSION) -> UpdateInfo | None:
    """
    Return UpdateInfo if a newer version is available, else None. ``url`` may be:
      * ``github:owner/repo``     -> check that repo's latest GitHub release
      * an http(s):// or file://  -> a version.json manifest
    """
    url = url if url is not None else effective_update_url()
    if not url:
        return None
    if url.startswith(GITHUB_PREFIX):
        return _check_github(url[len(GITHUB_PREFIX):].strip(), current)
    try:
        data = fetch_manifest(url)
    except Exception as exc:  # noqa: BLE001
        logbus.trace(SRC, f"update check failed: {exc}")
        return None
    ver = str(data.get("version", "")).strip()
    if ver and is_newer(ver, current):
        return UpdateInfo(ver, str(data.get("url", "")),
                          str(data.get("notes", "")), str(data.get("sha256", "")),
                          str(data.get("source_url", "")))
    return None


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "Aetheris-Updater"})
    with urllib.request.urlopen(req, timeout=600) as resp, open(dest, "wb") as fh:
        while chunk := resp.read(1 << 20):
            fh.write(chunk)


def stage(info: UpdateInfo, dest: Path | None = None) -> tuple[bool, str]:
    """Download the new exe to the staging path and record it as pending."""
    dest = dest or staging_path()
    try:
        download(info.url, dest)
    except Exception as exc:  # noqa: BLE001
        return False, f"download failed: {exc}"
    if info.sha256:
        got = _sha256(dest)
        if got.lower() != info.sha256.lower():
            dest.unlink(missing_ok=True)
            return False, "checksum mismatch (update discarded)"
    settings().update(pending_update_version=info.version)
    settings().save()
    logbus.success(SRC, f"update {info.version} staged; applies on next launch")
    return True, f"update {info.version} staged"


def has_pending() -> bool:
    return staging_path().exists()


def pending_version() -> str:
    return str(settings().get("pending_update_version", "")) if has_pending() else ""


def _discard_pending(reason: str) -> None:
    """Drop a staged exe we can't (or won't) apply, and clear the pending flag,
    so the UI stops reporting a phantom update. Best-effort; never raises."""
    try:
        staging_path().unlink(missing_ok=True)
    except OSError:
        pass
    try:
        settings().update(pending_update_version="")
        settings().save()
    except Exception:  # noqa: BLE001 -- cleanup must never crash startup
        pass
    logbus.trace(SRC, f"discarded staged update ({reason})")


# --- source (venv-installer) self-update ------------------------------------
#
# Files the per-user installer lays down (install.ps1's $items). The updater
# mirrors exactly these over the install; the .venv, shortcuts, uninstaller and
# settings sit outside this set and are left untouched.
APP_ITEMS = ("aetheris", "run.py", "requirements.txt", "README.md", "pyproject.toml")


def install_root() -> Path | None:
    """The root of a source (venv-installer) install: the directory holding
    ``run.py`` next to the ``aetheris`` package. ``None`` for a frozen exe, a
    pip / site-packages install, or a git dev checkout (a ``.git`` working tree
    updates via git, never by self-overwrite)."""
    if is_frozen():
        return None
    try:
        root = Path(__file__).resolve().parents[2]
    except IndexError:
        return None
    if (root / ".git").exists():
        return None
    if (root / "run.py").is_file() and (root / "aetheris").is_dir():
        return root
    return None


def source_staging_dir() -> Path:
    return config_dir() / "update" / "staged-src"


def _clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)


def _find_app_tree(base: Path) -> Path | None:
    """Locate the app tree (a dir holding ``aetheris/`` + ``run.py``) in an
    extracted archive — either ``base`` itself or its single top-level subdir
    (GitHub source zips nest everything under ``<repo>-<tag>/``)."""
    if (base / "aetheris").is_dir() and (base / "run.py").is_file():
        return base
    try:
        subs = [p for p in base.iterdir() if p.is_dir()]
    except OSError:
        return None
    for sub in subs:
        if (sub / "aetheris").is_dir() and (sub / "run.py").is_file():
            return sub
    return None


def has_pending_source() -> bool:
    if not settings().get("pending_source_version", ""):
        return False
    d = source_staging_dir()
    return d.is_dir() and (d / "run.py").is_file() and (d / "aetheris").is_dir()


def pending_source_version() -> str:
    return str(settings().get("pending_source_version", "")) if has_pending_source() else ""


def _discard_source(reason: str) -> None:
    """Drop a staged source tree we can't (or won't) apply and clear its flag.
    Best-effort; never raises."""
    _clean_dir(source_staging_dir())
    try:
        settings().update(pending_source_version="")
        settings().save()
    except Exception:  # noqa: BLE001 -- cleanup must never crash startup
        pass
    logbus.trace(SRC, f"discarded staged source update ({reason})")


def stage_source(info: UpdateInfo, root: Path | None = None,
                 staging: Path | None = None) -> tuple[bool, str]:
    """Download + extract the new source into a staging dir, verified complete,
    and record it as pending. Nothing touches the live install until
    ``apply_pending_source`` runs on the next launch."""
    root = root if root is not None else install_root()
    if root is None:
        return False, "not a source install (nothing to update in place)"
    if not info.source_url:
        return False, "no source download available for this release"
    staging = staging if staging is not None else source_staging_dir()
    work = staging.parent / "src-download"
    zip_path = staging.parent / "src.zip"
    try:
        _clean_dir(work)
        _clean_dir(staging)
        zip_path.unlink(missing_ok=True)
        download(info.source_url, zip_path)
        work.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(work)
        tree = _find_app_tree(work)
        if tree is None:
            _clean_dir(work)
            zip_path.unlink(missing_ok=True)
            return False, "downloaded source missing aetheris/ or run.py (discarded)"
        staging.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(tree), str(staging))
        _clean_dir(work)
        zip_path.unlink(missing_ok=True)
    except Exception as exc:  # noqa: BLE001
        _clean_dir(work)
        _clean_dir(staging)
        try:
            zip_path.unlink(missing_ok=True)
        except OSError:
            pass
        return False, f"source update download failed: {exc}"
    settings().update(pending_source_version=info.version)
    settings().save()
    logbus.success(SRC, f"source update {info.version} staged; applies on next launch")
    return True, f"source update {info.version} staged"


def _source_swap_script(python_exe: str, root: Path, staged: Path,
                        items: tuple[str, ...] = APP_ITEMS) -> str:
    """Batch that mirrors the staged source over the install and relaunches.
    Directories are mirrored (robocopy /MIR — removes files deleted upstream);
    top-level files are copied. The .venv and everything outside ``items`` are
    untouched."""
    lines = ["@echo off", "timeout /t 1 /nobreak >nul"]
    for item in items:
        src, dst = staged / item, root / item
        if src.is_dir():
            lines.append(
                f'robocopy "{src}" "{dst}" /MIR /NFL /NDL /NJH /NJS /NC /NS /NP >nul')
        elif src.is_file():
            lines.append(f'copy /y "{src}" "{dst}" >nul')
    lines.append(f'start "" "{python_exe}" "{root / "run.py"}"')
    lines.append(f'rmdir /s /q "{staged}" >nul 2>&1')
    lines.append('del "%~f0"')
    return "\r\n".join(lines) + "\r\n"


def apply_pending_source() -> bool:
    """If a staged source update exists, spawn a detached helper that mirrors it
    over the install and relaunches — the caller should exit right after this
    returns True. Returns True if an apply was initiated."""
    if not has_pending_source():
        return False
    root = install_root()
    staged = source_staging_dir()
    if root is None:
        _discard_source("no source install root (pip / dev / frozen)")
        return False
    try:
        helper = config_dir() / "update" / "apply-src.cmd"
        helper.parent.mkdir(parents=True, exist_ok=True)
        helper.write_text(_source_swap_script(sys.executable, root, staged),
                          encoding="ascii")
        settings().update(pending_source_version="")
        settings().save()
        subprocess.Popen(["cmd", "/c", str(helper)],
                         creationflags=DETACHED_PROCESS, close_fds=True)
        logbus.action(SRC, "applying staged source update; relaunching")
        return True
    except Exception as exc:  # noqa: BLE001
        logbus.error(SRC, f"failed to apply source update: {exc}")
        return False


def any_pending() -> bool:
    return has_pending() or has_pending_source()


def pending_label() -> str:
    return pending_source_version() or pending_version()


def _apply_pending_exe() -> bool:
    if not has_pending():
        return False
    exe = current_exe()
    staged = staging_path()
    if exe is None:
        _discard_pending("not a frozen exe; source installs update in place")
        return False
    try:
        swapper = config_dir() / "update" / "swap.cmd"
        swapper.parent.mkdir(parents=True, exist_ok=True)
        script = (
            "@echo off\r\n"
            "timeout /t 1 /nobreak >nul\r\n"
            ":retry\r\n"
            f'move /y "{staged}" "{exe}" >nul 2>&1 || (timeout /t 1 >nul & goto retry)\r\n'
            f'start "" "{exe}"\r\n'
            'del "%~f0"\r\n'
        )
        swapper.write_text(script, encoding="ascii")
        settings().update(pending_update_version="")
        settings().save()
        subprocess.Popen(["cmd", "/c", str(swapper)],
                         creationflags=DETACHED_PROCESS, close_fds=True)
        logbus.action(SRC, "applying staged update; relaunching")
        return True
    except Exception as exc:  # noqa: BLE001
        logbus.error(SRC, f"failed to apply update: {exc}")
        return False


def apply_pending() -> bool:
    """
    Apply a staged update, if any. The frozen exe swaps its ``.new`` file; a
    source install mirrors a staged source tree over itself. Both spawn a small
    detached helper that waits for this process to exit and relaunches — so the
    caller should exit immediately after this returns True. Returns True if an
    apply was initiated.
    """
    if is_frozen():
        return _apply_pending_exe()
    if has_pending():
        _discard_pending("not a frozen exe; source installs update in place")
    return apply_pending_source()


def check_and_stage(url: str | None = None) -> tuple[bool, str]:
    """One-shot: check for a newer version and stage it if found — the frozen
    exe stages the new exe, a source install stages the new source. A pip /
    site-packages install or git dev checkout (no ``install_root``) can't stage
    in place and reports the available version instead."""
    info = check(url)
    if info is None:
        return False, "no update available"
    if is_frozen():
        if not info.url:
            return False, f"v{info.version} available, but the release has no exe asset"
        return stage(info)
    if install_root() is None:
        return False, (f"v{info.version} available — update this checkout via git "
                       "or by re-running the installer")
    return stage_source(info)
