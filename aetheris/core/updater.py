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

Only the frozen one-file exe self-updates. A dev/pip install logs that updates
are managed by git/pip instead. Everything is verifiable with a ``file://``
manifest + a local file (no server needed).
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import urllib.request
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


# --- version comparison (pure) --------------------------------------------
def parse_version(s: str) -> tuple[int, ...]:
    nums = [int(x) for x in re.findall(r"\d+", str(s))[:4]]
    return tuple(nums) or (0,)


def is_newer(remote: str, local: str) -> bool:
    return parse_version(remote) > parse_version(local)


# --- environment ----------------------------------------------------------
def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def current_exe() -> Path | None:
    return Path(sys.executable) if is_frozen() else None


def staging_path() -> Path:
    exe = current_exe()
    if exe is not None:
        return exe.with_name(exe.name + ".new")
    return config_dir() / "update" / "AetherisQuantumCore.exe.new"


# --- check + download -----------------------------------------------------
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
    # Prefer the standalone exe asset (not the setup.exe installer).
    exe_url = ""
    for asset in data.get("assets", []):
        name = str(asset.get("name", "")).lower()
        if name.endswith(".exe") and "setup" not in name:
            exe_url = str(asset.get("browser_download_url", ""))
            break
    if not exe_url:
        return None
    return UpdateInfo(tag.lstrip("vV"), exe_url, str(data.get("body", "")))


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
                          str(data.get("notes", "")), str(data.get("sha256", "")))
    return None


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=600) as resp, open(dest, "wb") as fh:
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


# --- apply (next launch) --------------------------------------------------
def apply_pending() -> bool:
    """
    If a staged update exists, apply it. For the frozen exe this spawns a small
    detached swapper that waits for this process to exit, replaces the exe, and
    relaunches — so the caller should exit immediately after this returns True.
    Returns True if an update apply was initiated.
    """
    if not has_pending():
        return False
    exe = current_exe()
    staged = staging_path()
    if exe is None:
        # Dev / pip install: don't self-modify source; leave the staged file.
        logbus.warn(SRC, "pending update ignored (not a frozen exe; use git/pip)")
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


def check_and_stage(url: str | None = None) -> tuple[bool, str]:
    """One-shot: check the manifest and stage a newer version if found."""
    info = check(url)
    if info is None:
        return False, "no update available"
    return stage(info)
