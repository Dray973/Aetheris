"""
Persistent settings.

A tiny JSON-backed preferences store at ``%APPDATA%\\AetherisQuantumCore\\
settings.json`` (platform config dir elsewhere). Used to remember window
geometry, the active tab, the log-drawer verbosity, and a few per-tab inputs
across sessions. Writes are atomic (temp file + os.replace); every read falls
back to a built-in default, so a missing or corrupt file is harmless.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

from . import logbus

SRC = "core.settings"


def config_dir() -> Path:
    base = os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), ".config")
    return Path(base) / "AetherisQuantumCore"


DEFAULTS: dict[str, Any] = {
    "window_geometry": "",        # base64 of QMainWindow.saveGeometry()
    "window_state": "",           # base64 of QMainWindow.saveState()
    "active_tab": 0,
    "log_min_level": "TRACE",
    "log_autoscroll": True,
    "network_resolve_dns": False,
    "mft_volume": r"\\.\C:",
    "mft_max_records": 20000,
    # Persist the tamper-evident audit chain to a per-session JSONL file under
    # %APPDATA%\AetherisQuantumCore\audit\ so a forensic record survives close.
    "audit_persist": True,
    # Auto-update source: a public GitHub repo (github:owner/repo) or a
    # version.json URL (https:// / file://). Public repo required (no auth).
    "update_url": "github:Dray973/Aetheris",
    "update_auto_check": True,    # check on startup (background)
    "pending_update_version": "",
}


class Settings:
    def __init__(self, path: str | os.PathLike | None = None) -> None:
        self.path = Path(path) if path else (config_dir() / "settings.json")
        self._data: dict[str, Any] = dict(DEFAULTS)
        self._lock = threading.Lock()
        self.load()

    def load(self) -> None:
        try:
            with open(self.path, encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                with self._lock:
                    self._data.update(data)
        except (OSError, json.JSONDecodeError):
            pass  # missing/corrupt -> keep defaults

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            if key in self._data:
                return self._data[key]
        return DEFAULTS.get(key, default)

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._data[key] = value

    def update(self, **kwargs: Any) -> None:
        with self._lock:
            self._data.update(kwargs)

    def save(self) -> bool:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self._lock:
                blob = json.dumps(self._data, indent=2)
            tmp = self.path.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(blob)
            os.replace(tmp, self.path)
            logbus.trace(SRC, f"settings saved: {self.path}")
            return True
        except OSError as exc:
            logbus.warn(SRC, "could not save settings", str(exc))
            return False


_settings: Settings | None = None


def settings() -> Settings:
    """Process-wide settings singleton."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
