"""
In-process API monitor — host side.

Authorized use only. Injects the native agent DLL (``dist/aetheris_agent.dll``,
built from ``agent/aetheris_agent.cpp``) into a user-chosen, non-critical
process and streams the Win32 calls it observes back over a named pipe. Every
start/stop is confirm-gated by the UI, audited, dry-run-aware, and refuses
system-critical processes — the same posture as the debugger and DMA write. The
agent only *observes*; it forwards every hooked call unchanged.

This module splits cleanly: the pure parts (event parsing + display, DLL
discovery, the refusal check) are unit-tested; the injection + pipe I/O are
Windows-native and covered by the live check.
"""
from __future__ import annotations

import json
import os
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ..core import logbus
from ..core.settings import config_dir
from ..storage.unlock import CRITICAL_PROCESSES

SRC = "forensics.apimonitor"
AGENT_DLL = "aetheris_agent.dll"

# Page-protection constants → readable names (for VirtualAlloc/-Protect events).
_PROTECT = {
    0x01: "NOACCESS", 0x02: "READONLY", 0x04: "READWRITE", 0x08: "WRITECOPY",
    0x10: "EXECUTE", 0x20: "EXECUTE_READ", 0x40: "EXECUTE_READWRITE",
    0x80: "EXECUTE_WRITECOPY",
}


def protect_name(value: int) -> str:
    base = _PROTECT.get(value & 0xFF, hex(value))
    flags = ""
    if value & 0x100:
        flags += "+GUARD"
    if value & 0x400:
        flags += "+NOCACHE"
    return base + flags


@dataclass
class ApiEvent:
    api: str
    tid: int = 0
    fields: dict[str, object] = field(default_factory=dict)

    @property
    def is_control(self) -> bool:
        return self.api.startswith("__")

    def describe(self) -> str:
        f = self.fields
        if self.api == "__ready__":
            return f"agent ready — {f.get('hooks', 0)} hook(s) installed"
        caller = f.get("caller")
        tail = f"   ← {caller}" if caller else ""
        if "path" in f:
            base = f"{self.api}  {f['path']}"
        elif self.api == "CreateProcessW":
            base = f"{self.api}  {f.get('app', '')} {f.get('cmdline', '')}".rstrip()
        elif self.api == "connect":
            base = f"{self.api}  {f.get('endpoint', '')}"
        elif self.api == "VirtualAlloc":
            base = f"{self.api}  size={f.get('size', 0)}  protect={protect_name(int(f.get('protect', 0)))}"
        elif self.api == "WriteProcessMemory":
            base = f"{self.api}  size={f.get('size', 0)}  → pid {f.get('pid', '?')}"
        else:
            extra = "  ".join(f"{k}={v}" for k, v in sorted(f.items()) if k != "caller")
            base = f"{self.api}  {extra}".rstrip()
        return base + tail


def parse_event(line: str) -> ApiEvent | None:
    """Parse one NDJSON line emitted by the agent. Returns None on junk."""
    line = line.strip()
    if not line:
        return None
    try:
        data = json.loads(line)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict) or "api" not in data:
        return None
    api = str(data.pop("api"))
    tid = int(data.pop("tid", 0) or 0)
    return ApiEvent(api=api, tid=tid, fields=data)


def can_monitor(name: str) -> tuple[bool, str]:
    """Guard: never inject into a system-critical process."""
    if name.lower() in CRITICAL_PROCESSES:
        return False, f"refused: {name} is system-critical"
    return True, ""


def _cached_dll() -> Path:
    """Where a downloaded agent DLL is cached (for compiler-less installs)."""
    return config_dir() / "agent" / AGENT_DLL


def agent_dll_path() -> Path | None:
    """Locate a present agent DLL. Search: env override, next to / inside a
    frozen exe (bundled), the repo's dist/ (local build), then the download
    cache (fetched from the release)."""
    override = os.environ.get("AETHERIS_AGENT_DLL")
    if override and Path(override).is_file():
        return Path(override)
    candidates: list[Path] = []
    if getattr(sys, "frozen", False):
        candidates.append(Path(sys.executable).with_name(AGENT_DLL))
        meipass = getattr(sys, "_MEIPASS", "")
        if meipass:
            candidates.append(Path(meipass) / AGENT_DLL)
    repo = Path(__file__).resolve().parents[2]
    candidates.append(repo / "dist" / AGENT_DLL)
    candidates.append(_cached_dll())
    for c in candidates:
        if c.is_file():
            return c
    return None


def _manifest_url() -> str:
    """The version.json URL for the configured update source (so a source
    install can fetch the agent DLL published with the release)."""
    from ..core import updater
    src = updater.effective_update_url()
    if src.startswith("github:"):
        repo = src[len("github:"):].strip()
        return f"https://github.com/{repo}/releases/latest/download/version.json"
    return src


def ensure_agent_dll(allow_download: bool = True) -> tuple[Path | None, str]:
    """Return a usable agent DLL, downloading it from the release (sha256-
    verified) when it isn't present locally — so an install with no C++ compiler
    still gets a working agent. Returns (path, how) or (None, reason)."""
    local = agent_dll_path()
    if local is not None:
        return local, "local"
    if not allow_download:
        return None, "agent DLL not found — build it with agent/build.ps1"
    from ..core import updater
    url = _manifest_url()
    if not url:
        return None, "agent DLL not found and no update source is configured"
    try:
        data = updater._fetch_json(url, {"User-Agent": "Aetheris-Updater"})
    except Exception as exc:  # noqa: BLE001
        return None, f"agent DLL unavailable (manifest fetch failed: {exc})"
    agent = data.get("agent") if isinstance(data, dict) else None
    dll_url = str(agent.get("url", "")) if isinstance(agent, dict) else ""
    sha = str(agent.get("sha256", "")) if isinstance(agent, dict) else ""
    if not dll_url:
        return None, "this release publishes no downloadable agent DLL"
    dest = _cached_dll()
    try:
        updater.download(dll_url, dest)
    except Exception as exc:  # noqa: BLE001
        return None, f"agent DLL download failed: {exc}"
    if sha and updater._sha256(dest).lower() != sha.lower():
        dest.unlink(missing_ok=True)
        return None, "agent DLL checksum mismatch (discarded)"
    logbus.success(SRC, f"fetched API-monitor agent → {dest}")
    return dest, "downloaded"


# --- native injection + pipe transport (Windows only) ----------------------
IS_WINDOWS = sys.platform == "win32"

# Process rights just sufficient to inject a DLL via CreateRemoteThread.
_PROCESS_INJECT = 0x0002 | 0x0008 | 0x0010 | 0x0020 | 0x0400  # CREATE_THREAD|VM_OP|VM_READ|VM_WRITE|QUERY
_MEM_COMMIT_RESERVE = 0x1000 | 0x2000
_PAGE_READWRITE = 0x04
_MEM_RELEASE = 0x8000
_PIPE_ACCESS_INBOUND = 0x00000001
_PIPE_TYPE_BYTE = 0x00000000
_EVENT_MODIFY_STATE = 0x0002
_INVALID = -1

if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _k32.OpenProcess.restype = wintypes.HANDLE
    _k32.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t,
                                    wintypes.DWORD, wintypes.DWORD]
    _k32.VirtualAllocEx.restype = wintypes.LPVOID
    _k32.VirtualFreeEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t,
                                   wintypes.DWORD]
    _k32.VirtualFreeEx.restype = wintypes.BOOL
    _k32.WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID,
                                        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    _k32.WriteProcessMemory.restype = wintypes.BOOL
    _k32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    _k32.GetModuleHandleW.restype = wintypes.HMODULE
    _k32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
    _k32.GetProcAddress.restype = wintypes.LPVOID
    _k32.CreateRemoteThread.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t,
                                        wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD,
                                        wintypes.LPVOID]
    _k32.CreateRemoteThread.restype = wintypes.HANDLE
    _k32.CreateNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                      wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                                      wintypes.DWORD, wintypes.LPVOID]
    _k32.CreateNamedPipeW.restype = wintypes.HANDLE
    _k32.ConnectNamedPipe.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
    _k32.ConnectNamedPipe.restype = wintypes.BOOL
    _k32.ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                              ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
    _k32.ReadFile.restype = wintypes.BOOL
    _k32.CancelIoEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
    _k32.CancelIoEx.restype = wintypes.BOOL
    _k32.OpenEventW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    _k32.OpenEventW.restype = wintypes.HANDLE
    _k32.SetEvent.argtypes = [wintypes.HANDLE]
    _k32.SetEvent.restype = wintypes.BOOL
    _k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _k32.WaitForSingleObject.restype = wintypes.DWORD
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.CloseHandle.restype = wintypes.BOOL


def _err() -> str:
    import ctypes
    code = ctypes.get_last_error()
    return f"{code} ({ctypes.FormatError(code).strip()})" if code else "0"


def inject_dll(pid: int, dll_path: str) -> tuple[bool, str]:
    """Load ``dll_path`` into ``pid`` via the classic VirtualAllocEx +
    WriteProcessMemory + CreateRemoteThread(LoadLibraryW) sequence."""
    if not IS_WINDOWS:
        return False, "injection is Windows-only"
    import ctypes
    h = _k32.OpenProcess(_PROCESS_INJECT, False, pid)
    if not h:
        return False, f"OpenProcess failed: {_err()}"
    remote = None
    try:
        blob = (dll_path + "\0").encode("utf-16-le")
        remote = _k32.VirtualAllocEx(h, None, len(blob), _MEM_COMMIT_RESERVE, _PAGE_READWRITE)
        if not remote:
            return False, f"VirtualAllocEx failed: {_err()}"
        written = ctypes.c_size_t(0)
        if not _k32.WriteProcessMemory(h, remote, blob, len(blob), ctypes.byref(written)):
            return False, f"WriteProcessMemory failed: {_err()}"
        load = _k32.GetProcAddress(_k32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryW")
        if not load:
            return False, f"resolve LoadLibraryW failed: {_err()}"
        thread = _k32.CreateRemoteThread(h, None, 0, load, remote, 0, None)
        if not thread:
            return False, f"CreateRemoteThread failed: {_err()}"
        _k32.WaitForSingleObject(thread, 10000)
        _k32.CloseHandle(thread)
        return True, "injected"
    finally:
        if remote:
            _k32.VirtualFreeEx(h, remote, 0, _MEM_RELEASE)
        _k32.CloseHandle(h)


class AgentSession:
    """A live monitoring session: hosts the pipe, injects the agent, streams
    events to ``on_event`` on a background thread until ``stop()``."""

    def __init__(self, pid: int, name: str) -> None:
        self.pid = pid
        self.name = name
        self._pipe: int | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._on_event: Callable[[ApiEvent], None] = lambda e: None

    def _pipe_name(self) -> str:
        return rf"\\.\pipe\aetheris_agent_{self.pid}"

    def start(self, on_event: Callable[[ApiEvent], None],
              dry_run: bool = False) -> tuple[bool, str]:
        ok, msg = can_monitor(self.name)
        if not ok:
            logbus.warn(SRC, msg)
            return False, msg
        if dry_run:
            logbus.action(SRC, f"[dry-run] would inject the agent into {self.name} (pid {self.pid})")
            return True, "dry-run: agent not injected"
        if not IS_WINDOWS:
            return False, "API monitor is Windows-only"
        dll, how = ensure_agent_dll()
        if dll is None:
            return False, how
        if how == "downloaded":
            logbus.action(SRC, "fetched the API-monitor agent from the release")
        self._on_event = on_event
        self._pipe = _k32.CreateNamedPipeW(self._pipe_name(), _PIPE_ACCESS_INBOUND,
                                           _PIPE_TYPE_BYTE, 1, 65536, 65536, 0, None)
        if not self._pipe or self._pipe == _INVALID:
            self._pipe = None
            return False, f"CreateNamedPipe failed: {_err()}"
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, name="apimonitor", daemon=True)
        self._thread.start()
        ok, msg = inject_dll(self.pid, str(dll))
        if not ok:
            self.stop()
            return False, msg
        logbus.action(SRC, f"API monitor attached to {self.name} (pid {self.pid})")
        return True, f"attached to {self.name} (pid {self.pid})"

    def _serve(self) -> None:
        import ctypes
        _k32.ConnectNamedPipe(self._pipe, None)
        buf = b""
        size = 65536
        cbuf = ctypes.create_string_buffer(size)
        nread = wintypes.DWORD(0)
        while not self._stop.is_set():
            if not _k32.ReadFile(self._pipe, cbuf, size, ctypes.byref(nread), None) \
                    or nread.value == 0:
                break
            buf += cbuf.raw[:nread.value]
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                ev = parse_event(raw.decode("utf-8", "replace"))
                if ev is not None:
                    self._deliver(ev)
        # stream ended on its own (target exited / closed the pipe) — tell the UI
        if not self._stop.is_set():
            self._deliver(ApiEvent("__closed__"))

    def _deliver(self, ev: ApiEvent) -> None:
        try:
            self._on_event(ev)
        except Exception:  # noqa: BLE001 -- a bad callback can't kill the reader
            pass

    def stop(self) -> None:
        self._stop.set()
        if IS_WINDOWS:
            ev = _k32.OpenEventW(_EVENT_MODIFY_STATE, False, f"aetheris_agent_stop_{self.pid}")
            if ev:
                _k32.SetEvent(ev)
                _k32.CloseHandle(ev)
            if self._pipe and self._pipe != _INVALID:
                _k32.CancelIoEx(self._pipe, None)
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None
        if IS_WINDOWS and self._pipe and self._pipe != _INVALID:
            _k32.CloseHandle(self._pipe)
        self._pipe = None
        logbus.trace(SRC, f"API monitor detached from pid {self.pid}")
