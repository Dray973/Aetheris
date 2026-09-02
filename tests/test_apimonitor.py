"""In-process API monitor: event parsing/display, refusal guard, DLL discovery."""
import hashlib

from aetheris.core import updater
from aetheris.forensics import apimonitor as am


def test_parse_event_valid():
    ev = am.parse_event('{"tid":42,"api":"CreateFileW","path":"C:\\\\x.txt"}')
    assert ev is not None
    assert ev.api == "CreateFileW" and ev.tid == 42
    assert ev.fields["path"] == "C:\\x.txt"
    assert not ev.is_control


def test_parse_event_control_and_junk():
    assert am.parse_event('{"tid":1,"api":"__ready__","hooks":57}').is_control
    assert am.parse_event("") is None
    assert am.parse_event("not json") is None
    assert am.parse_event('{"tid":1}') is None          # no api
    assert am.parse_event('["a","b"]') is None           # not an object


def test_describe_variants():
    assert "57 hook" in am.ApiEvent("__ready__", fields={"hooks": 57}).describe()
    assert am.ApiEvent("CreateFileW", fields={"path": "C:\\x"}).describe().endswith("C:\\x")
    d = am.ApiEvent("VirtualAlloc", fields={"size": 4096, "protect": 0x40}).describe()
    assert "size=4096" in d and "EXECUTE_READWRITE" in d
    d = am.ApiEvent("WriteProcessMemory", fields={"size": 128, "pid": 9002}).describe()
    assert "size=128" in d and "9002" in d
    # generic fallback sorts unknown fields
    assert "a=1  b=2" in am.ApiEvent("Foo", fields={"b": 2, "a": 1}).describe()


def test_describe_caller_process_and_network():
    d = am.ApiEvent("CreateProcessW", 1,
                    {"app": "", "cmdline": "cmd.exe /c exit", "caller": "t.exe+0x1"}).describe()
    assert "cmd.exe /c exit" in d and d.endswith("t.exe+0x1")
    d = am.ApiEvent("connect", 1,
                    {"endpoint": "127.0.0.1:9999", "caller": "ws2_32.dll+0x40"}).describe()
    assert "127.0.0.1:9999" in d and "ws2_32.dll+0x40" in d
    # caller renders as a trailing "← …" tail, not folded into the generic k=v list
    d = am.ApiEvent("CreateFileW", 1, {"path": "C:/x", "caller": "u.dll+0x9"}).describe()
    assert d == "CreateFileW  C:/x   \u2190 u.dll+0x9"


def test_protect_name():
    assert am.protect_name(0x40) == "EXECUTE_READWRITE"
    assert am.protect_name(0x04) == "READWRITE"
    assert am.protect_name(0x04 | 0x100) == "READWRITE+GUARD"
    assert am.protect_name(0x1234).startswith("0x")  # unknown → hex


def test_can_monitor_refuses_critical():
    ok, msg = am.can_monitor("lsass.exe")
    assert not ok and "system-critical" in msg
    ok, _ = am.can_monitor("notepad.exe")
    assert ok


def test_agent_dll_path_env_override(tmp_path, monkeypatch):
    dll = tmp_path / "aetheris_agent.dll"
    dll.write_bytes(b"MZ")
    monkeypatch.setenv("AETHERIS_AGENT_DLL", str(dll))
    assert am.agent_dll_path() == dll
    monkeypatch.setenv("AETHERIS_AGENT_DLL", str(tmp_path / "missing.dll"))
    # falls through to repo/dist discovery (may or may not exist) — just must not raise
    am.agent_dll_path()


def test_manifest_url_from_github_and_http(monkeypatch):
    monkeypatch.setattr(updater, "effective_update_url", lambda: "github:owner/repo")
    assert am._manifest_url() == \
        "https://github.com/owner/repo/releases/latest/download/version.json"
    monkeypatch.setattr(updater, "effective_update_url", lambda: "https://x/version.json")
    assert am._manifest_url() == "https://x/version.json"


def test_ensure_agent_dll_uses_local(monkeypatch, tmp_path):
    local = tmp_path / "aetheris_agent.dll"
    local.write_bytes(b"MZ")
    monkeypatch.setattr(am, "agent_dll_path", lambda: local)
    path, how = am.ensure_agent_dll()
    assert path == local and how == "local"


def test_ensure_agent_dll_no_download_when_disallowed(monkeypatch):
    monkeypatch.setattr(am, "agent_dll_path", lambda: None)
    path, how = am.ensure_agent_dll(allow_download=False)
    assert path is None and "build it" in how


def test_ensure_agent_dll_downloads_and_verifies(monkeypatch, tmp_path):
    payload = b"AGENT-DLL-BYTES"
    sha = hashlib.sha256(payload).hexdigest()
    dest = tmp_path / "agent" / "aetheris_agent.dll"
    monkeypatch.setattr(am, "agent_dll_path", lambda: None)
    monkeypatch.setattr(am, "_cached_dll", lambda: dest)
    monkeypatch.setattr(am, "_manifest_url", lambda: "http://x/version.json")
    monkeypatch.setattr(updater, "_fetch_json",
                        lambda url, headers=None: {"agent": {"url": "http://x/a.dll", "sha256": sha}})

    def _dl(url, d):
        d.parent.mkdir(parents=True, exist_ok=True)
        d.write_bytes(payload)
    monkeypatch.setattr(updater, "download", _dl)

    path, how = am.ensure_agent_dll()
    assert path == dest and how == "downloaded"
    assert dest.read_bytes() == payload


def test_ensure_agent_dll_rejects_checksum_mismatch(monkeypatch, tmp_path):
    dest = tmp_path / "agent" / "aetheris_agent.dll"
    monkeypatch.setattr(am, "agent_dll_path", lambda: None)
    monkeypatch.setattr(am, "_cached_dll", lambda: dest)
    monkeypatch.setattr(am, "_manifest_url", lambda: "http://x/version.json")
    monkeypatch.setattr(updater, "_fetch_json",
                        lambda url, headers=None: {"agent": {"url": "http://x/a.dll", "sha256": "dead"}})

    def _dl(url, d):
        d.parent.mkdir(parents=True, exist_ok=True)
        d.write_bytes(b"whatever")
    monkeypatch.setattr(updater, "download", _dl)

    path, how = am.ensure_agent_dll()
    assert path is None and "checksum" in how
    assert not dest.exists()


def test_ensure_agent_dll_no_agent_in_manifest(monkeypatch):
    monkeypatch.setattr(am, "agent_dll_path", lambda: None)
    monkeypatch.setattr(am, "_manifest_url", lambda: "http://x/version.json")
    monkeypatch.setattr(updater, "_fetch_json", lambda url, headers=None: {"version": "9.9.9"})
    path, how = am.ensure_agent_dll()
    assert path is None and "no downloadable" in how
