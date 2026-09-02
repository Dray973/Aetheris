"""In-process API monitor: event parsing/display, refusal guard, DLL discovery."""
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
