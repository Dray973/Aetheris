"""
Native services, drivers, sockets and privileges: parity with the Python paths.

These run against the live machine, so they assert agreement between the two
implementations and structural invariants rather than fixed values. Sets are
compared with tolerance for churn — a service can start or a socket close
between the two passes, and that is not a parity failure.
"""
import ctypes
import sys

import pytest

from aetheris.core import privileges, services
from aetheris.native import win
from aetheris.network import connections

pytestmark = pytest.mark.skipif(
    not win.available() or sys.platform != "win32",
    reason="aetheris_win.dll not built, or not Windows",
)


@pytest.fixture
def no_native(monkeypatch):
    """Force every caller in this module onto its Python path."""
    for name in ("enum_services", "enum_driver_services", "enum_connections",
                 "enable_privilege"):
        monkeypatch.setattr(win, name, lambda *a, **k: None)


# --- ABI layout ------------------------------------------------------------


def test_struct_sizes_match_the_cpp_side():
    assert ctypes.sizeof(win._AwService) == 2588
    assert ctypes.sizeof(win._AwConnection) == 52


# --- services --------------------------------------------------------------


def test_services_enumerate():
    svcs = win.enum_services()
    assert svcs is not None and len(svcs) > 20
    assert all(s.name for s in svcs)
    # Every box has the Windows Event Log service.
    assert any(s.name.lower() == "eventlog" for s in svcs)


def test_service_labels_are_known_values():
    for s in win.enum_services():
        assert s.state_label in ("stopped", "start_pending", "stop_pending",
                                 "running", "continue_pending", "pause_pending",
                                 "paused", "unknown")
        assert s.start_label in ("boot", "system", "auto", "manual",
                                 "disabled", "unknown")


def test_services_agree_with_psutil(monkeypatch):
    native = {s.name.lower(): s for s in services.enumerate_services(check_signature=False)}
    monkeypatch.setattr(win, "enum_services", lambda *a, **k: None)
    py = {s.name.lower(): s for s in services.enumerate_services(check_signature=False)}
    common = set(native) & set(py)
    assert len(common) > 20
    # A service may start or stop between the two passes; require near-total
    # agreement rather than exact, and no systematic divergence.
    mismatched = [k for k in common
                  if (native[k].state, native[k].start_type)
                  != (py[k].state, py[k].start_type)]
    assert len(mismatched) <= 2, f"state/start differs for {mismatched[:5]}"


def test_start_label_spelling_matches_the_services_module():
    """core.services spells automatic start 'auto'; the binding must agree."""
    assert set(win._START_TYPE.values()) <= set(services._START_TYPES.values())
    for code, label in services._START_TYPES.items():
        assert win._START_TYPE[code] == label


# --- drivers ---------------------------------------------------------------


def test_drivers_enumerate():
    drivers = win.enum_driver_services()
    assert drivers is not None and len(drivers) > 50
    assert all(d.name for d in drivers)


def test_drivers_agree_with_winreg(monkeypatch):
    native = {d.name.lower(): d for d in services.enumerate_drivers(check_signature=False)}
    monkeypatch.setattr(win, "enum_driver_services", lambda *a, **k: None)
    py = {d.name.lower(): d for d in services.enumerate_drivers(check_signature=False)}
    assert set(native) == set(py)
    for k in native:
        assert (native[k].image_path, native[k].start_type, native[k].state) == \
               (py[k].image_path, py[k].start_type, py[k].state), k


def test_absent_start_value_reports_unknown_not_boot():
    """A Services key with no Start value must not be read as boot-start (0)."""
    for d in win.enum_driver_services():
        assert d.start_type != win.VALUE_ABSENT
        assert d.start_type == -1 or 0 <= d.start_type <= 4


# --- sockets ---------------------------------------------------------------


def test_connections_enumerate():
    conns = win.enum_connections()
    assert conns is not None and conns
    assert all(c.proto in ("TCP", "UDP") for c in conns)
    assert all(c.family in (4, 6) for c in conns)
    assert all(0 <= c.lport <= 65535 for c in conns)


def test_listening_socket_has_no_peer():
    """A LISTEN socket reports 0.0.0.0:0 as its peer; that must read as empty."""
    listening = [c for c in win.enum_connections()
                 if c.proto == "TCP" and win.tcp_state_label(c.state) == "LISTEN"]
    assert listening, "expected at least one listening socket"
    assert all(c.raddr == "" and c.rport == 0 for c in listening)


def test_udp_sockets_have_no_peer_or_state():
    for c in win.enum_connections():
        if c.proto == "UDP":
            assert c.raddr == "" and c.rport == 0


def test_addresses_are_parseable():
    import ipaddress
    for c in win.enum_connections():
        if c.laddr:
            ipaddress.ip_address(c.laddr)
        if c.raddr:
            ipaddress.ip_address(c.raddr)


def test_connections_agree_with_psutil(monkeypatch):
    def key(c):
        return (c.kind, c.family, c.laddr, c.lport, c.raddr, c.rport)

    native = {key(c): c for c in connections.snapshot(resolve_geo=False)}
    monkeypatch.setattr(win, "enum_connections", lambda *a, **k: None)
    py = {key(c): c for c in connections.snapshot(resolve_geo=False)}
    common = set(native) & set(py)
    assert len(common) > 5, "expected overlapping sockets between the two passes"
    for k in common:
        assert native[k].status == py[k].status, k
        assert native[k].remote_class == py[k].remote_class, k


def test_tcp_state_labels():
    assert win.tcp_state_label(2) == "LISTEN"
    assert win.tcp_state_label(5) == "ESTABLISHED"
    assert win.tcp_state_label(999) == "NONE"


# --- privileges ------------------------------------------------------------


def test_enable_privilege_reports_a_result():
    result = win.enable_privilege("SeDebugPrivilege")
    assert result is not None
    ok, msg = result
    assert isinstance(ok, bool) and "SeDebugPrivilege" in msg


def test_unknown_privilege_is_refused():
    ok, msg = win.enable_privilege("SeNotARealPrivilege")
    assert not ok and "SeNotARealPrivilege" in msg


def test_privilege_paths_agree(monkeypatch):
    native_ok, _ = privileges.enable_privilege("SeDebugPrivilege")
    monkeypatch.setattr(win, "enable_privilege", lambda *a, **k: None)
    py_ok, _ = privileges.enable_privilege("SeDebugPrivilege")
    assert native_ok == py_ok


# --- fallback --------------------------------------------------------------


def test_every_caller_still_works_without_the_engine(no_native):
    assert len(services.enumerate_services(check_signature=False)) > 20
    assert len(services.enumerate_drivers(check_signature=False)) > 50
    assert connections.snapshot(resolve_geo=False)
    ok, msg = privileges.enable_privilege("SeDebugPrivilege")
    assert isinstance(ok, bool) and msg
