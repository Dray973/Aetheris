"""
Native handle search and forced close.

These exercise the destructive path, so every test operates on a file this test
opened itself, in this process. Nothing here touches another process's handles.
"""
import os
import sys

import pytest

from aetheris.native import win
from aetheris.storage import handles

pytestmark = pytest.mark.skipif(
    not win.available() or sys.platform != "win32",
    reason="aetheris_win.dll not built, or not Windows",
)


@pytest.fixture
def open_file(tmp_path):
    """A real file held open by this process, plus its NT device path."""
    p = tmp_path / "handle-probe.bin"
    p.write_bytes(b"aetheris handle search probe")
    fh = open(p, "rb")
    device = handles.to_device_path(str(p))
    try:
        yield str(p), device, fh
    finally:
        try:
            fh.close()
        except OSError:
            pass


def test_to_device_path_maps_a_drive_letter(open_file):
    _path, device, _fh = open_file
    assert device is not None
    assert device.lower().startswith("\\device\\")


def test_finds_a_handle_this_process_holds(open_file):
    path, device, _fh = open_file
    found = win.find_handles_by_name(device, {os.getpid()})
    assert found is not None
    assert found, f"expected to find our own open handle to {path}"
    assert all(e.pid == os.getpid() for e in found)


def test_search_is_case_insensitive(open_file):
    _path, device, _fh = open_file
    upper = win.find_handles_by_name(device.upper(), {os.getpid()})
    lower = win.find_handles_by_name(device.lower(), {os.getpid()})
    assert upper and lower
    assert {e.handle for e in upper} == {e.handle for e in lower}


def test_unmatched_name_returns_empty(open_file):
    _path, device, _fh = open_file
    assert win.find_handles_by_name(device + ".no-such-suffix", {os.getpid()}) == []


def test_pid_filter_excludes_other_processes(open_file):
    _path, device, _fh = open_file
    # Filter to a pid that cannot hold our handle.
    assert win.find_handles_by_name(device, {4}) == []


def test_find_file_handles_goes_through_the_engine(open_file):
    path, _device, _fh = open_file
    matches = handles.find_file_handles(path, {os.getpid()})
    assert matches, "storage.handles should surface our own handle"
    assert all(pid == os.getpid() for pid, _hv in matches)


def test_forced_close_actually_closes(open_file):
    """The destructive path, on a handle this test owns."""
    path, device, fh = open_file
    found = win.find_handles_by_name(device, {os.getpid()})
    assert found, "nothing to close"

    ok = win.close_handle_in_process(os.getpid(), found[0].handle)
    assert ok is True

    # The handle is gone from the table.
    after = win.find_handles_by_name(device, {os.getpid()})
    assert len(after) < len(found)

    # And the Python file object is now backed by a dead descriptor. Reading
    # raises rather than returning data; either error is a correct outcome.
    with pytest.raises((OSError, ValueError)):
        fh.seek(0)
        fh.read()


def test_closing_a_bogus_handle_fails_cleanly():
    assert win.close_handle_in_process(os.getpid(), 0xFFFC) is False


def test_closing_in_a_protected_process_is_refused():
    # pid 4 (System) refuses PROCESS_DUP_HANDLE even elevated.
    assert win.close_handle_in_process(4, 0x4) is False


def test_search_without_pids_scans_every_process(open_file):
    """pids=None is the system-wide search the Python original could not run."""
    _path, device, _fh = open_file
    found = win.find_handles_by_name(device, None)
    assert found is not None
    assert any(e.pid == os.getpid() for e in found)
