"""
Guardrails on the forced handle-close path.

This is the most invasive operation in `storage` — it takes a handle away from
a process that is still using it, which can cost that process unsaved data. Two
protections are easy to lose in a refactor and are pinned here:

  * an empty PID filter must match nothing, never everything;
  * global dry-run must rehearse rather than act.

Both are tested without touching a real handle: the empty-filter case cannot
reach the OS by definition, and the dry-run case asserts the destructive call
is never made.
"""
import sys

import pytest

from aetheris.core import dryrun
from aetheris.native import win
from aetheris.storage import handles

# --- an empty PID filter must not widen into a system-wide search -----------


def test_empty_pid_set_matches_nothing(monkeypatch):
    """
    The caller narrows this set to exclude system-critical processes. If an
    empty set fell through as "no filter", the search would return handles from
    every process on the machine — including the ones just excluded — and those
    results feed the forced-close path.
    """
    called = []
    monkeypatch.setattr(win, "find_handles_by_name",
                        lambda *a, **k: called.append(a) or [])
    assert handles.find_file_handles(r"C:\Windows\notepad.exe", set()) == []
    assert not called, "an empty filter must not reach the engine at all"


@pytest.mark.skipif(not win.available() or sys.platform != "win32",
                    reason="aetheris_win.dll not built, or not Windows")
def test_engine_distinguishes_empty_set_from_none():
    """None means every process; an empty set means none of them."""
    device = handles.to_device_path(sys.executable)
    assert device is not None
    assert win.find_handles_by_name(device, set()) == []
    # None is the deliberate system-wide search and must still work.
    assert win.find_handles_by_name(device, None) is not None


def test_strip_file_handles_short_circuits_on_empty(monkeypatch):
    closed = []
    monkeypatch.setattr(handles, "close_handle_in_process",
                        lambda p, h: closed.append((p, h)) or (True, "closed"))
    assert handles.strip_file_handles(r"C:\Windows\notepad.exe", set()) == []
    assert not closed


# --- dry-run must rehearse, not act -----------------------------------------


def test_forced_close_honours_dry_run(monkeypatch):
    """
    Every other destructive op in the suite rehearses under dry-run (kill,
    patch_memory, physical_write, autorun disable). This one did not, and the
    check belongs on the primitive so no caller can route around it.
    """
    reached = []
    monkeypatch.setattr(win, "close_handle_in_process",
                        lambda p, h: reached.append((p, h)) or True)

    with dryrun.active(True):
        ok, msg = handles.close_handle_in_process(1234, 0xC0)
    assert ok, "a rehearsed action reports success"
    assert "dry-run" in msg.lower()
    assert not reached, "dry-run must not perform the close"


def test_forced_close_acts_when_dry_run_is_off(monkeypatch):
    reached = []
    monkeypatch.setattr(win, "close_handle_in_process",
                        lambda p, h: reached.append((p, h)) or True)
    with dryrun.active(False):
        ok, msg = handles.close_handle_in_process(1234, 0xC0)
    assert ok and "dry-run" not in msg.lower()
    assert reached == [(1234, 0xC0)], "the close must happen when not rehearsing"


def test_strip_handles_rehearses_end_to_end(monkeypatch):
    """The orchestrator inherits the guard from the primitive."""
    monkeypatch.setattr(handles, "find_file_handles",
                        lambda path, pids: [(1234, 0xC0), (1234, 0xC4)])
    reached = []
    monkeypatch.setattr(win, "close_handle_in_process",
                        lambda p, h: reached.append((p, h)) or True)

    with dryrun.active(True):
        results = handles.strip_file_handles(r"C:\some\file.txt", {1234})
    assert len(results) == 2
    assert all(ok for _p, _h, ok, _n in results)
    assert all("dry-run" in note.lower() for _p, _h, _ok, note in results)
    assert not reached
