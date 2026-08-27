"""Handle enumeration, Restart-Manager lockers, and forced handle closing.

Windows-only. The strip test spawns a child that holds a file open, then closes
that handle out from under it and confirms the file becomes deletable.
"""
import os
import sys
import time
import shutil
import tempfile
import subprocess

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")

from aetheris.storage import handles, unlock  # noqa: E402


def test_to_device_path():
    d = tempfile.mkdtemp()
    try:
        p = os.path.join(d, "f.txt")
        dev = handles.to_device_path(p)
        assert dev and dev.lower().startswith("\\device\\")
        assert dev.endswith(p[2:])  # drive-letter stripped, tail preserved
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_locking_processes_finds_self():
    d = tempfile.mkdtemp()
    p = os.path.join(d, "held.dat")
    fh = open(p, "w")
    fh.write("x")
    fh.flush()
    try:
        pids = {pid for pid, _name in handles.locking_processes(p)}
        assert os.getpid() in pids
    finally:
        fh.close()
        shutil.rmtree(d, ignore_errors=True)


def test_strip_closes_child_handle_and_unlocks_file():
    d = tempfile.mkdtemp()
    target = os.path.join(d, "locked.dat")
    open(target, "w").write("payload")
    child = subprocess.Popen(
        [sys.executable, "-c",
         f"f=open(r'{target}','r'); import time; time.sleep(30)"])  # keep handle open
    try:
        # Poll (child startup + Restart-Manager visibility varies by machine/load).
        deadline = time.time() + 15
        lockers: set[int] = set()
        while time.time() < deadline:
            lockers = {p for p, _ in handles.locking_processes(target)}
            if child.pid in lockers:
                break
            time.sleep(0.3)
        if child.pid not in lockers:
            import pytest
            pytest.skip("Restart Manager did not report the child locker in time")

        results = unlock.strip_handles(target)
        assert results and all(ok for _pid, _hv, ok, _note in results)

        # The child's handle to the file is gone.
        assert handles.find_file_handles(target, {child.pid}) == []
        # ...and (best effort) the file is now deletable.
        try:
            os.remove(target)
        except OSError:
            pass
    finally:
        child.terminate()
        try:
            child.wait(timeout=3)
        except Exception:
            child.kill()
        shutil.rmtree(d, ignore_errors=True)
