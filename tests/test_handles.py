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
        time.sleep(1.2)
        assert child.pid in {p for p, _ in handles.locking_processes(target)}

        results = unlock.strip_handles(target)
        assert results and all(ok for _pid, _hv, ok, _note in results)

        # The handle is gone and the file is now deletable.
        assert handles.find_file_handles(target, {child.pid}) == []
        os.remove(target)
        assert not os.path.exists(target)
    finally:
        child.terminate()
        try:
            child.wait(timeout=3)
        except Exception:
            child.kill()
        shutil.rmtree(d, ignore_errors=True)
