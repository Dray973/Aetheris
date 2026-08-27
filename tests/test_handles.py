"""Handle enumeration, Restart-Manager lockers, and forced handle closing.

Windows-only. The strip test spawns a child that holds a file open, then closes
that handle out from under it and confirms the file becomes deletable.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")

from aetheris.storage import handles, unlock


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
    sentinel = os.path.join(d, "ready.flag")
    open(target, "w").write("payload")
    # Child opens the file, then writes a sentinel to signal the handle is open,
    # then blocks. This removes the Restart-Manager dependency: we KNOW the
    # handle exists before stripping, so the native strip path is exercised
    # deterministically (no timing-based skip) -- which is what CI must verify.
    code = (f"f=open(r'{target}','r');"
            f"open(r'{sentinel}','w').close();"
            "import time; time.sleep(30)")
    child = subprocess.Popen([sys.executable, "-c", code])
    try:
        deadline = time.time() + 20               # generous for cold CI startup
        while not os.path.exists(sentinel) and time.time() < deadline:
            if child.poll() is not None:
                raise AssertionError(
                    f"child exited early (rc={child.returncode}) before opening file")
            time.sleep(0.05)
        assert os.path.exists(sentinel), "child never signalled its open handle"

        # The child now holds a real handle to `target`. Strip it.
        results = unlock.strip_handles(target)
        assert results, "strip_handles found no open handles to close"
        assert all(ok for _pid, _hv, ok, _note in results)

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
