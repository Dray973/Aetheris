"""
Native signature verification: parity with the ctypes path, and the
embedded/catalog distinction the Python original collapsed.

The engine and the pure-ctypes implementation must reach the same verdict for
every binary — that is the contract that makes the native path safe to prefer.
Tests assert agreement rather than fixed verdicts, so they stay valid whatever
this machine happens to have installed.
"""
import os
import sys

import pytest

from aetheris.core import signing
from aetheris.native import win

pytestmark = pytest.mark.skipif(
    not win.available() or sys.platform != "win32",
    reason="aetheris_win.dll not built, or not Windows",
)


@pytest.fixture
def python_path(monkeypatch):
    """Force signing onto its pure-ctypes implementation."""
    monkeypatch.setattr(win, "verify_signature", lambda _p: None)
    signing._cache.clear()
    yield
    signing._cache.clear()


def _both(monkeypatch, path):
    """(native verdict, ctypes verdict) for one path, bypassing the cache."""
    signing._cache.clear()
    native = signing._verify(path)
    monkeypatch.setattr(win, "verify_signature", lambda _p: None)
    signing._cache.clear()
    fallback = signing._verify(path)
    return native, fallback


def _system_binaries(limit=25):
    root = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    out = []
    try:
        for name in sorted(os.listdir(root)):
            if name.lower().endswith((".exe", ".dll")):
                p = os.path.join(root, name)
                if os.path.isfile(p):
                    out.append(p)
            if len(out) >= limit:
                break
    except OSError:
        pass
    return out


def test_signed_system_binary_agrees_both_ways(monkeypatch):
    native, fallback = _both(monkeypatch, sys.executable)
    assert native == fallback


def test_parity_across_system_binaries(monkeypatch):
    paths = _system_binaries()
    if not paths:
        pytest.skip("no system binaries readable")
    for p in paths:
        native, fallback = _both(monkeypatch, p)
        assert native == fallback, f"verdict differs for {p}: {native} vs {fallback}"


def test_unsigned_file_is_reported_unsigned(tmp_path, monkeypatch):
    fake = tmp_path / "unsigned.exe"
    fake.write_bytes(b"MZ" + b"\x00" * 1024)
    native, fallback = _both(monkeypatch, str(fake))
    assert native is False and fallback is False


def test_missing_file_is_undeterminable():
    signing._cache.clear()
    assert signing._verify(r"C:\definitely\not\here\nope.exe") is None
    assert win.verify_signature(r"C:\definitely\not\here\nope.exe") is None


def test_directory_is_rejected():
    assert win.verify_signature(os.environ.get("SystemRoot", r"C:\Windows")) is None


def test_empty_path_is_rejected():
    assert win.verify_signature("") is None


def test_catalog_and_embedded_are_distinguished():
    """OS binaries are catalog-signed; the Python path could not tell them
    apart from embedded-signed ones."""
    verdicts = {win.verify_signature(p) for p in _system_binaries(40)}
    verdicts.discard(None)
    assert verdicts, "expected at least one verdict"
    assert verdicts <= {win.SIG_NONE, win.SIG_EMBEDDED, win.SIG_CATALOG}
    # System32 is overwhelmingly catalog-signed; if this ever fails the
    # distinction has stopped working rather than the machine being unusual.
    assert win.SIG_CATALOG in verdicts


def test_label_maps_verdicts(python_path):
    """label() still reports the same three words on the fallback path."""
    assert signing.label(sys.executable) in ("signed", "unsigned", "unknown")
    assert signing.label(None) == "unknown"
    assert signing.label(r"C:\nope\missing.exe") == "unknown"


def test_cache_is_used(monkeypatch):
    """is_signed caches per path — the second call must not re-verify."""
    signing._cache.clear()
    calls = []
    real = signing._verify
    monkeypatch.setattr(signing, "_verify", lambda p: (calls.append(p), real(p))[1])
    signing.is_signed(sys.executable)
    signing.is_signed(sys.executable)
    assert len(calls) == 1
