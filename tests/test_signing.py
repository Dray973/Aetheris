"""Authenticode signature check: real WinVerifyTrust + catalog fallback.

Windows-only (loads wintrust). Proves embedded-signed and catalog-signed OS
binaries both verify, a hand-made file does not, and undeterminable inputs
return None.
"""
import os
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows signing APIs")

from aetheris.core import signing


def test_none_and_missing_are_undeterminable(tmp_path):
    assert signing.is_signed(None) is None
    assert signing.is_signed(str(tmp_path / "does-not-exist.exe")) is None


def test_embedded_and_catalog_signed_os_binaries_verify():
    assert signing.is_signed(r"C:\Windows\System32\kernel32.dll") is True   # embedded
    assert signing.is_signed(r"C:\Windows\System32\notepad.exe") is True    # catalog


def test_handmade_file_is_unsigned(tmp_path):
    f = tmp_path / "fake.exe"
    f.write_bytes(b"MZ" + b"\x00" * 512)
    assert signing.is_signed(str(f)) is False


def test_label_maps_states(tmp_path):
    assert signing.label(r"C:\Windows\System32\kernel32.dll") == "signed"
    f = tmp_path / "fake.exe"
    f.write_bytes(b"MZ" + b"\x00" * 300)
    assert signing.label(str(f)) == "unsigned"
    assert signing.label(None) == "unknown"


def test_results_are_cached():
    p = r"C:\Windows\System32\kernel32.dll"
    signing._cache.clear()
    signing.is_signed(p)
    assert os.path.normcase(os.path.abspath(p)) in signing._cache
