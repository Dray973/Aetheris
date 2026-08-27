"""Autoruns enumeration + reversible disable/enable."""
import sys

import pytest

from aetheris.core import autoruns


def test_enumerate_returns_entries():
    entries = autoruns.enumerate_entries()
    assert isinstance(entries, list)
    for e in entries:
        assert isinstance(e, autoruns.AutorunEntry)
        assert e.kind in ("registry", "folder")
        assert isinstance(e.enabled, bool)


def test_entry_model():
    e = autoruns.AutorunEntry("n", "cmd", "loc", "registry", True,
                              root="HKCU", subkey="X")
    assert e.enabled and e.root == "HKCU" and e.kind == "registry"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")
def test_disable_enable_registry_roundtrip():
    import winreg
    RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"
    name = "AetherisAutorunTest_UnitTest_zzz"
    val = r"C:\nonexistent\aetheris-test.exe"

    def _get():
        try:
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN)
            v, _ = winreg.QueryValueEx(k, name)
            winreg.CloseKey(k)
            return v
        except OSError:
            return None

    def _del(subkey):
        try:
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(k, name)
            winreg.CloseKey(k)
        except OSError:
            pass

    k = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN, 0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(k, name, 0, winreg.REG_SZ, val)
    winreg.CloseKey(k)
    try:
        e = next(x for x in autoruns.enumerate_entries() if x.name == name and x.enabled)
        ok, _ = autoruns.disable(e)
        assert ok and _get() is None                      # removed from Run

        e2 = next(x for x in autoruns.enumerate_entries() if x.name == name)
        assert not e2.enabled                              # shows as disabled

        ok2, _ = autoruns.enable(e2)
        assert ok2 and _get() == val                       # restored exactly
    finally:
        _del(RUN)
        _del(autoruns._BACKUP_KEY)
