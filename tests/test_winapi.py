"""Shared native bindings: the 64-bit HANDLE restypes are bound centrally so no
consumer can truncate a handle to a 32-bit int by importing in the wrong order."""
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows ctypes")


def test_handle_returning_functions_are_bound_to_HANDLE():
    from ctypes import wintypes

    from aetheris.core import winapi as W
    assert W.kernel32.OpenProcess.restype is wintypes.HANDLE
    assert W.kernel32.GetCurrentProcess.restype is wintypes.HANDLE
    assert W.kernel32.CloseHandle.restype is wintypes.BOOL
