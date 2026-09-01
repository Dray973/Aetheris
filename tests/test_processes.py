"""Process autopsy: the Authenticode signature wiring."""
import sys

import pytest

from aetheris.forensics import processes


def test_snapshot_without_sign_leaves_unchecked():
    rows = processes.snapshot(sign=False)
    assert rows
    assert all(r.signature == "unchecked" for r in rows)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Authenticode APIs")
def test_snapshot_with_sign_populates_real_signature():
    rows = processes.snapshot(sign=True)
    assert rows
    labels = {r.signature for r in rows}
    assert "signed" in labels
    for r in rows:
        if r.exe:
            assert r.signature in ("signed", "unsigned", "unknown")
