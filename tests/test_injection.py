"""Memory-injection classification: RWX / unbacked-exec / private-PE."""
from types import SimpleNamespace

from aetheris.forensics import injection as inj


def _r(base, size, protect, type_):
    return SimpleNamespace(base=base, size=size, protect=protect, type=type_)


class FakeBackend:
    def __init__(self, regions, mem=None):
        self._regions = regions
        self._mem = mem or {}

    def memory_map(self, pid):
        return self._regions

    def read(self, pid, address, size):
        return self._mem.get(address, b"")[:size]


def test_classify_region():
    assert inj.classify_region("rwx", "private") == "rwx"
    assert inj.classify_region("rwx", "image") == "rwx"            # RWX even if image-backed
    assert inj.classify_region("r-x", "private") == "unbacked-exec"
    assert inj.classify_region("r-x", "image") is None             # normal code page
    assert inj.classify_region("rw-", "private") is None           # data
    assert inj.classify_region("---", "private") is None


def test_scan_process_promotes_private_pe():
    regions = [
        _r(0x1000, 0x2000, "rwx", "private"),      # rwx
        _r(0x4000, 0x1000, "r-x", "private"),      # unbacked-exec (no MZ)
        _r(0x8000, 0x1000, "r-x", "private"),      # unbacked-exec + MZ -> private-pe
        _r(0xC000, 0x1000, "r-x", "image"),        # normal, ignored
        _r(0xE000, 0x1000, "rw-", "private"),      # data, ignored
    ]
    be = FakeBackend(regions, {0x8000: b"MZ\x90\x00"})
    kinds = {f.base: f.kind for f in inj.scan_process(be, 1234, "evil.exe")}
    assert kinds == {0x1000: "rwx", 0x4000: "unbacked-exec", 0x8000: "private-pe"}
