"""Virtual-memory helpers: hex formatter + backend selection."""
from aetheris.forensics import memvirt


def test_format_hex_layout():
    out = memvirt.format_hex(bytes(range(16)), 0x1000)
    line = out.splitlines()[0]
    assert line.startswith("0x000000001000  00 01 02 03")
    assert line.endswith("." * 16)


def test_format_hex_ascii_column():
    out = memvirt.format_hex(b"ABC\x00\xff", 0)
    assert out.splitlines()[0].endswith("ABC..")


def test_get_backend_returns_a_backend():
    b = memvirt.get_backend()
    assert isinstance(b, memvirt.MemoryBackend)
    assert hasattr(b.capabilities, "physical")
