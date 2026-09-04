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


def test_pmem_expands_to_the_driver_path(tmp_path, monkeypatch):
    driver = tmp_path / "winpmem_x64.sys"
    driver.write_bytes(b"")
    monkeypatch.setenv("AETHERIS_WINPMEM", str(driver))
    arg, blocked = memvirt._device_arg("pmem")
    assert not blocked
    assert arg == f"pmem://{driver.resolve()}"


def test_pmem_is_skipped_when_no_driver_is_found(tmp_path, monkeypatch):
    """Bare '-device pmem' always fails in LeechCore, so it must not be tried."""
    monkeypatch.delenv("AETHERIS_WINPMEM", raising=False)
    monkeypatch.setattr(memvirt, "find_winpmem", lambda: None)
    arg, blocked = memvirt._device_arg("pmem")
    assert arg == "pmem" and "winpmem" in blocked


def test_other_devices_pass_through_untouched():
    for dev in ("fpga", r"c:\dumps\win10x64.raw", "pmem://c:\\drv\\winpmem_x64.sys"):
        assert memvirt._device_arg(dev) == (dev, "")
