"""Validate the committed application icon is a well-formed multi-size ICO."""
import struct
from pathlib import Path

ICON = Path(__file__).resolve().parent.parent / "aetheris" / "ui" / "assets" / "aetheris.ico"


def test_icon_exists():
    assert ICON.is_file(), f"missing icon: {ICON}"


def test_icon_is_valid_multisize_ico():
    data = ICON.read_bytes()
    reserved, itype, count = struct.unpack_from("<HHH", data, 0)
    assert reserved == 0 and itype == 1
    assert count >= 4
    sizes = []
    for i in range(count):
        off = 6 + 16 * i
        w, h, _cc, _r, _planes, _bpp, nbytes, img_off = struct.unpack_from(
            "<BBBBHHII", data, off)
        sizes.append(w or 256)
        assert nbytes > 0 and img_off + nbytes <= len(data)
        assert data[img_off:img_off + 4] == b"\x89PNG"
    assert 16 in sizes and 256 in sizes
