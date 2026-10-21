"""Mark-of-the-Web (Zone.Identifier) parsing."""
import sys

from aetheris.forensics import motw

CHROME = """[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://downloads.example.com/get?id=7&ref=%20x
HostUrl=https://cdn.example.net/files/upd.exe
"""


def test_parses_a_browser_download():
    o = motw.parse(CHROME)
    assert o is not None and o.zone_id == 3 and o.from_internet
    assert o.host == "cdn.example.net"
    assert o.zone == "internet"
    assert "cdn.example.net/files/upd.exe" in o.describe()
    assert "linked from https://downloads.example.com" in o.describe()


def test_tolerates_bom_case_junk_and_duplicates():
    text = "\ufeff[zonetransfer]\r\nzoneid = 3\r\ngarbage line\r\nZoneId=1\r\n"
    o = motw.parse(text)
    assert o is not None and o.zone_id == 3  # first value wins


def test_host_falls_back_to_referrer_and_skips_blob_urls():
    o = motw.parse("[ZoneTransfer]\nZoneId=3\nHostUrl=blob:https://x\n"
                   "ReferrerUrl=https://mail.example.org/inbox\n")
    assert o.host == "mail.example.org"


def test_local_zone_is_not_internet():
    o = motw.parse("[ZoneTransfer]\nZoneId=0\n")
    assert not o.from_internet and o.zone == "local machine"


def test_no_zonetransfer_section_is_none():
    assert motw.parse("[Other]\nZoneId=3\n") is None
    assert motw.parse("") is None


def test_bad_zone_id_is_unknown():
    o = motw.parse("[ZoneTransfer]\nZoneId=abc\nHostUrl=https://a.example/x\n")
    assert o.zone_id is None and o.zone == "unknown" and not o.from_internet


def test_read_is_none_off_windows_or_without_stream(tmp_path):
    f = tmp_path / "plain.exe"
    f.write_bytes(b"MZ")
    assert motw.read(str(f)) is None
    assert motw.read("") is None
    if sys.platform != "win32":
        assert motw.read(r"C:\Windows\notepad.exe") is None
