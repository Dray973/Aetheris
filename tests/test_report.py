"""Forensic report serializers (pure string transforms)."""
import json

from aetheris.core import report
from aetheris.forensics.processes import ProcessInfo
from aetheris.network.connections import Connection


def _procs():
    return [
        ProcessInfo(1, "a.exe", "u", r"C:\a.exe", 1.0, 100 * 2**20, 4, "running"),
        ProcessInfo(2, "b.exe", "u", r"C:\b.exe", 2.0, 300 * 2**20, 8, "running"),
    ]


def _conns():
    return [
        Connection(1, "a.exe", "10.0.0.2", 5000, "8.8.8.8", 443, "ESTABLISHED",
                   "IPv4", "TCP", "public", "dns.google", "US · Mountain View"),
        Connection(2, "b.exe", "0.0.0.0", 135, "", 0, "LISTEN", "IPv4", "TCP"),
    ]


def test_rows_to_csv():
    out = report.rows_to_csv(["a", "b"], [[1, 2], [3, 4]])
    assert out.splitlines()[0] == "a,b"
    assert "3,4" in out


def test_rows_to_json():
    data = json.loads(report.rows_to_json([{"x": 1}, {"x": 2}]))
    assert data == [{"x": 1}, {"x": 2}]


def test_escape_html_blocks_injection():
    assert report.escape_html("<script>&\"") == "&lt;script&gt;&amp;&quot;"


def test_process_and_connection_rows():
    pr = report.process_rows(_procs())
    assert pr[0]["pid"] == 1 and pr[1]["mem_rss"] == 300 * 2**20
    cr = report.connection_rows(_conns())
    assert cr[0]["geo"] == "US · Mountain View" and cr[0]["remote"] == "8.8.8.8"


def test_html_document_structure_and_escaping():
    html = report.html_document("Report <x>", [
        ("Summary", "kv", {"host": "PC<1>"}),
        ("Procs", "table", (["PID", "Name"], [[1, "a<b>"]])),
        ("Log", "pre", "line1\n<b>"),
    ])
    assert html.startswith("<!doctype html>")
    assert "<title>Report &lt;x&gt;</title>" in html
    assert "PC&lt;1&gt;" in html
    assert "a&lt;b&gt;" in html
    assert html.rstrip().endswith("</html>")


def test_session_markdown_has_sections():
    md = report.session_markdown(_procs(), _conns())
    assert "# Aetheris Quantum Core — Session Report" in md
    assert "## Top processes by memory" in md
    assert "## Active remote connections" in md
    assert "8.8.8.8" in md
