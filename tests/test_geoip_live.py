"""
End-to-end GeoIP against a real GeoLite2 .mmdb.

Runs only when a database is discoverable — set AETHERIS_GEOIP_DB, or drop a
.mmdb into tests/fixtures/ (see tests/fixtures/README.md). Skips otherwise, so
CI and default runs stay offline and dependency-light. The fake-reader unit
tests in test_geoip.py cover the extraction logic unconditionally.
"""
import os
from pathlib import Path

import pytest

from aetheris.network import geoip


def _find_db() -> str | None:
    env = os.environ.get("AETHERIS_GEOIP_DB")
    if env and os.path.isfile(env):
        return env
    fixtures = Path(__file__).resolve().parent / "fixtures"
    for name in ("GeoLite2-City-Test.mmdb", "GeoLite2-City.mmdb",
                 "GeoLite2-Country.mmdb"):
        p = fixtures / name
        if p.is_file():
            return str(p)
    return None


_DB = _find_db()
try:
    import geoip2  # noqa: F401
    _HAS_GEOIP2 = True
except Exception:
    _HAS_GEOIP2 = False

pytestmark = pytest.mark.skipif(
    _DB is None or not _HAS_GEOIP2,
    reason="no GeoLite2 .mmdb or geoip2 not installed")


def _resolver_for(db: str) -> geoip.GeoIPResolver:
    prev = os.environ.get("AETHERIS_GEOIP_DB")
    os.environ["AETHERIS_GEOIP_DB"] = db
    try:
        geoip._resolver = None
        r = geoip.GeoIPResolver()
    finally:
        if prev is None:
            os.environ.pop("AETHERIS_GEOIP_DB", None)
        else:
            os.environ["AETHERIS_GEOIP_DB"] = prev
    return r


def test_real_lookup_returns_a_location():
    r = _resolver_for(_DB)
    assert r.available, r.status
    loc = r.lookup("81.2.69.160")
    assert isinstance(loc.country, str)
    assert isinstance(r.lookup_str("81.2.69.160"), str)


def test_maxmind_test_db_known_ip():
    # These IPs are fixed fixtures in MaxMind's GeoLite2-City-Test.mmdb.
    if "Test" not in os.path.basename(_DB):
        pytest.skip("not the MaxMind test database")
    r = _resolver_for(_DB)
    loc = r.lookup("81.2.69.160")
    assert loc.country == "GB" and loc.city == "London"
    assert loc.as_str() == "GB · London"
