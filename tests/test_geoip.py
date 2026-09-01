"""GeoIP label formatting + graceful degradation (no DB / library required)."""
import types

from aetheris.network import geoip


def test_format_location_combinations():
    assert geoip.format_location("US", "Ashburn") == "US · Ashburn"
    assert geoip.format_location("US", "") == "US"
    assert geoip.format_location("", "Berlin") == "Berlin"
    assert geoip.format_location("", "") == ""


def test_geolocation_as_str():
    assert geoip.GeoLocation(country="DE", city="Berlin").as_str() == "DE · Berlin"
    assert geoip.GeoLocation().as_str() == ""


def test_resolver_is_graceful_without_db():
    r = geoip.GeoIPResolver()
    assert isinstance(r.available, bool)
    assert r.status
    loc = r.lookup("10.0.0.1")
    assert isinstance(loc, geoip.GeoLocation)
    assert isinstance(r.lookup_str("not-an-ip"), str)


def test_get_resolver_is_singleton():
    assert geoip.get_resolver() is geoip.get_resolver()


def _resolver_with_reader(reader, is_city):
    r = geoip.GeoIPResolver.__new__(geoip.GeoIPResolver)
    r.available = True
    r.status = "test"
    r._reader = reader
    r._is_city = is_city
    r._cache = {}
    return r


def test_lookup_extracts_city_fields():
    resp = types.SimpleNamespace(
        country=types.SimpleNamespace(iso_code="US"),
        city=types.SimpleNamespace(name="Ashburn"),
        location=types.SimpleNamespace(latitude=39.0, longitude=-77.5))
    r = _resolver_with_reader(types.SimpleNamespace(city=lambda ip: resp), True)
    loc = r.lookup("1.2.3.4")
    assert (loc.country, loc.city, loc.lat, loc.lon) == ("US", "Ashburn", 39.0, -77.5)
    assert loc.as_str() == "US · Ashburn"
    assert r.lookup("1.2.3.4") is loc


def test_lookup_country_only_db():
    resp = types.SimpleNamespace(country=types.SimpleNamespace(iso_code="DE"))
    r = _resolver_with_reader(types.SimpleNamespace(country=lambda ip: resp), False)
    assert r.lookup_str("9.9.9.9") == "DE"


def test_lookup_swallows_reader_errors():
    def boom(ip):
        raise ValueError("not in DB")
    r = _resolver_with_reader(types.SimpleNamespace(city=boom), True)
    assert r.lookup_str("203.0.113.1") == ""
