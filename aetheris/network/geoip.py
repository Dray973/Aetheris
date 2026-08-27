"""
Offline IP geolocation (Module 3: "resolve geolocation data").

Uses the optional ``geoip2`` library against a local MaxMind GeoLite2 database.
No network calls are ever made — lookups hit a memory-mapped ``.mmdb`` file, so
this stays fast and private. Both the library and the database are optional: if
either is missing the resolver reports ``available = False`` and the UI shows
why, exactly like the other optional engines.

Database discovery order:
  1. $AETHERIS_GEOIP_DB (explicit path)
  2. a ``data/`` folder next to the installed package
  3. the current working directory
Looks for GeoLite2-City.mmdb first (city + coords), then GeoLite2-Country.mmdb.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from ..core import logbus

SRC = "network.geoip"

_CITY_NAMES = ("GeoLite2-City.mmdb",)
_COUNTRY_NAMES = ("GeoLite2-Country.mmdb",)


@dataclass
class GeoLocation:
    country: str = ""     # ISO code, e.g. "US"
    city: str = ""
    lat: float | None = None
    lon: float | None = None

    def as_str(self) -> str:
        return format_location(self.country, self.city)


def format_location(country: str, city: str) -> str:
    """Compact one-line label, safe for empty parts (pure; unit-tested)."""
    if country and city:
        return f"{country} · {city}"
    return country or city or ""


def _discover_db() -> tuple[str | None, bool]:
    """Return (db_path, is_city_db) or (None, False)."""
    roots = []
    env = os.environ.get("AETHERIS_GEOIP_DB")
    if env:
        # Explicit path may point straight at a file.
        if os.path.isfile(env):
            return env, "city" in os.path.basename(env).lower()
        roots.append(Path(env))
    roots.append(Path(__file__).resolve().parent.parent / "data")
    roots.append(Path.cwd())
    for root in roots:
        for name in _CITY_NAMES:
            p = root / name
            if p.is_file():
                return str(p), True
        for name in _COUNTRY_NAMES:
            p = root / name
            if p.is_file():
                return str(p), False
    return None, False


class GeoIPResolver:
    def __init__(self) -> None:
        self.available = False
        self.status = "not initialized"
        self._reader = None
        self._is_city = False
        self._cache: dict[str, GeoLocation] = {}
        self._init()

    def _init(self) -> None:
        try:
            import geoip2.database  # type: ignore
        except Exception:
            self.status = "geoip2 not installed (pip install geoip2)"
            logbus.trace(SRC, self.status)
            return
        db, is_city = _discover_db()
        if not db:
            self.status = ("no GeoLite2 .mmdb found (set $AETHERIS_GEOIP_DB or "
                           "drop one in aetheris/data/)")
            logbus.trace(SRC, self.status)
            return
        try:
            self._reader = geoip2.database.Reader(db)
            self._is_city = is_city
            self.available = True
            self.status = f"GeoLite2 loaded: {os.path.basename(db)}"
            logbus.success(SRC, self.status)
        except Exception as exc:  # noqa: BLE001
            self.status = f"failed to open {db}: {exc}"
            logbus.warn(SRC, self.status)

    def lookup(self, ip: str) -> GeoLocation:
        if not self.available or not ip:
            return GeoLocation()
        if ip in self._cache:
            return self._cache[ip]
        loc = GeoLocation()
        try:
            if self._is_city:
                r = self._reader.city(ip)
                loc = GeoLocation(
                    country=r.country.iso_code or "",
                    city=r.city.name or "",
                    lat=r.location.latitude, lon=r.location.longitude)
            else:
                r = self._reader.country(ip)
                loc = GeoLocation(country=r.country.iso_code or "")
        except Exception:
            loc = GeoLocation()   # address not in DB / private / invalid
        self._cache[ip] = loc
        return loc

    def lookup_str(self, ip: str) -> str:
        return self.lookup(ip).as_str()

    def close(self) -> None:
        if self._reader is not None:
            try:
                self._reader.close()
            except Exception:
                pass


_resolver: GeoIPResolver | None = None


def get_resolver() -> GeoIPResolver:
    """Process-wide singleton (the .mmdb is opened once)."""
    global _resolver
    if _resolver is None:
        _resolver = GeoIPResolver()
    return _resolver
