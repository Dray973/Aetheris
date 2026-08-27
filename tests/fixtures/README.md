# Test fixtures

## GeoIP end-to-end test

`test_geoip_live.py` runs a real lookup against a GeoLite2 database when one is
available, and **skips** otherwise (so the default suite and CI stay offline).

No `.mmdb` is committed here — MaxMind's databases are licensed (the test data is
CC-BY-SA-4.0), so we don't redistribute them. To run the live test locally, do
one of:

- **MaxMind's small test database** (fixed IPs like `81.2.69.160 → GB/London`):
  download `GeoLite2-City-Test.mmdb` from
  <https://github.com/maxmind/MaxMind-DB/tree/main/test-data> and drop it here as
  `tests/fixtures/GeoLite2-City-Test.mmdb`.
- **A real GeoLite2 database**: `python docs/fetch_geoip.py --license-key YOUR_KEY`
  (installs it into `aetheris/data/`), then run pytest with
  `AETHERIS_GEOIP_DB` pointing at it.
