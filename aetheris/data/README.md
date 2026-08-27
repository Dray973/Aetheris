# GeoIP database drop-in

The network interceptor geolocates public remote IPs offline using a MaxMind
**GeoLite2** database. No database ships with the app (MaxMind's license
requires you to download it yourself), and geolocation degrades gracefully when
it's absent — the Network tab shows the reason in its status line.

To enable it (one command, with a free MaxMind license key):

```powershell
pip install geoip2                                   # in the `recommended` extra
python docs/fetch_geoip.py --license-key YOUR_KEY     # installs the .mmdb here
```

Get a free key at <https://www.maxmind.com/en/geolite2/signup>. Prefer to do it
by hand? Download **GeoLite2-City.mmdb** (city + coords) or
**GeoLite2-Country.mmdb** (country only), drop it in this folder, **or** point
`AETHERIS_GEOIP_DB` at its full path.

Discovery order: `$AETHERIS_GEOIP_DB` → `aetheris/data/` → current directory.
GeoLite2-City is preferred over GeoLite2-Country when both are present.
