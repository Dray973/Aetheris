#!/usr/bin/env python3
"""
Fetch a MaxMind GeoLite2 database to enable city-level GeoIP.

MaxMind requires a free account + license key (the data can't be redistributed
with the app). This downloads GeoLite2-City for you and drops the .mmdb into
aetheris/data/, where the app discovers it automatically.

    # 1) sign up (free): https://www.maxmind.com/en/geolite2/signup
    # 2) create a license key in your account
    python docs/fetch_geoip.py --license-key YOUR_KEY
    #    or:  set MAXMIND_LICENSE_KEY=YOUR_KEY  &&  python docs/fetch_geoip.py

Use --edition GeoLite2-Country for the smaller country-only DB.
"""
from __future__ import annotations

import io
import os
import sys
import argparse
import tarfile
import urllib.request
from pathlib import Path

DEST_DIR = Path(__file__).resolve().parent.parent / "aetheris" / "data"
ENDPOINT = ("https://download.maxmind.com/app/geoip_download"
            "?edition_id={edition}&license_key={key}&suffix=tar.gz")


def main() -> int:
    ap = argparse.ArgumentParser(description="Download a GeoLite2 .mmdb")
    ap.add_argument("--license-key", default=os.environ.get("MAXMIND_LICENSE_KEY"))
    ap.add_argument("--edition", default="GeoLite2-City",
                    choices=["GeoLite2-City", "GeoLite2-Country"])
    args = ap.parse_args()

    if not args.license_key:
        print("No MaxMind license key provided.\n")
        print("  1) Sign up (free): https://www.maxmind.com/en/geolite2/signup")
        print("  2) Create a license key in your MaxMind account")
        print("  3) Re-run:  python docs/fetch_geoip.py --license-key YOUR_KEY")
        print("     (or set the MAXMIND_LICENSE_KEY environment variable)")
        return 2

    url = ENDPOINT.format(edition=args.edition, key=args.license_key)
    print(f"Downloading {args.edition}…")
    try:
        with urllib.request.urlopen(url, timeout=120) as resp:
            blob = resp.read()
    except Exception as exc:  # noqa: BLE001
        print(f"Download failed: {exc}")
        print("Check the license key and your network connection.")
        return 1

    # The archive contains <edition>_<date>/<edition>.mmdb — extract just that.
    member_name = f"{args.edition}.mmdb"
    try:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
            match = next((m for m in tar.getmembers()
                          if m.name.endswith(member_name)), None)
            if match is None:
                print(f"Archive did not contain {member_name}.")
                return 1
            fh = tar.extractfile(match)
            data = fh.read() if fh else b""
    except tarfile.TarError as exc:
        print(f"Extraction failed: {exc}")
        return 1

    DEST_DIR.mkdir(parents=True, exist_ok=True)
    out = DEST_DIR / member_name
    out.write_bytes(data)
    print(f"Installed {out} ({len(data) // 1024} KB).")
    print("GeoIP is now enabled — restart the app (or the Network tab) to use it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
