"""
Mark-of-the-Web: where a file came from.

When a browser, mail client or archiver saves a file from the internet,
Windows attaches a ``Zone.Identifier`` alternate data stream to it::

    [ZoneTransfer]
    ZoneId=3
    ReferrerUrl=https://example.com/download-page
    HostUrl=https://cdn.example.com/files/upd.exe

That stream is the single best answer to "how did this binary get here", and
almost no triage tool shows it. It is evidence, not proof -- any program can
strip or forge it -- so it is reported as a provenance hint and feeds the
attack storyline, never a verdict on its own.

The parser is pure; :func:`read` is the only part that touches the disk and it
returns None anywhere ADS are unavailable (non-NTFS, non-Windows, no stream).
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from urllib.parse import urlsplit

#: URLZONE_* values from urlmon.h.
ZONES = {0: "local machine", 1: "intranet", 2: "trusted sites",
         3: "internet", 4: "restricted sites"}

#: Upper bound on what we read: the stream is a few hundred bytes, and a huge
#: one is either corrupt or hostile.
_MAX_STREAM = 64 * 1024


@dataclass(frozen=True)
class Origin:
    zone_id: int | None = None
    host_url: str = ""
    referrer_url: str = ""
    app_zone_id: int | None = None   # set by some apps (e.g. Office) on extraction

    @property
    def zone(self) -> str:
        if self.zone_id is None:
            return "unknown"
        return ZONES.get(self.zone_id, f"zone {self.zone_id}")

    @property
    def from_internet(self) -> bool:
        return self.zone_id is not None and self.zone_id >= 3

    @property
    def host(self) -> str:
        """Domain the file was fetched from (falls back to the referrer)."""
        for url in (self.host_url, self.referrer_url):
            if url and not url.lower().startswith(("about:", "blob:", "data:")):
                netloc = urlsplit(url).hostname
                if netloc:
                    return netloc
        return ""

    def describe(self) -> str:
        parts = [f"downloaded from the {self.zone} zone"]
        if self.host_url:
            parts.append(f"via {_short(self.host_url)}")
        if self.referrer_url and self.referrer_url != self.host_url:
            parts.append(f"(linked from {_short(self.referrer_url)})")
        return " ".join(parts)


def _short(url: str, limit: int = 90) -> str:
    return url if len(url) <= limit else url[: limit - 1] + "…"


def _int(v: str) -> int | None:
    try:
        return int(v.strip())
    except ValueError:
        return None


def parse(text: str) -> Origin | None:
    """Parse a Zone.Identifier stream. None when it has no ZoneTransfer data.

    Deliberately not configparser: real streams contain URLs with ``%`` and
    ``;``, duplicate keys and junk lines, all of which it chokes on.
    """
    in_section = False
    fields: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip().lstrip("﻿")
        if not line:
            continue
        if line.startswith("["):
            in_section = line.lower() == "[zonetransfer]"
            continue
        if in_section and "=" in line:
            k, v = line.split("=", 1)
            fields.setdefault(k.strip().lower(), v.strip())
    if not fields:
        return None
    return Origin(zone_id=_int(fields.get("zoneid", "")),
                  host_url=fields.get("hosturl", ""),
                  referrer_url=fields.get("referrerurl", ""),
                  app_zone_id=_int(fields.get("appzoneid", "")))


def read(path: str) -> Origin | None:
    """Read and parse ``path``'s Zone.Identifier stream, or None if absent."""
    if not path or sys.platform != "win32":
        return None
    try:
        with open(path + ":Zone.Identifier", "rb") as fh:
            raw = fh.read(_MAX_STREAM)
    except OSError:
        return None
    for enc in ("utf-8-sig", "utf-16", "latin-1"):
        try:
            return parse(raw.decode(enc))
        except UnicodeDecodeError:
            continue
    return None
