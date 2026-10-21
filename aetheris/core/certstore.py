"""
Trusted-certificate audit: what your machine trusts, and what's new.

A classic way to break TLS on a machine you've compromised is to drop your own
CA into the Trusted Root store -- after that the OS and most browsers accept
forged certificates for any site without a warning. Almost no consumer tool
surfaces that. This module reads the machine and user Root and Intermediate
stores and flags what's worth a human look:

* a root that is **new** since the last saved snapshot (the real tell);
* an **expired** or not-yet-valid certificate still sitting in a trust store;
* a root whose subject does not look like a recognised public CA (heuristic,
  informational -- a flag to review, never a verdict).

Parsing, the anomaly flags and the snapshot diff are pure and tested;
:func:`collect` is the impure part that reads the live stores (PowerShell),
and returns [] off Windows.
"""
from __future__ import annotations

import json
import os
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path

# Flags surfaced per cert.
F_NEW, F_EXPIRED, F_FUTURE, F_UNCOMMON = "new", "expired", "not-yet-valid", "uncommon-root"

#: Substrings of well-known public-CA org names. Presence is reassuring;
#: absence only means "review", since private/enterprise roots are legitimate.
_KNOWN_CA_HINTS = (
    "microsoft", "digicert", "verisign", "globalsign", "sectigo", "comodo",
    "entrust", "go daddy", "godaddy", "google trust", "amazon", "certum",
    "baltimore", "thawte", "geotrust", "usertrust", "isrg", "let's encrypt",
    "lets encrypt", "ssl.com", "quovadis", "buypass", "starfield", "actalis",
    "t-systems", "swisssign", "identrust", "symantec", "rsa security",
)


@dataclass(frozen=True)
class Certificate:
    subject: str
    issuer: str
    thumbprint: str
    not_before: float          # epoch seconds
    not_after: float
    store: str                 # "LocalMachine\\Root", "CurrentUser\\CA", …

    @property
    def is_root(self) -> bool:
        return self.store.endswith("\\Root")

    @property
    def common_name(self) -> str:
        return _cn(self.subject) or self.subject

    def expired(self, now: float) -> bool:
        return bool(self.not_after) and now > self.not_after

    def not_yet_valid(self, now: float) -> bool:
        return bool(self.not_before) and now < self.not_before


def _cn(dn: str) -> str:
    for part in dn.split(","):
        part = part.strip()
        if part.upper().startswith("CN="):
            return part[3:].strip()
    return ""


def looks_like_known_ca(cert: Certificate) -> bool:
    hay = (cert.subject + " " + cert.issuer).lower()
    return any(h in hay for h in _KNOWN_CA_HINTS)


def flags(cert: Certificate, now: float, known_thumbprints: set[str] | None = None) -> list[str]:
    """Review flags for one cert. ``known_thumbprints`` is the saved snapshot;
    None means no snapshot, so nothing is flagged 'new'."""
    out: list[str] = []
    if known_thumbprints is not None and cert.thumbprint not in known_thumbprints:
        out.append(F_NEW)
    if cert.expired(now):
        out.append(F_EXPIRED)
    if cert.not_yet_valid(now):
        out.append(F_FUTURE)
    if cert.is_root and not looks_like_known_ca(cert):
        out.append(F_UNCOMMON)
    return out


# --- snapshot persistence --------------------------------------------------


def default_path() -> Path:
    from .settings import config_dir
    return config_dir() / "cert-snapshot.json"


def save(certs: Iterable[Certificate], path: str | os.PathLike[str] | None = None) -> None:
    p = Path(path) if path else default_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps([asdict(c) for c in certs], indent=2), encoding="utf-8")
    os.replace(tmp, p)


def load_thumbprints(path: str | os.PathLike[str] | None = None) -> set[str] | None:
    """Thumbprints from the saved snapshot, or None if there is none."""
    p = Path(path) if path else default_path()
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return {str(r["thumbprint"]) for r in raw if isinstance(r, dict) and r.get("thumbprint")}


# --- report ----------------------------------------------------------------


@dataclass
class CertReport:
    certs: list[Certificate] = field(default_factory=list)
    flags: dict[str, list[str]] = field(default_factory=dict)   # thumbprint -> flags
    ts: float = 0.0

    def flagged(self) -> list[Certificate]:
        order = {F_NEW: 0, F_UNCOMMON: 1, F_EXPIRED: 2, F_FUTURE: 3}
        out = [c for c in self.certs if self.flags.get(c.thumbprint)]
        return sorted(out, key=lambda c: min(
            (order.get(f, 9) for f in self.flags.get(c.thumbprint, [])), default=9))


def build_report(certs: list[Certificate], known: set[str] | None,
                 now: float | None = None) -> CertReport:
    now = time.time() if now is None else now
    report = CertReport(certs=certs, ts=now)
    for c in certs:
        f = flags(c, now, known)
        if f:
            report.flags[c.thumbprint] = f
    return report


# --- impure collection -----------------------------------------------------

_STORES = (r"LocalMachine\Root", r"LocalMachine\CA",
           r"CurrentUser\Root", r"CurrentUser\CA")


def collect() -> list[Certificate]:
    """Read the machine + user Root and Intermediate stores. [] off Windows."""
    import subprocess
    import sys
    if sys.platform != "win32":
        return []
    out: list[Certificate] = []
    for store in _STORES:
        ps = (f"Get-ChildItem -Path Cert:\\{store} -ErrorAction SilentlyContinue | "
              "ForEach-Object { [pscustomobject]@{ s=$_.Subject; i=$_.Issuer; "
              "t=$_.Thumbprint; nb=$_.NotBefore.ToFileTimeUtc(); "
              "na=$_.NotAfter.ToFileTimeUtc() } } | ConvertTo-Json -Compress")
        try:
            res = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                                capture_output=True, text=True, timeout=30,
                                creationflags=0x08000000)
        except Exception:  # noqa: BLE001
            continue
        out.extend(parse_powershell(res.stdout, store))
    # De-dup by (thumbprint, store): a store can't list the same cert twice, but
    # guard anyway so flags map cleanly.
    seen: set[tuple[str, str]] = set()
    uniq: list[Certificate] = []
    for c in out:
        k = (c.thumbprint, c.store)
        if k not in seen:
            seen.add(k)
            uniq.append(c)
    return uniq


def parse_powershell(stdout: str, store: str) -> list[Certificate]:
    """Parse ConvertTo-Json output (object, array, or empty) into certs.

    FILETIME (100-ns ticks since 1601) is converted to epoch seconds.
    """
    text = stdout.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        return []
    rows = data if isinstance(data, list) else [data]
    out: list[Certificate] = []
    for r in rows:
        if not isinstance(r, dict) or not r.get("t"):
            continue
        out.append(Certificate(
            subject=str(r.get("s", "")), issuer=str(r.get("i", "")),
            thumbprint=str(r["t"]).upper(),
            not_before=_filetime(r.get("nb")), not_after=_filetime(r.get("na")),
            store=store))
    return out


def _filetime(ticks: object) -> float:
    if not isinstance(ticks, (int, float, str)):
        return 0.0
    try:
        t = int(ticks)
    except (TypeError, ValueError):
        return 0.0
    if t <= 0:
        return 0.0
    # FILETIME epoch is 1601-01-01; 11644473600 s to the Unix epoch.
    return t / 1e7 - 11644473600.0
