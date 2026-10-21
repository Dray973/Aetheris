"""
Startup impact: what runs at boot, and how much each one costs.

Two sources, merged:

* **what starts** -- Run/RunOnce keys + Startup folders (``autoruns``) and
  auto/boot-start services (``services``);
* **what it costs** -- Windows' own boot-performance diagnostics. After every
  boot the OS writes events to *Microsoft-Windows-Diagnostics-Performance/
  Operational*: event 100 is the boot summary, and 101/102/103 name the apps,
  drivers and services that *degraded* boot, each with the milliseconds it
  added. This is the same measurement Task Manager's "Startup impact" column
  and the old Soluto were built on -- real numbers, not a guess.

The XML parsing and the merge/ranking are pure and tested; :func:`collect`
is the impure part that shells out to ``Get-WinEvent``. Everywhere the log is
unavailable (not elevated, non-Windows, logging disabled) the tab still lists
what starts, just without timings. Read-only.
"""
from __future__ import annotations

import ntpath
from dataclasses import dataclass, field
from xml.etree import ElementTree as ET

HIGH, MEDIUM, LOW, NONE = "high", "medium", "low", "none"

#: Boot-degradation thresholds (ms) -> impact band. Task Manager uses a
#: comparable split; these are deliberately round and documented so the tab's
#: labels are explainable rather than magic.
_HIGH_MS = 3000
_MED_MS = 1000

# Diagnostics-Performance event ids that carry a per-item boot cost.
_DEGRADATION_IDS = {101: "app", 102: "driver", 103: "service", 107: "service"}


@dataclass
class BootCost:
    name: str
    kind: str          # app / driver / service
    total_ms: int


@dataclass
class StartupItem:
    name: str
    command: str
    kind: str          # app / service / driver
    source: str        # where it is registered (Run key, Startup folder, SCM…)
    enabled: bool = True
    impact_ms: int | None = None   # None = no measurement available

    @property
    def impact(self) -> str:
        if self.impact_ms is None:
            return NONE
        if self.impact_ms >= _HIGH_MS:
            return HIGH
        if self.impact_ms >= _MED_MS:
            return MEDIUM
        return LOW


@dataclass
class StartupReport:
    items: list[StartupItem] = field(default_factory=list)
    last_boot_ms: int | None = None   # total boot time from event 100
    measured: bool = False            # did we get any timings?

    def ranked(self) -> list[StartupItem]:
        """Most expensive first; unmeasured items after measured ones."""
        return sorted(self.items,
                      key=lambda i: (i.impact_ms is not None, i.impact_ms or 0),
                      reverse=True)


# --- pure: parse the boot-performance log ----------------------------------


def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_boot_events(xml_events: list[str]) -> tuple[list[BootCost], int | None]:
    """Parse Get-WinEvent XML records into per-item boot costs.

    Returns ``(costs, boot_total_ms)``. Each Diagnostics-Performance event
    stores its fields in ``<EventData><Data Name="...">value</Data>``; the
    degradation events carry ``Name`` and a time field (``TotalTime`` /
    ``DegradationTime`` depending on the id). Unparseable records are skipped,
    not fatal -- the log mixes schemas across Windows versions.
    """
    costs: list[BootCost] = []
    boot_total: int | None = None
    for raw in xml_events:
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            continue
        eid = 0
        data: dict[str, str] = {}
        for el in root.iter():
            tag = _localname(el.tag)
            if tag == "EventID" and el.text and el.text.isdigit():
                eid = int(el.text)
            elif tag == "Data":
                name = el.attrib.get("Name", "")
                if name:
                    data[name] = (el.text or "").strip()
        if eid == 100:
            boot_total = _int(data.get("BootTime")) or boot_total
        elif eid in _DEGRADATION_IDS:
            name = data.get("Name") or data.get("FriendlyName") or ""
            ms = (_int(data.get("TotalTime")) or _int(data.get("DegradationTime"))
                  or _int(data.get("Time")))
            if name and ms:
                costs.append(BootCost(name.strip(), _DEGRADATION_IDS[eid], ms))
    return costs, boot_total


def _int(v: str | None) -> int | None:
    try:
        return int(v) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None


# --- pure: merge what-starts with what-it-costs ----------------------------


def _match_key(text: str) -> str:
    """Normalise an item/cost name to its executable basename for matching."""
    text = (text or "").strip().strip('"')
    base = ntpath.basename(text) if ("\\" in text or "/" in text) else text
    return base.lower()


def merge(items: list[StartupItem], costs: list[BootCost]) -> StartupReport:
    """Attach each boot cost to the startup item it names (summing repeats)."""
    by_key: dict[str, int] = {}
    for c in costs:
        k = _match_key(c.name)
        by_key[k] = by_key.get(k, 0) + c.total_ms
    for item in items:
        for cand in (_match_key(item.name), _match_key(item.command)):
            if cand in by_key:
                item.impact_ms = by_key[cand]
                break
    return StartupReport(items=items, measured=bool(costs))


# --- impure: collect -------------------------------------------------------


def _items_from_autoruns_services() -> list[StartupItem]:
    from . import autoruns, services
    out: list[StartupItem] = []
    try:
        for e in autoruns.enumerate_entries():
            out.append(StartupItem(e.name, e.command, "app", e.location, e.enabled))
    except Exception:  # noqa: BLE001
        pass
    try:
        for s in services.enumerate_services(check_signature=False):
            if s.start_type in ("auto", "boot", "system"):
                out.append(StartupItem(s.display_name or s.name, s.binary, "service",
                                       f"service ({s.start_type})",
                                       s.state == "running"))
    except Exception:  # noqa: BLE001
        pass
    return out


def _boot_costs() -> tuple[list[BootCost], int | None]:
    import subprocess
    import sys
    if sys.platform != "win32":
        return [], None
    ps = ("Get-WinEvent -FilterHashtable @{LogName="
          "'Microsoft-Windows-Diagnostics-Performance/Operational'; Id=100,101,102,103,107} "
          "-MaxEvents 200 -ErrorAction Stop | ForEach-Object { $_.ToXml() }")
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                             capture_output=True, text=True, timeout=30,
                             creationflags=0x08000000)  # CREATE_NO_WINDOW
    except Exception:  # noqa: BLE001
        return [], None
    # Each record is one <Event>…</Event>; ToXml() emits them back to back.
    chunks = [c + "</Event>" for c in out.stdout.split("</Event>") if "<Event" in c]
    return parse_boot_events(chunks)


def collect() -> StartupReport:
    """What runs at boot, ranked by measured impact where the log provides it."""
    items = _items_from_autoruns_services()
    costs, boot_total = _boot_costs()
    report = merge(items, costs)
    report.last_boot_ms = boot_total
    return report
