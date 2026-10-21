"""
System health: a plain "is my PC okay" readout.

The scoring layer is pure -- each ``score_*`` function turns a raw number
(disk fullness, memory pressure, battery wear, uptime, temperature) into a
:class:`Metric` with a status, a human value and a recommendation -- so the
thresholds are unit-tested without touching a machine. :func:`collect` is the
impure part: it reads the system with psutil (plus a little ctypes on Windows)
and is defensive everywhere, because health data is exactly where psutil raises
on locked-down or headless machines. A metric it cannot read becomes
``unknown`` rather than a crash or a false alarm.

Nothing here changes the system; it only reports.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

OK, WARN, CRITICAL, UNKNOWN = "ok", "warn", "critical", "unknown"

#: Status ranking, worst first -- for the overall roll-up.
_RANK = {CRITICAL: 3, WARN: 2, UNKNOWN: 1, OK: 0}

_GB = 1024 ** 3


@dataclass
class Metric:
    key: str
    label: str
    status: str
    value: str = ""
    detail: str = ""
    recommendation: str = ""


@dataclass
class HealthReport:
    metrics: list[Metric] = field(default_factory=list)
    ts: float = 0.0

    @property
    def overall(self) -> str:
        if not self.metrics:
            return UNKNOWN
        return max((m.status for m in self.metrics), key=lambda s: _RANK[s])

    @property
    def score(self) -> int:
        """0-100, the share of checks that are OK, with WARN as half credit and
        unknowns not counted against the machine."""
        graded = [m for m in self.metrics if m.status != UNKNOWN]
        if not graded:
            return 0
        pts = sum(1.0 if m.status == OK else 0.5 if m.status == WARN else 0.0
                  for m in graded)
        return round(100 * pts / len(graded))

    def worst_first(self) -> list[Metric]:
        return sorted(self.metrics, key=lambda m: _RANK[m.status], reverse=True)


# --- pure scoring ----------------------------------------------------------


def score_disk(mount: str, used_pct: float, free_bytes: int) -> Metric:
    gb = free_bytes / _GB
    value = f"{used_pct:.0f}% used, {gb:.1f} GB free"
    if used_pct >= 95 or gb < 2:
        return Metric("disk:" + mount, f"Disk {mount}", CRITICAL, value,
                      recommendation="Free up space now — this little room hurts "
                                     "performance and can block updates.")
    if used_pct >= 85 or gb < 10:
        return Metric("disk:" + mount, f"Disk {mount}", WARN, value,
                      recommendation="Getting full; clear some space soon.")
    return Metric("disk:" + mount, f"Disk {mount}", OK, value)


def score_memory(used_pct: float, avail_bytes: int, swap_pct: float) -> Metric:
    value = f"{used_pct:.0f}% used, {avail_bytes / _GB:.1f} GB free"
    if used_pct >= 92:
        return Metric("memory", "Memory", CRITICAL, value,
                      detail=f"swap {swap_pct:.0f}% used",
                      recommendation="Memory is nearly full; close heavy apps or "
                                     "browser tabs, or add RAM.")
    if used_pct >= 80:
        return Metric("memory", "Memory", WARN, value,
                      detail=f"swap {swap_pct:.0f}% used")
    return Metric("memory", "Memory", OK, value)


def score_battery(percent: float, plugged: bool, wear_pct: float | None) -> Metric:
    bits = [f"{percent:.0f}%", "plugged in" if plugged else "on battery"]
    if wear_pct is not None:
        bits.append(f"{wear_pct:.0f}% worn")
    value = ", ".join(bits)
    if wear_pct is not None and wear_pct >= 40:
        return Metric("battery", "Battery", WARN, value,
                      recommendation="Battery has lost a lot of its original "
                                     "capacity; a replacement would help runtime.")
    return Metric("battery", "Battery", OK, value)


def score_uptime(seconds: float) -> Metric:
    days = seconds / 86400
    value = _dur(seconds)
    if days >= 14:
        return Metric("uptime", "Uptime", WARN, value,
                      recommendation="Up for a while; a reboot clears leaks and "
                                     "finishes pending updates.")
    return Metric("uptime", "Uptime", OK, value)


def score_temperature(celsius: float, label: str = "CPU") -> Metric:
    value = f"{celsius:.0f} °C"
    if celsius >= 90:
        return Metric("temp", f"{label} temperature", CRITICAL, value,
                      recommendation="Running hot; check fans and vents for dust.")
    if celsius >= 80:
        return Metric("temp", f"{label} temperature", WARN, value)
    return Metric("temp", f"{label} temperature", OK, value)


def _dur(seconds: float) -> str:
    s = int(seconds)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m = s // 60
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h {m}m"
    return f"{m}m"


# --- impure collection -----------------------------------------------------


def collect() -> HealthReport:
    """Read current health. Each probe is independently guarded: one that the
    OS refuses becomes an ``unknown`` metric, never an exception."""
    import psutil

    report = HealthReport(ts=time.time())
    m = report.metrics

    m.extend(_disks(psutil))
    m.append(_memory(psutil))
    bat = _battery(psutil)
    if bat is not None:
        m.append(bat)
    m.append(_uptime(psutil))
    temp = _temperature(psutil)
    if temp is not None:
        m.append(temp)
    return report


def _unknown(key: str, label: str, why: str) -> Metric:
    return Metric(key, label, UNKNOWN, detail=why)


def _disks(psutil: Any) -> list[Metric]:
    out: list[Metric] = []
    try:
        parts = psutil.disk_partitions(all=False)
    except Exception as exc:  # noqa: BLE001
        return [_unknown("disk", "Disks", str(exc))]
    for part in parts:
        # Skip removable media and optical drives: a CD reads as 100% full.
        if "cdrom" in part.opts or part.fstype == "":
            continue
        try:
            u = psutil.disk_usage(part.mountpoint)
        except (OSError, PermissionError):
            continue
        out.append(score_disk(part.mountpoint, u.percent, u.free))
    return out or [_unknown("disk", "Disks", "no fixed drives found")]


def _memory(psutil: Any) -> Metric:
    try:
        vm = psutil.virtual_memory()
        try:
            swap = psutil.swap_memory().percent
        except Exception:  # noqa: BLE001
            swap = 0.0
        return score_memory(vm.percent, vm.available, swap)
    except Exception as exc:  # noqa: BLE001
        return _unknown("memory", "Memory", str(exc))


def _battery(psutil: Any) -> Metric | None:
    try:
        b = psutil.sensors_battery()
    except Exception:  # noqa: BLE001
        b = None
    if b is None:
        return None  # desktop / no battery
    return score_battery(b.percent, b.power_plugged, _battery_wear())


def _battery_wear() -> float | None:
    """Windows battery wear = 1 - full-charge / design capacity, via WMI.
    None anywhere it can't be read (and on non-Windows)."""
    import sys
    if sys.platform != "win32":
        return None
    try:
        import subprocess
        # BatteryStaticData/FullChargedCapacity live in root\WMI.
        ps = ("$d=(Get-CimInstance -Namespace root/WMI -ClassName "
              "BatteryStaticData -ErrorAction Stop).DesignedCapacity; "
              "$f=(Get-CimInstance -Namespace root/WMI -ClassName "
              "BatteryFullChargedCapacity -ErrorAction Stop).FullChargedCapacity; "
              "if($d){[math]::Round((1-$f/$d)*100,1)}")
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                             capture_output=True, text=True, timeout=10,
                             creationflags=0x08000000)  # CREATE_NO_WINDOW
        val = out.stdout.strip().splitlines()
        return float(val[0]) if val and val[0] else None
    except Exception:  # noqa: BLE001
        return None


def _uptime(psutil: Any) -> Metric:
    try:
        return score_uptime(time.time() - psutil.boot_time())
    except Exception as exc:  # noqa: BLE001
        return _unknown("uptime", "Uptime", str(exc))


def _temperature(psutil: Any) -> Metric | None:
    """Hottest core reading psutil exposes. Absent on most Windows setups
    (no sensor API), so this simply contributes nothing there."""
    try:
        temps = psutil.sensors_temperatures()
    except Exception:  # noqa: BLE001
        return None
    readings = [t.current for group in (temps or {}).values()
                for t in group if getattr(t, "current", None)]
    if not readings:
        return None
    return score_temperature(max(readings))
