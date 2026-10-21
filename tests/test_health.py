"""System-health scoring (pure) + collect() resilience + the tab."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from aetheris.core import health  # noqa: E402

GB = 1024 ** 3


# --- disk ------------------------------------------------------------------


def test_disk_thresholds():
    assert health.score_disk("C:", 50, 400 * GB).status == health.OK
    assert health.score_disk("C:", 88, 20 * GB).status == health.WARN
    assert health.score_disk("C:", 96, 50 * GB).status == health.CRITICAL
    # Low absolute free space is critical even at a modest percentage.
    assert health.score_disk("D:", 60, 1 * GB).status == health.CRITICAL
    assert "GB free" in health.score_disk("C:", 50, 400 * GB).value


# --- memory ----------------------------------------------------------------


def test_memory_thresholds():
    assert health.score_memory(40, 8 * GB, 0).status == health.OK
    assert health.score_memory(85, 1 * GB, 10).status == health.WARN
    crit = health.score_memory(95, 0, 70)
    assert crit.status == health.CRITICAL and "swap 70%" in crit.detail


# --- battery ---------------------------------------------------------------


def test_battery_wear_warns_but_charge_alone_does_not():
    assert health.score_battery(80, True, 10).status == health.OK
    assert health.score_battery(12, False, None).status == health.OK  # low charge != unhealthy
    worn = health.score_battery(100, True, 55)
    assert worn.status == health.WARN and "55% worn" in worn.value


# --- uptime / temp ---------------------------------------------------------


def test_uptime_and_duration():
    assert health.score_uptime(3600).status == health.OK
    assert health.score_uptime(20 * 86400).status == health.WARN
    assert health._dur(90000) == "1d 1h"
    assert health._dur(3700) == "1h 1m"
    assert health._dur(120) == "2m"


def test_temperature_thresholds():
    assert health.score_temperature(55).status == health.OK
    assert health.score_temperature(83).status == health.WARN
    assert health.score_temperature(95).status == health.CRITICAL


# --- report roll-up --------------------------------------------------------


def test_overall_and_score():
    r = health.HealthReport(metrics=[
        health.Metric("a", "A", health.OK),
        health.Metric("b", "B", health.WARN),
        health.Metric("c", "C", health.CRITICAL),
        health.Metric("d", "D", health.UNKNOWN),
    ])
    assert r.overall == health.CRITICAL
    # OK=1 + WARN=0.5 + CRIT=0 over 3 graded (unknown excluded) = 50.
    assert r.score == 50
    assert [m.key for m in r.worst_first()][0] == "c"


def test_empty_and_all_unknown():
    assert health.HealthReport().overall == health.UNKNOWN
    allu = health.HealthReport(metrics=[health.Metric("x", "X", health.UNKNOWN)])
    assert allu.score == 0 and allu.overall == health.UNKNOWN


def test_unknown_does_not_drag_the_score_down():
    r = health.HealthReport(metrics=[
        health.Metric("a", "A", health.OK),
        health.Metric("b", "B", health.UNKNOWN),
    ])
    assert r.score == 100  # the one graded check is OK


# --- collect() resilience --------------------------------------------------


def test_collect_survives_a_hostile_psutil(monkeypatch):
    import psutil

    def boom(*a, **k):
        raise OSError("denied")

    for name in ("disk_partitions", "virtual_memory", "boot_time"):
        monkeypatch.setattr(psutil, name, boom)
    monkeypatch.setattr(psutil, "sensors_battery", boom, raising=False)
    monkeypatch.setattr(psutil, "sensors_temperatures", boom, raising=False)
    report = health.collect()
    # Nothing raised; disk/memory/uptime degrade to unknown, no battery/temp row.
    assert {m.key for m in report.metrics} >= {"disk", "memory", "uptime"}
    assert all(m.status == health.UNKNOWN for m in report.metrics)
    assert report.overall == health.UNKNOWN


def test_collect_on_this_machine_reads_something():
    report = health.collect()
    assert report.metrics
    assert any(m.status != health.UNKNOWN for m in report.metrics)


# --- tab -------------------------------------------------------------------


def test_health_tab_populates(qtbot):
    from aetheris.ui.tabs.health_tab import HealthTab

    tab = HealthTab()
    qtbot.addWidget(tab)
    report = health.HealthReport(metrics=[
        health.Metric("disk:C:", "Disk C:", health.CRITICAL, "96% used, 1.0 GB free",
                      recommendation="Free up space now."),
        health.Metric("memory", "Memory", health.OK, "40% used"),
    ])
    tab._populate(report)
    assert tab.table.rowCount() == 2
    # Worst first: the critical disk row leads.
    assert tab.table.item(0, 1).text() == "Disk C:"
    assert "50/100" in tab.score_label.text()
    assert "1 need action" in tab.summary.text()
