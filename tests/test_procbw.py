"""Per-process bandwidth attribution math (pure; no elevation/traffic needed)."""
from aetheris.network.procbw import aggregate


def test_aggregate_basic_rates():
    prev = {("1.1.1.1", 5, "2.2.2.2", 80): (1000, 2000)}
    cur = {("1.1.1.1", 5, "2.2.2.2", 80): (1500, 5000)}
    owners = {("1.1.1.1", 5, "2.2.2.2", 80): 42}
    res = aggregate(prev, cur, owners, dt=2.0)
    assert res[42] == (250.0, 1500.0)   # (1500-1000)/2, (5000-2000)/2


def test_aggregate_sums_multiple_connections_per_pid():
    k1 = ("a", 1, "b", 2)
    k2 = ("a", 3, "c", 4)
    prev = {k1: (0, 0), k2: (0, 0)}
    cur = {k1: (100, 10), k2: (300, 90)}
    owners = {k1: 7, k2: 7}
    res = aggregate(prev, cur, owners, dt=1.0)
    assert res[7] == (400.0, 100.0)


def test_aggregate_clamps_counter_rollback():
    k = ("a", 1, "b", 2)
    res = aggregate({k: (500, 500)}, {k: (100, 100)}, {k: 9}, dt=1.0)
    assert res[9] == (0.0, 0.0)         # negative delta clamped to zero


def test_aggregate_skips_unowned_connections():
    k = ("a", 1, "b", 2)
    res = aggregate({k: (0, 0)}, {k: (50, 50)}, owners={}, dt=1.0)
    assert res == {}
