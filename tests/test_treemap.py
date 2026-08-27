"""Squarified treemap layout: exact area coverage and in-bounds rectangles."""
from aetheris.ui.treemap import squarify


def test_squarify_covers_full_rectangle():
    items = [(f"n{i}", v) for i, v in enumerate([50, 30, 15, 5, 3, 2])]
    placed = squarify(items, 0, 0, 400, 300)
    assert len(placed) == 6
    area = sum(rw * rh for _n, (rx, ry, rw, rh) in placed)
    assert abs(area - 400 * 300) < 1.0


def test_squarify_rectangles_stay_in_bounds():
    placed = squarify([("a", 10), ("b", 20), ("c", 70)], 0, 0, 200, 100)
    for _n, (rx, ry, rw, rh) in placed:
        assert rx >= -1e-3 and ry >= -1e-3
        assert rx + rw <= 200 + 1e-3
        assert ry + rh <= 100 + 1e-3


def test_squarify_proportional_to_value():
    placed = dict((n, rw * rh) for n, (rx, ry, rw, rh)
                  in squarify([("big", 90), ("small", 10)], 0, 0, 100, 100))
    # Areas should track the 9:1 value ratio.
    assert placed["big"] > placed["small"] * 5
