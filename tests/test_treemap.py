"""Squarified treemap layout: exact area coverage and in-bounds rectangles.

The layout math lives in the Qt-free ``aetheris.ui.treemap_layout`` module, so
these pure-geometry tests import and run without PyQt6 (proved by
``test_layout_imports_with_no_qt`` below).
"""
import importlib
import sys

import pytest

from aetheris.ui.treemap_layout import squarify


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
    placed = {n: rw * rh for n, (rx, ry, rw, rh)
              in squarify([("big", 90), ("small", 10)], 0, 0, 100, 100)}
    # Areas should track the 9:1 value ratio.
    assert placed["big"] > placed["small"] * 5


class _BlockPyQt6:
    """meta_path finder that makes any PyQt6 import fail, to simulate a box
    with no Qt installed."""
    def find_spec(self, name, path=None, target=None):
        if name == "PyQt6" or name.startswith("PyQt6."):
            raise ModuleNotFoundError(f"No module named {name!r} (blocked for test)")


@pytest.fixture
def no_qt():
    finder = _BlockPyQt6()
    saved = {k: v for k, v in list(sys.modules.items())
             if k == "PyQt6" or k.startswith(("PyQt6.", "aetheris.ui"))}
    for k in saved:                      # force fresh imports through the finder
        del sys.modules[k]
    sys.meta_path.insert(0, finder)
    try:
        yield
    finally:
        sys.meta_path.remove(finder)
        for k in [k for k in sys.modules if k.startswith("aetheris.ui")]:
            del sys.modules[k]
        sys.modules.update(saved)


def test_layout_imports_with_no_qt(no_qt):
    # With PyQt6 blocked, the Qt widget module is genuinely unimportable...
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("aetheris.ui.treemap")
    # ...yet the pure layout algorithm imports and computes a correct tiling.
    layout = importlib.import_module("aetheris.ui.treemap_layout")
    placed = layout.squarify([("a", 10), ("b", 20), ("c", 70)], 0, 0, 200, 100)
    assert len(placed) == 3
    area = sum(rw * rh for _n, (rx, ry, rw, rh) in placed)
    assert abs(area - 200 * 100) < 1.0
