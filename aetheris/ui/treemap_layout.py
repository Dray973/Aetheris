"""
Pure squarified-treemap geometry (no Qt, no OS dependencies).

The squarify algorithm (Bruls, Huizing & van Wijk) lays a list of weighted
items out as area-proportional rectangles with good aspect ratios. This module
is deliberately import-clean -- it pulls in nothing from PyQt6 or the platform,
so the layout math is unit-testable anywhere, including machines without a
display or PyQt6 installed. The Qt canvas in ``treemap.py`` imports ``squarify``
from here.
"""
from __future__ import annotations


def _worst(areas: list[float], side: float) -> float:
    if not areas or side <= 0:
        return float("inf")
    s = sum(areas)
    if s <= 0:
        return float("inf")
    mx, mn = max(areas), min(areas)
    return max((side * side * mx) / (s * s), (s * s) / (side * side * mn))


def squarify(items, x, y, w, h):
    """
    items: list of (node, value). Returns [(node, (rx, ry, rw, rh)), ...].
    Areas are scaled so the values fill the x,y,w,h rectangle.
    """
    items = sorted(items, key=lambda t: t[1], reverse=True)
    total = sum(max(v, 0) for _n, v in items) or 1.0
    scale = (w * h) / total
    scaled = [(n, max(v, 0) * scale) for n, v in items]

    out = []
    i = 0
    while i < len(scaled) and w > 0.5 and h > 0.5:
        side = min(w, h)
        row = [scaled[i]]
        i += 1
        while i < len(scaled):
            cur = [a for _n, a in row]
            if _worst(cur + [scaled[i][1]], side) > _worst(cur, side):
                break
            row.append(scaled[i])
            i += 1
        row_area = sum(a for _n, a in row)
        if w <= h:                                  # lay a horizontal strip
            rh = row_area / w if w else 0
            rx = x
            for n, a in row:
                rw = (a / rh) if rh else 0
                out.append((n, (rx, y, rw, rh)))
                rx += rw
            y += rh
            h -= rh
        else:                                       # lay a vertical strip
            rw = row_area / h if h else 0
            ry = y
            for n, a in row:
                rh2 = (a / rw) if rw else 0
                out.append((n, (x, ry, rw, rh2)))
                ry += rh2
            x += rw
            w -= rw
    return out
