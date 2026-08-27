"""
Squarified treemap canvas (QPainter) for the MFT space-utilization view.

Renders a TreeNode's children as area-proportional rectangles using the
squarify algorithm (Bruls, Huizing & van Wijk) for good aspect ratios.
Double-click a directory tile to descend; the "Up" control pops back. Hovering
shows a name + size tooltip. Painting is bounded: the smallest tiles are folded
into a single "(N more…)" tile so huge directories stay responsive.
"""
from __future__ import annotations

from dataclasses import dataclass

from PyQt6.QtCore import Qt, QRectF, pyqtSignal
from PyQt6.QtGui import QPainter, QColor, QPen, QBrush, QFont
from PyQt6.QtWidgets import QWidget

_PALETTE = ["#2b4a6f", "#356083", "#3f7690", "#4a8c9d", "#5aa0a0",
            "#6f9f7a", "#8a9f5f", "#a89a4e", "#b98a52", "#b5705e"]
_MAX_TILES = 220


def _human(n: int) -> str:
    f = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if f < 1024 or unit == "TB":
            return f"{f:,.1f} {unit}"
        f /= 1024
    return f"{f} B"


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
    items: list of (node, value). Returns [(node, (rx, ry, rw, rh)), …].
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


@dataclass
class _Tile:
    node: object
    rect: QRectF
    color: QColor
    is_more: bool = False


class TreemapWidget(QWidget):
    pathChanged = pyqtSignal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setMinimumHeight(280)
        self.setMouseTracking(True)
        self._stack: list = []          # navigation stack of TreeNodes
        self._tiles: list[_Tile] = []
        self._root = None

    def set_root(self, node) -> None:
        self._root = node
        self._stack = [node] if node is not None else []
        self._relayout()

    def go_up(self) -> None:
        if len(self._stack) > 1:
            self._stack.pop()
            self._relayout()

    def current(self):
        return self._stack[-1] if self._stack else None

    def path(self) -> str:
        return " \\ ".join(getattr(n, "name", "?") for n in self._stack)

    # -- layout -------------------------------------------------------------
    def _relayout(self) -> None:
        self._tiles = []
        node = self.current()
        self.pathChanged.emit(self.path())
        if node is None or not getattr(node, "children", None):
            self.update()
            return
        kids = sorted(node.children, key=lambda c: c.total_size, reverse=True)
        kids = [c for c in kids if c.total_size > 0]
        more_val = 0
        if len(kids) > _MAX_TILES:
            more_val = sum(c.total_size for c in kids[_MAX_TILES:])
            kids = kids[:_MAX_TILES]

        m = 6
        w = max(self.width() - 2 * m, 1)
        h = max(self.height() - 2 * m, 1)
        items = [(c, float(c.total_size)) for c in kids]
        if more_val > 0:
            items.append(("__more__", float(more_val)))

        placed = squarify(items, m, m, w, h)
        for idx, (n, (rx, ry, rw, rh)) in enumerate(placed):
            color = QColor(_PALETTE[idx % len(_PALETTE)])
            self._tiles.append(_Tile(n, QRectF(rx, ry, rw, rh), color, n == "__more__"))
        self.update()

    def resizeEvent(self, ev) -> None:
        super().resizeEvent(ev)
        self._relayout()

    # -- paint --------------------------------------------------------------
    def paintEvent(self, ev) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        p.fillRect(self.rect(), QColor("#0d111a"))
        if not self._tiles:
            p.setPen(QPen(QColor("#6b7699")))
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter,
                       "Parse the MFT, then Build tree-map.")
            return
        font = QFont("Segoe UI", 8)
        p.setFont(font)
        for t in self._tiles:
            p.setBrush(QBrush(t.color))
            p.setPen(QPen(QColor("#0b0e14"), 1))
            p.drawRect(t.rect)
            if t.rect.width() > 46 and t.rect.height() > 20:
                if t.is_more:
                    label = f"(+{self._more_count()} more)"
                    size = ""
                else:
                    label = getattr(t.node, "name", "?")
                    size = _human(getattr(t.node, "total_size", 0))
                p.setPen(QPen(QColor("#e6ecff")))
                inner = t.rect.adjusted(4, 3, -4, -3)
                dir_mark = "📁 " if getattr(t.node, "is_dir", False) and not t.is_more else ""
                p.drawText(inner, int(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft),
                           dir_mark + label)
                if size and t.rect.height() > 34:
                    p.setPen(QPen(QColor("#9fb0e0")))
                    p.drawText(inner, int(Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignLeft),
                               size)

    def _more_count(self) -> int:
        node = self.current()
        if not node:
            return 0
        shown = len([t for t in self._tiles if not t.is_more])
        return max(len([c for c in node.children if c.total_size > 0]) - shown, 0)

    # -- interaction --------------------------------------------------------
    def _hit(self, pos) -> _Tile | None:
        for t in self._tiles:
            if t.rect.contains(float(pos.x()), float(pos.y())):
                return t
        return None

    def mouseMoveEvent(self, ev) -> None:
        t = self._hit(ev.position())
        if t and not t.is_more:
            self.setToolTip(f"{getattr(t.node,'name','?')}\n"
                            f"{_human(getattr(t.node,'total_size',0))}"
                            f"  ({getattr(t.node,'leaf_count',0):,} items)")
        else:
            self.setToolTip("")

    def mouseDoubleClickEvent(self, ev) -> None:
        t = self._hit(ev.position())
        if t and not t.is_more and getattr(t.node, "children", None):
            self._stack.append(t.node)
            self._relayout()
