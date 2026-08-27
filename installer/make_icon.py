#!/usr/bin/env python3
"""
Generate the Aetheris Quantum Core application icon.

Renders a "quantum core" mark (a cyan hexagon ring with a glowing center and an
accent orbit) at several resolutions using Qt, encodes each as PNG, and packs
them into a genuine multi-resolution Windows .ico. No external image library
required.

    python installer/make_icon.py
    -> writes aetheris/ui/assets/aetheris.ico
"""
from __future__ import annotations

import os
import math
import struct

from PyQt6.QtCore import Qt, QBuffer, QByteArray, QPointF, QRectF
from PyQt6.QtGui import (
    QImage, QPainter, QColor, QPen, QBrush, QPolygonF, QRadialGradient,
)
from PyQt6.QtWidgets import QApplication

SIZES = [16, 24, 32, 48, 64, 128, 256]
BG = QColor("#0b0e14")
BORDER = QColor("#24304a")
CYAN = QColor("#7dd3fc")
GREEN = QColor("#5ee0a0")


def _hexagon(cx: float, cy: float, r: float) -> QPolygonF:
    pts = []
    for i in range(6):
        a = math.radians(60 * i - 90)
        pts.append(QPointF(cx + r * math.cos(a), cy + r * math.sin(a)))
    return QPolygonF(pts)


def render(size: int) -> QImage:
    img = QImage(size, size, QImage.Format.Format_ARGB32)
    img.fill(Qt.GlobalColor.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing, True)

    # Rounded background tile.
    inset = size * 0.04
    radius = size * 0.20
    p.setBrush(QBrush(BG))
    p.setPen(QPen(BORDER, max(1.0, size * 0.03)))
    p.drawRoundedRect(QRectF(inset, inset, size - 2 * inset, size - 2 * inset),
                      radius, radius)

    cx = cy = size / 2.0

    # Soft glow behind the core.
    glow = QRadialGradient(cx, cy, size * 0.42)
    gc = QColor(CYAN); gc.setAlpha(70)
    glow.setColorAt(0.0, gc)
    glow.setColorAt(1.0, QColor(0, 0, 0, 0))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QBrush(glow))
    p.drawEllipse(QPointF(cx, cy), size * 0.42, size * 0.42)

    # Accent orbit ring.
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.setPen(QPen(GREEN, max(1.0, size * 0.028)))
    p.drawEllipse(QPointF(cx, cy), size * 0.34, size * 0.34)

    # Hexagon "core" outline.
    p.setPen(QPen(CYAN, max(1.2, size * 0.07)))
    p.drawPolygon(_hexagon(cx, cy, size * 0.26))

    # Center node.
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QBrush(CYAN))
    p.drawEllipse(QPointF(cx, cy), size * 0.09, size * 0.09)

    p.end()
    return img


def png_bytes(img: QImage) -> bytes:
    ba = QByteArray()
    buf = QBuffer(ba)
    buf.open(QBuffer.OpenModeFlag.WriteOnly)
    img.save(buf, "PNG")
    buf.close()
    return bytes(ba)


def build_ico(images: list[QImage]) -> bytes:
    blobs = [png_bytes(im) for im in images]
    n = len(blobs)
    header = struct.pack("<HHH", 0, 1, n)          # reserved, type=icon, count
    entries = b""
    offset = 6 + 16 * n
    for im, blob in zip(images, blobs):
        w = im.width() if im.width() < 256 else 0   # 0 encodes 256
        h = im.height() if im.height() < 256 else 0
        entries += struct.pack(
            "<BBBBHHII", w, h, 0, 0, 1, 32, len(blob), offset)
        offset += len(blob)
    return header + entries + b"".join(blobs)


def main() -> None:
    app = QApplication.instance() or QApplication([])  # noqa: F841
    out_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "aetheris", "ui", "assets")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "aetheris.ico")
    images = [render(s) for s in SIZES]
    with open(out_path, "wb") as fh:
        fh.write(build_ico(images))
    print(f"wrote {out_path} ({os.path.getsize(out_path):,} bytes, "
          f"{len(SIZES)} sizes: {SIZES})")


if __name__ == "__main__":
    main()
