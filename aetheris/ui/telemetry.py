"""
Hardware-accelerated telemetry charts (Section 1, item 4).

``TelemetryChart`` is a thin, theme-matched wrapper over a pyqtgraph PlotWidget
with fixed-size numpy ring buffers per series — O(1) per update, so it renders
smoothly at high frame rates while the *sampling* cadence (owned by each tab's
timer) stays coarse enough to keep host CPU overhead low. OpenGL acceleration is
enabled when PyOpenGL is present.

If pyqtgraph is not installed the class degrades to a compact numeric readout
(the same ``push()`` API), so the app stays fully functional without the extra
wheel.
"""
from __future__ import annotations

from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget

try:
    import numpy as np
    import pyqtgraph as pg

    pg.setConfigOptions(antialias=True, background="#0d111a", foreground="#6b7699")
    _HAS_PG = True
except Exception:  # pragma: no cover - fallback path
    np = None       # type: ignore
    pg = None       # type: ignore
    _HAS_PG = False

try:
    import OpenGL  # noqa: F401
    _HAS_GL = True
except Exception:
    _HAS_GL = False


class TelemetryChart(QWidget):
    """
    series: list of (key, label, color_hex).
    window: number of samples retained on screen.
    """

    def __init__(self, series, window: int = 240, y_label: str = "",
                 y_range: tuple[float, float] | None = None,
                 use_gl: bool = False, parent=None) -> None:
        super().__init__(parent)
        self._series = series
        self._window = window
        self._y_range = y_range
        self._build(y_label, use_gl)

    def _build(self, y_label: str, use_gl: bool) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        if not _HAS_PG:
            self._build_fallback(layout)
            return

        self._x = np.arange(-self._window + 1, 1)
        self._buffers = {key: np.zeros(self._window) for key, _l, _c in self._series}
        self._curves = {}

        self.plot = pg.PlotWidget()
        self.plot.setMenuEnabled(False)
        self.plot.setMouseEnabled(x=False, y=False)
        self.plot.hideButtons()
        self.plot.showGrid(x=False, y=True, alpha=0.15)
        self.plot.getAxis("left").setPen(pg.mkPen("#24304a"))
        self.plot.getAxis("bottom").setPen(pg.mkPen("#24304a"))
        self.plot.getAxis("left").setTextPen(pg.mkPen("#6b7699"))
        self.plot.getAxis("bottom").setStyle(showValues=False)
        if y_label:
            self.plot.setLabel("left", y_label, color="#6b7699")
        if self._y_range is not None:
            self.plot.setYRange(*self._y_range)
        else:
            self.plot.enableAutoRange(axis="y")
        if use_gl and _HAS_GL:
            try:
                self.plot.useOpenGL(True)
            except Exception:
                pass

        legend = self.plot.addLegend(offset=(8, 4), labelTextColor="#9fb0e0")
        legend.setBrush(pg.mkBrush(11, 14, 20, 180))
        for key, label, color in self._series:
            curve = self.plot.plot(
                self._x, self._buffers[key],
                pen=pg.mkPen(color, width=2), name=label, fillLevel=None,
            )
            self._curves[key] = curve
        layout.addWidget(self.plot)

    def _build_fallback(self, layout) -> None:
        self._readouts: dict[str, QLabel] = {}
        row = QHBoxLayout()
        note = QLabel("charts: install 'pyqtgraph' — live values:", objectName="subtle")
        row.addWidget(note)
        for key, label, color in self._series:
            lbl = QLabel(f"{label}: –")
            lbl.setFont(QFont("Cascadia Code", 10))
            lbl.setStyleSheet(f"color: {color};")
            self._readouts[key] = lbl
            row.addWidget(lbl)
        row.addStretch(1)
        layout.addLayout(row)

    def push(self, sample: dict) -> None:
        """Append one sample; missing keys hold their previous value."""
        if not _HAS_PG:
            for key, lbl in getattr(self, "_readouts", {}).items():
                if key in sample:
                    series_label = next(l for k, l, _c in self._series if k == key)
                    lbl.setText(f"{series_label}: {sample[key]:,.1f}")
            return
        for key, buf in self._buffers.items():
            buf[:-1] = buf[1:]
            buf[-1] = float(sample.get(key, buf[-1]))
            self._curves[key].setData(self._x, buf)

    def clear(self) -> None:
        if not _HAS_PG:
            return
        for key, buf in self._buffers.items():
            buf[:] = 0
            self._curves[key].setData(self._x, buf)
