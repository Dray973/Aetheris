"""Built-in GUI plugin: live CPU/RAM gauges (demonstrates widget plugins)."""
from aetheris.core.plugins import widget_plugin

PERMISSIONS = ["reads-processes"]


def _make_widget():
    # Qt is imported lazily here so the headless CLI can discover this plugin
    # without pulling in PyQt6.
    import psutil
    from PyQt6.QtCore import QTimer
    from PyQt6.QtWidgets import QLabel, QProgressBar, QVBoxLayout, QWidget

    class Gauges(QWidget):
        def __init__(self):
            super().__init__()
            v = QVBoxLayout(self)
            v.addWidget(QLabel("Live system gauges", objectName="title"))
            self.cpu = QProgressBar()
            self.cpu.setFormat("CPU  %p%")
            self.ram = QProgressBar()
            self.ram.setFormat("RAM  %p%")
            v.addWidget(self.cpu)
            v.addWidget(self.ram)
            self.cores_lbl = QLabel("", objectName="subtle")
            v.addWidget(self.cores_lbl)
            v.addStretch(1)
            psutil.cpu_percent(interval=None, percpu=True)   # prime
            self._t = QTimer(self)
            self._t.timeout.connect(self._tick)
            self._t.start(1000)
            self._tick()

        def _tick(self):
            per = psutil.cpu_percent(interval=None, percpu=True)
            self.cpu.setValue(int(sum(per) / max(len(per), 1)))
            self.ram.setValue(int(psutil.virtual_memory().percent))
            self.cores_lbl.setText(
                "per-core: " + "  ".join(f"{i}:{p:.0f}%" for i, p in enumerate(per)))

    return Gauges()


PLUGIN = widget_plugin("system-gauges",
                       "Live CPU/RAM gauges (GUI-only widget plugin)")(_make_widget)
