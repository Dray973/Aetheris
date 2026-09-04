"""
Module 3 — Network Socket Interceptor & Live Application Firewall.

Live socket→process table with a system-wide bandwidth readout, and a per-app
"Nuke" isolation button that injects INetFwPolicy2 BLOCK rules (rolled back by
PANIC or the Un-isolate button).
"""
from __future__ import annotations

import psutil
from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...core import logbus, report
from ...core.settings import settings
from ...network import connections, firewall
from ..telemetry import TelemetryChart
from ..workers import Worker


def _fmt_bps(v: float) -> str:
    for unit in ("B/s", "KB/s", "MB/s", "GB/s"):
        if v < 1024 or unit == "GB/s":
            return f"{v:,.1f} {unit}"
        v /= 1024
    return f"{v:.1f} GB/s"


class NetworkTab(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._rows: list[connections.Connection] = []
        self._sampler = connections.BandwidthSampler()
        self._ppbw = connections.per_process_bandwidth_sampler()
        self._pp_rates: dict[int, tuple[float, float]] = {}
        self._worker: Worker | None = None
        self._build()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh)
        self._timer.start(3000)
        self._bw_timer = QTimer(self)
        self._bw_timer.timeout.connect(self._sample_bandwidth)
        self._bw_timer.start(1000)
        self.refresh()

    def _sample_bandwidth(self) -> None:
        up, down = self._sampler.sample()
        self.bw_lbl.setText(f"↑ {_fmt_bps(up)}   ↓ {_fmt_bps(down)}")
        self.throughput.push({"up": up / 1024.0, "down": down / 1024.0})
        if self._ppbw.available:
            self._pp_rates = self._ppbw.sample()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.addWidget(QLabel("Network Socket Interceptor & Live Firewall", objectName="title"))

        bar = QHBoxLayout()
        self.bw_lbl = QLabel("↑ –  ↓ –", objectName="subtle")
        bar.addWidget(self.bw_lbl)
        pp = ("per-proc B/s: live" if self._ppbw.available
              else f"per-proc B/s: off ({self._ppbw.status})")
        self.pp_lbl = QLabel("  •  " + pp, objectName="subtle")
        self.pp_lbl.setToolTip("Per-process TCP bandwidth via IP Helper EStats "
                               "(needs an elevated session + a build where "
                               "EStats collection can be enabled).")
        bar.addWidget(self.pp_lbl)
        bar.addStretch(1)
        self.dns_cb = QCheckBox("resolve remote DNS (slower)")
        self.dns_cb.setChecked(bool(settings().get("network_resolve_dns", False)))
        self.dns_cb.toggled.connect(
            lambda v: settings().set("network_resolve_dns", v))
        bar.addWidget(self.dns_cb)
        export = QPushButton("Export…")
        export.clicked.connect(self._export)
        bar.addWidget(export)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        bar.addWidget(refresh)
        root.addLayout(bar)

        self.throughput = TelemetryChart(
            series=[("down", "↓ KB/s", "#5ee0a0"), ("up", "↑ KB/s", "#e0b341")],
            window=240, y_label="KB/s",
        )
        self.throughput.setMaximumHeight(140)
        root.addWidget(self.throughput)

        self.table = QTableWidget(0, 10)
        self.table.setHorizontalHeaderLabels(
            ["PID", "Process", "Proto", "Local", "Remote", "Port", "Status",
             "Class", "rDNS", "Proc B/s ↓/↑"]
        )
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setSectionResizeMode(8, QHeaderView.ResizeMode.Stretch)
        root.addWidget(self.table)

        actions = QHBoxLayout()
        nuke = QPushButton("🚫 Nuke (isolate this app's traffic)")
        nuke.clicked.connect(self._nuke)
        actions.addWidget(nuke)
        unnuke = QPushButton("Un-isolate…")
        unnuke.clicked.connect(self._unisolate)
        actions.addWidget(unnuke)
        actions.addStretch(1)
        self.count_lbl = QLabel("", objectName="subtle")
        actions.addWidget(self.count_lbl)
        root.addLayout(actions)

    def refresh(self) -> None:
        if self._worker and self._worker.isRunning():
            return
        self._worker = Worker(connections.snapshot, resolve_dns=self.dns_cb.isChecked())
        self._worker.done.connect(self._populate)
        self._worker.start()

    def _populate(self, rows) -> None:
        self._rows = rows
        self.table.setRowCount(len(rows))
        for i, c in enumerate(rows):
            rate = self._pp_rates.get(c.pid or -1)
            pp = (f"{_fmt_bps(rate[1])} / {_fmt_bps(rate[0])}"
                  if rate and (rate[0] or rate[1]) else "-")
            klass = f"{c.remote_class} · {c.geo}" if c.geo else c.remote_class
            vals = [
                str(c.pid or "-"), c.proc_name, f"{c.kind}/{c.family[-1]}",
                f"{c.laddr}:{c.lport}", c.raddr or "-", str(c.rport or "-"),
                c.status, klass, c.rdns, pp,
            ]
            for col, v in enumerate(vals):
                item = QTableWidgetItem(v)
                if c.remote_class == "public" and col == 7:
                    item.setForeground(Qt.GlobalColor.yellow)
                self.table.setItem(i, col, item)
        self.count_lbl.setText(f"{len(rows)} sockets")

    def _export(self) -> None:
        if not self._rows:
            self._toast(False, "nothing to export yet")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export connections", "aetheris-connections.csv",
            "CSV (*.csv);;JSON (*.json)")
        if not path:
            return
        rows = report.connection_rows(self._rows)
        try:
            if path.lower().endswith(".json"):
                content = report.rows_to_json(rows)
            else:
                headers = list(rows[0].keys())
                content = report.rows_to_csv(
                    headers, [[r[h] for h in headers] for r in rows])
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(content)
            self._toast(True, f"exported {len(rows)} connections -> {path}")
        except Exception as exc:  # noqa: BLE001
            self._toast(False, str(exc))

    def _selected(self) -> connections.Connection | None:
        row = self.table.currentRow()
        if 0 <= row < len(self._rows):
            return self._rows[row]
        return None

    def _nuke(self) -> None:
        c = self._selected()
        if c is None or c.pid is None:
            self._toast(False, "select a connection with a known PID")
            return
        try:
            exe = psutil.Process(c.pid).exe()
        except Exception as exc:  # noqa: BLE001
            self._toast(False, f"cannot resolve exe: {exc}")
            return
        if QMessageBox.warning(
            self, "Isolate application",
            f"Inject inbound + outbound BLOCK firewall rules for:\n\n{exe}\n\n"
            "All its network traffic will be dropped. (Reversible via PANIC or Un-isolate.)",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        self._run(firewall.isolate, self._show_isolate, exe)

    def _show_isolate(self, res) -> None:
        self._toast(res.ok, res.message)

    def _unisolate(self) -> None:
        self._run(firewall.list_isolation_rules, self._pick_and_deisolate)

    def _pick_and_deisolate(self, active) -> None:
        if not active:
            self._toast(True, "no active Aetheris isolation rules")
            return
        labels = sorted({r.split(":", 1)[1].rsplit("(", 1)[0].strip()
                         for r in active if ":" in r})
        from PySide6.QtWidgets import QInputDialog
        label, ok = QInputDialog.getItem(self, "Un-isolate", "Application:", labels, 0, False)
        if ok and label:
            self._run(firewall.deisolate, self._show_deisolate, label)

    def _show_deisolate(self, res) -> None:
        good, msg = res
        self._toast(good, msg)

    def _run(self, fn, on_done, *args) -> None:
        """Run a blocking native/COM call on the shared Worker."""
        if self._worker and self._worker.isRunning():
            self._toast(False, "a task is already running")
            return
        self._worker = Worker(fn, *args)
        self._worker.done.connect(on_done)
        self._worker.failed.connect(lambda e: self._toast(False, e))
        self._worker.start()

    def _toast(self, ok: bool, msg: str) -> None:
        (logbus.success if ok else logbus.error)("ui.network", msg)
