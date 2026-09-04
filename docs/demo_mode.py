#!/usr/bin/env python3
"""
Live demo mode — auto-cycles the module tabs with animated charts, for screen
recording. Launches the real app in a normal visible window and, on timers,
advances through the five workspaces while the telemetry/throughput charts move.

    python docs/demo_mode.py              # visible window, loops until closed
    python docs/demo_mode.py --interval 4 # seconds per tab (default 3.5)
    python docs/demo_mode.py --selftest   # headless: cycle a few times and exit

Like the screenshot tool, data-bearing tabs are seeded with representative
(non-identifying) values so a recording doesn't leak real machine state.
"""
from __future__ import annotations

import argparse
import math
import os
import sys
from pathlib import Path

SELFTEST = "--selftest" in sys.argv
if SELFTEST:
    os.environ["QT_QPA_PLATFORM"] = "offscreen"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PySide6.QtCore import QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication, QTabWidget  # noqa: E402

from aetheris.forensics.processes import ProcessInfo  # noqa: E402
from aetheris.network.connections import Connection  # noqa: E402
from aetheris.storage import mft  # noqa: E402
from aetheris.ui.mainwindow import MainWindow  # noqa: E402


def seed(w) -> None:
    """Populate every tab with representative data."""
    mem = w.tabs.widget(0)
    mem._timer.stop()
    mem._populate([
        ProcessInfo(1234, "chrome.exe", "DESKTOP\\user",
                    r"C:\Program Files\Google\Chrome\chrome.exe",
                    6.4, 612 * 2**20, 44, "running", "on", "on", "signed"),
        ProcessInfo(4020, "Code.exe", "DESKTOP\\user",
                    r"C:\Program Files\Microsoft VS Code\Code.exe",
                    3.1, 410 * 2**20, 38, "running", "on", "on", "signed"),
        ProcessInfo(7788, "Discord.exe", "DESKTOP\\user",
                    r"C:\Users\user\AppData\Local\Discord\Discord.exe",
                    2.0, 388 * 2**20, 51, "running", "on", "on", "signed"),
        ProcessInfo(880, "explorer.exe", "DESKTOP\\user", r"C:\Windows\explorer.exe",
                    1.2, 180 * 2**20, 62, "running", "on", "on", "signed"),
        ProcessInfo(9002, "python.exe", "DESKTOP\\user", r"C:\Python312\python.exe",
                    12.7, 96 * 2**20, 9, "running", "on", "off", "unsigned"),
    ])

    st = w.tabs.widget(1)
    R = mft.MftRecord
    recs = [R(5, True, True, "C:\\", 0, 5)]
    layout = {
        "Windows": [("WinSxS", 9_800_000_000), ("System32", 4_200_000_000),
                    ("Installer", 3_100_000_000)],
        "Users": [("Videos", 22_000_000_000), ("Downloads", 7_400_000_000),
                  ("Documents", 2_600_000_000), ("Pictures", 3_300_000_000)],
        "Program Files": [("Adobe", 5_100_000_000), ("Google", 640_000_000)],
        "ProgramData": [("Docker", 4_400_000_000)],
    }
    idx = 10
    for top, kids in layout.items():
        top_idx = idx; idx += 1
        recs.append(R(top_idx, True, True, top, 0, 5))
        for name, size in kids:
            recs.append(R(idx, True, False, name, size, top_idx)); idx += 1
    st._show_mft(recs); st._build_treemap()
    for tw in st.findChildren(QTabWidget):
        for i in range(tw.count()):
            if tw.tabText(i) in ("Tree-map", "Raw MFT Scan"):
                tw.setCurrentIndex(i)

    net = w.tabs.widget(2)
    net._timer.stop()
    net._pp_rates = {1234: (48_000.0, 512_000.0), 7788: (9800.0, 26000.0)}
    net._populate([
        Connection(1234, "chrome.exe", "192.168.0.20", 51344, "142.250.72.206", 443,
                   "ESTABLISHED", "IPv4", "TCP", "public",
                   "lhr25s34-in-f14.1e100.net", "US · Mountain View"),
        Connection(7788, "Discord.exe", "192.168.0.20", 51777, "162.159.128.233", 443,
                   "ESTABLISHED", "IPv4", "TCP", "public", "", "US · San Francisco"),
        Connection(880, "svchost.exe", "0.0.0.0", 135, "", 0, "LISTEN",
                   "IPv4", "TCP", "", "", ""),
    ])

    aut = w.tabs.widget(4)
    aut.input.setText("Isolate my web browser execution context exclusively to "
                      "CPU cores 4, 5, and 6.")
    aut._compile()


class Demo:
    def __init__(self, w, interval: float) -> None:
        self.w = w
        self.frame = 0
        self.anim = QTimer(w)
        self.anim.timeout.connect(self._animate)
        self.anim.start(200)
        self.cycle = QTimer(w)
        self.cycle.timeout.connect(self._advance)
        self.cycle.start(int(interval * 1000))

    def _animate(self) -> None:
        i = self.frame = self.frame + 1
        self.w.tabs.widget(0).telemetry.push(
            {"cpu": max(1, 34 + 24 * math.sin(i / 9) + 7 * math.sin(i / 2.3)),
             "ram": 56 + 6 * math.sin(i / 20)})
        self.w.tabs.widget(2).throughput.push(
            {"up": 45 + 22 * math.sin(i / 7), "down": 430 + 130 * math.sin(i / 9)})

    def _advance(self) -> None:
        nxt = (self.w.tabs.currentIndex() + 1) % self.w.tabs.count()
        self.w.tabs.setCurrentIndex(nxt)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=3.5)
    ap.add_argument("--selftest", action="store_true")
    args, _ = ap.parse_known_args()

    app = QApplication(sys.argv)
    w = MainWindow()
    w.resize(1500, 950)
    w.show()
    seed(w)
    demo = Demo(w, args.interval)

    if args.selftest:
        demo.cycle.setInterval(120)
        start = w.tabs.currentIndex()
        seen: set[int] = set()

        def check():
            seen.add(w.tabs.currentIndex())
            if len(seen) >= w.tabs.count():
                print(f"selftest OK: cycled all {w.tabs.count()} tabs "
                      f"(started at {start})")
                app.quit()

        t = QTimer(w)
        t.timeout.connect(check)
        t.start(60)
        QTimer.singleShot(8000, app.quit)

    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
