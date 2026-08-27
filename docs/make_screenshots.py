#!/usr/bin/env python3
"""
Render the Aetheris UI to the screenshots used in the README.

Renders the *real* widgets (native Windows platform, so fonts render) but feeds
each data-bearing tab **representative, non-identifying** data — so the images
show the genuine app without leaking real process paths, usernames, or remote
IPs from the machine that generated them.

    python docs/make_screenshots.py          # writes docs/screenshots/*.png
    python docs/make_screenshots.py --gif     # also builds walkthrough.gif (needs Pillow)

The window is rendered off the visible desktop so nothing pops up on screen.
"""
from __future__ import annotations

import os
import sys
import math
import time
from pathlib import Path

# Native platform => real font rendering (the offscreen plugin draws tofu).
os.environ.pop("QT_QPA_PLATFORM", None)

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
OUT = REPO / "docs" / "screenshots"
OUT.mkdir(parents=True, exist_ok=True)

from PyQt6.QtWidgets import QApplication, QTabWidget          # noqa: E402
from PyQt6.QtCore import QEventLoop                            # noqa: E402
from aetheris.ui.mainwindow import MainWindow                 # noqa: E402
from aetheris.forensics.processes import ProcessInfo          # noqa: E402
from aetheris.network.connections import Connection           # noqa: E402
from aetheris.storage import mft                              # noqa: E402

app = QApplication(sys.argv)
w = MainWindow()
w.resize(1500, 950)
w.move(-6000, -6000)
w.show()


def pump(sec: float) -> None:
    end = time.time() + sec
    while time.time() < end:
        app.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 30)
        time.sleep(0.01)


def shot(name: str) -> None:
    app.processEvents()
    pm = w.grab()
    pm.save(str(OUT / name))
    print(f"saved {name}: {pm.width()}x{pm.height()}")


def main() -> None:
    pump(1.5)

    # 1) Memory / Process Autopsy
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
        ProcessInfo(512, "svchost.exe", "NT AUTHORITY\\SYSTEM",
                    r"C:\Windows\System32\svchost.exe",
                    0.3, 42 * 2**20, 18, "running", "on", "on", "signed"),
    ])
    for i in range(240):
        mem.telemetry.push({"cpu": max(1, 30 + 22 * math.sin(i / 12) + 8 * math.sin(i / 3)),
                            "ram": 55 + 6 * math.sin(i / 30)})
    w.tabs.setCurrentIndex(0); pump(0.4); shot("01-memory.png")

    # 2) Storage tree-map
    st = w.tabs.widget(1)
    R = mft.MftRecord
    recs = [R(5, True, True, "C:\\", 0, 5)]
    layout = {
        "Windows": [("WinSxS", 9_800_000_000), ("System32", 4_200_000_000),
                    ("Installer", 3_100_000_000), ("assembly", 900_000_000)],
        "Users": [("Videos", 22_000_000_000), ("Downloads", 7_400_000_000),
                  ("Documents", 2_600_000_000), ("Pictures", 3_300_000_000)],
        "Program Files": [("Adobe", 5_100_000_000), ("Microsoft VS Code", 720_000_000),
                          ("Google", 640_000_000)],
        "ProgramData": [("Docker", 4_400_000_000), ("Package Cache", 1_800_000_000)],
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
    st.treemap.resize(1400, 560); st.treemap._relayout()
    w.tabs.setCurrentIndex(1); pump(0.4); shot("02-storage-treemap.png")

    # 3) Network
    net = w.tabs.widget(2)
    net._timer.stop()
    net._pp_rates = {1234: (48_000.0, 512_000.0), 4020: (1200.0, 8600.0),
                     7788: (9800.0, 26000.0)}
    net._populate([
        Connection(1234, "chrome.exe", "192.168.0.20", 51344, "142.250.72.206", 443,
                   "ESTABLISHED", "IPv4", "TCP", "public",
                   "lhr25s34-in-f14.1e100.net", "US · Mountain View"),
        Connection(4020, "Code.exe", "192.168.0.20", 51501, "20.60.40.4", 443,
                   "ESTABLISHED", "IPv4", "TCP", "public", "", "IE · Dublin"),
        Connection(7788, "Discord.exe", "192.168.0.20", 51777, "162.159.128.233", 443,
                   "ESTABLISHED", "IPv4", "TCP", "public", "", "US · San Francisco"),
        Connection(880, "svchost.exe", "0.0.0.0", 135, "", 0, "LISTEN",
                   "IPv4", "TCP", "", "", ""),
        Connection(512, "System", "192.168.0.20", 139, "192.168.0.1", 62000,
                   "ESTABLISHED", "IPv4", "TCP", "private", "", ""),
    ])
    net.bw_lbl.setText("↑ 61.2 KB/s   ↓ 540.9 KB/s")
    for i in range(120):
        net.throughput.push({"up": 40 + 20 * math.sin(i / 8),
                             "down": 420 + 120 * math.sin(i / 10)})
    w.tabs.setCurrentIndex(2); pump(0.4); shot("03-network.png")

    # 4) Shell / Registry
    w.tabs.setCurrentIndex(3); pump(0.3); shot("04-shell.png")

    # 5) Auto-Shell
    aut = w.tabs.widget(4)
    aut.input.setText("Terminate all background processes utilizing more than "
                      "350MB of system memory right now.")
    aut._compile()
    w.tabs.setCurrentIndex(4); pump(0.3); shot("05-autoshell.png")

    # 6) Plugins - run the live-gauges widget plugin so the shot shows a widget
    plugins_tab = w.tabs.widget(5)
    for i in range(plugins_tab.list.count()):
        if plugins_tab.list.item(i).text() == "system-gauges":
            plugins_tab.list.setCurrentRow(i)
            plugins_tab._run()
            break
    w.tabs.setCurrentIndex(5); pump(0.5); shot("06-plugins.png")

    if "--gif" in sys.argv:
        _build_gif()
    print("done")


def _build_gif() -> None:
    try:
        from PIL import Image
    except Exception:
        print("Pillow not installed; skipping GIF")
        return
    order = ["01-memory.png", "02-storage-treemap.png", "03-network.png",
             "04-shell.png", "05-autoshell.png", "06-plugins.png"]
    imgs = []
    for f in order:
        im = Image.open(OUT / f).convert("RGB")
        w2 = 1100
        imgs.append(im.resize((w2, int(im.height * w2 / im.width)), Image.LANCZOS))
    imgs[0].save(OUT / "walkthrough.gif", save_all=True, append_images=imgs[1:],
                 duration=2200, loop=0, optimize=True)
    print("saved walkthrough.gif")


if __name__ == "__main__":
    main()
