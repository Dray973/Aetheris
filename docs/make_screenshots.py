#!/usr/bin/env python3
"""
Render the Aetheris UI to the screenshots used in the README.

Renders the *real* widgets (native Windows platform, so fonts render) but feeds
each data-bearing tab **representative, non-identifying** data -- so the images
show the genuine app without leaking real process paths, usernames, or remote
IPs from the machine that generated them.

    python docs/make_screenshots.py          # writes docs/screenshots/*.png
    python docs/make_screenshots.py --gif     # also builds walkthrough.gif (needs Pillow)

The window is rendered off the visible desktop so nothing pops up on screen.
"""
from __future__ import annotations

import math
import os
import sys
import time
from pathlib import Path

os.environ.pop("QT_QPA_PLATFORM", None)

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
OUT = REPO / "docs" / "screenshots"
OUT.mkdir(parents=True, exist_ok=True)

from PyQt6.QtCore import QEventLoop, QTimer  # noqa: E402
from PyQt6.QtWidgets import QApplication, QTabWidget  # noqa: E402

from aetheris.analysis.findings import Finding  # noqa: E402
from aetheris.core import timeline as tl  # noqa: E402
from aetheris.core.persistence import PersistenceEntry  # noqa: E402
from aetheris.core.services import ServiceInfo  # noqa: E402
from aetheris.forensics import debugger, memvirt  # noqa: E402
from aetheris.forensics.memvirt import Capabilities  # noqa: E402
from aetheris.forensics.processes import ProcessInfo  # noqa: E402
from aetheris.network.connections import Connection  # noqa: E402
from aetheris.storage import mft  # noqa: E402
from aetheris.ui.mainwindow import MainWindow  # noqa: E402

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


def _inner_tab(widget, label: str) -> None:
    """Switch a tab's inner QTabWidget to the sub-panel named ``label``."""
    for tw in widget.findChildren(QTabWidget):
        for i in range(tw.count()):
            if tw.tabText(i) == label:
                tw.setCurrentIndex(i)
                return


def freeze(tab) -> None:
    """Stop a tab's live refresh so the synthetic data we inject can't be
    overwritten by an in-flight async snapshot — which would leak *real* machine
    data (usernames, exe paths, remote IPs) into the committed README images.
    Stops every timer and disconnects + awaits any running background worker."""
    for t in tab.findChildren(QTimer):
        t.stop()
    worker = getattr(tab, "_worker", None)
    if worker is not None:
        try:
            worker.done.disconnect()
        except (TypeError, RuntimeError):
            pass
        try:
            worker.wait(3000)
        except Exception:  # noqa: BLE001
            pass


def main() -> None:
    pump(1.5)
    # Quiesce every tab BEFORE injecting synthetic data (see freeze() — this is
    # what keeps real machine data out of the screenshots).
    for _i in range(w.tabs.count()):
        freeze(w.tabs.widget(_i))
    pump(0.1)  # drain any already-queued (now-disconnected) worker callbacks

    mem = w.tabs.widget(0)
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
        ProcessInfo(9002, "helper.exe", "DESKTOP\\user",
                    r"C:\Users\user\AppData\Local\Temp\helper.exe",
                    12.7, 96 * 2**20, 9, "running", "on", "off", "unsigned"),
        ProcessInfo(512, "svchost.exe", "NT AUTHORITY\\SYSTEM",
                    r"C:\Windows\System32\svchost.exe",
                    0.3, 42 * 2**20, 18, "running", "on", "on", "signed"),
    ])
    for i in range(240):
        mem.telemetry.push({"cpu": max(1, 30 + 22 * math.sin(i / 12) + 8 * math.sin(i / 3)),
                            "ram": 55 + 6 * math.sin(i / 30)})
    w.tabs.setCurrentIndex(0); pump(0.4); shot("01-memory.png")

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
    _inner_tab(st, "Tree-map")
    st.treemap.resize(1400, 560); st.treemap._relayout()
    w.tabs.setCurrentIndex(1); pump(0.5); shot("02-storage-treemap.png")

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
    w.tabs.setCurrentIndex(2); pump(0.5); shot("03-network.png")

    shell = w.tabs.widget(3)
    shell._services = [
        ServiceInfo("Dnscache", "DNS Client", r"C:\Windows\System32\svchost.exe",
                    r"C:\Windows\System32\svchost.exe", "auto", "service",
                    "NT AUTHORITY\\NetworkService", "running", "signed", False),
        ServiceInfo("AppUpdater", "App Updater", r'C:\Program Files\My App\upd.exe',
                    r'C:\Program Files\My App\upd.exe', "auto", "service",
                    "LocalSystem", "running", "signed", True),
        ServiceInfo("HelperSvc", "Vendor Helper",
                    r"C:\Users\user\AppData\Local\Temp\helper.exe",
                    r"C:\Users\user\AppData\Local\Temp\helper.exe", "auto", "service",
                    "LocalSystem", "stopped", "unsigned", False),
        ServiceInfo("disk", "Disk Driver", r"C:\Windows\System32\drivers\disk.sys",
                    r"C:\Windows\System32\drivers\disk.sys", "boot", "driver", "",
                    "loaded", "signed", False),
        ServiceInfo("nvlddmkm", "NVIDIA Kernel", r"C:\Windows\System32\drivers\nvlddmkm.sys",
                    r"C:\Windows\System32\drivers\nvlddmkm.sys", "manual", "driver", "",
                    "not loaded", "signed", False),
    ]
    _inner_tab(shell, "Services & Drivers")
    shell._apply_svc_filter()
    w.tabs.setCurrentIndex(3); pump(0.4); shot("04-services.png")

    shell._pm = [
        PersistenceEntry("Run", "OneDrive",
                         r"C:\Users\user\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background",
                         r"HKCU\...\CurrentVersion\Run",
                         r"C:\Users\user\AppData\Local\Microsoft\OneDrive\OneDrive.exe",
                         "signed", True),
        PersistenceEntry("Startup", "Spotify",
                         r"C:\Users\user\AppData\Roaming\Spotify\Spotify.exe",
                         "Startup folder (user)",
                         r"C:\Users\user\AppData\Roaming\Spotify\Spotify.exe", "signed", True),
        PersistenceEntry("Service", "AppUpdater", r'"C:\Program Files\My App\upd.exe"',
                         "Service (auto)", r"C:\Program Files\My App\upd.exe", "signed", True),
        PersistenceEntry("Task", "\\Vendor\\SyncTask",
                         r"C:\Users\user\AppData\Local\Temp\sync.exe",
                         r"\Vendor\SyncTask", r"C:\Users\user\AppData\Local\Temp\sync.exe",
                         "unsigned", True),
    ]
    _inner_tab(shell, "Persistence Map")
    shell._apply_pm_filter()
    w.tabs.setCurrentIndex(3); pump(0.4); shot("05-persistence.png")

    tlab = w.tabs.widget(5)
    now = time.time()
    tlab._timeline.add(tl.Snapshot(
        0, now - 300,
        processes={(1234, "chrome.exe"), (4020, "Code.exe"), (880, "explorer.exe")},
        listening={("tcp", 135), ("tcp", 445)},
        connections={"142.250.72.206:443"},
        autoruns={"OneDrive @ HKCU\\Run"}))
    tlab._timeline.add(tl.Snapshot(
        1, now,
        processes={(4020, "Code.exe"), (880, "explorer.exe"), (9002, "powershell.exe")},
        listening={("tcp", 135), ("tcp", 445), ("tcp", 5985)},
        connections={"142.250.72.206:443", "185.199.108.153:443"},
        autoruns={"OneDrive @ HKCU\\Run", "SyncTask @ \\Vendor\\SyncTask"}))
    tlab._refresh_pickers()
    tlab.combo_a.setCurrentIndex(0)
    tlab.combo_b.setCurrentIndex(1)
    tlab._diff()
    w.tabs.setCurrentIndex(5); pump(0.4); shot("06-timeline.png")

    aut = w.tabs.widget(4)
    aut.input.setText("Terminate all background processes utilizing more than "
                      "350MB of system memory right now.")
    aut._compile()
    w.tabs.setCurrentIndex(4); pump(0.3); shot("07-autoshell.png")

    dma_tab = w.tabs.widget(6)

    class _StubFPGA:
        name = "MemProcFS · PCILeech FPGA (Artix-7 100T)"
        capabilities = Capabilities(physical=True, hidden_detection=True,
                                    page_tables=True, physical_write=True)

    dma_tab._backend = _StubFPGA()
    dma_tab._refresh_capabilities()
    dma_tab.read_addr.setText("1a2b3000")
    dma_tab.write_addr.setText("1a2b3040")
    dma_tab.write_bytes.setText("90 90 90 90")
    sample = (bytes.fromhex("4d5a9000030000000400000000ff0000b8000000")
              + b"\x00" * 12 + b"This program cannot be run in DOS mode.\r\r\n$"
              + b"\x00" * 40)
    dma_tab.out.appendPlainText("── physical read @ 0x1a2b3000 (256 bytes) ──")
    dma_tab.out.appendPlainText(memvirt.format_hex(sample, base_addr=0x1a2b3000))
    dma_tab.out.appendPlainText("✓ wrote 4 bytes @ 0x1a2b3040")
    w.tabs.setCurrentIndex(6); pump(0.4); shot("08-dma.png")

    dbg = w.tabs.widget(7)
    dbg.status.setText("attached to target.exe (pid 8321) — stopped at breakpoint")
    dbg.attach_btn.setEnabled(False)
    dbg.detach_btn.setEnabled(True)
    dbg.cont_btn.setEnabled(True)
    dbg.step_btn.setEnabled(True)
    dbg.bp_addr.setText("7ff6a1b2c3d0")
    dbg.mem_addr.setText("7ff6a1b2c3d0")
    dbg.bp_list.setText("0x7ff6a1b2c3d0  0x7ff6a1b2c4a0")
    regs = {"Rax": 1, "Rbx": 0x7FF6A1B30000, "Rcx": 0xC4E5AFF740, "Rdx": 0,
            "Rsi": 0x7FF6A1B2C3D0, "Rdi": 0x140, "Rbp": 0xC4E5AFF8A0, "Rsp": 0xC4E5AFF720,
            "Rip": 0x7FF6A1B2C3D0, "R8": 0, "R9": 0x7FFCE0000000, "R10": 0, "R11": 0x246,
            "R12": 0, "R13": 0, "R14": 0, "R15": 0, "EFlags": 0x202}
    for ev in ("[create-process] tid 4102", "[load-dll] tid 4102  ntdll.dll",
               "[breakpoint] tid 4102 @ 0x7ff6a1b2c3d0"):
        dbg.out.appendPlainText(ev)
    dbg.out.appendPlainText("── registers ──")
    _rline = []
    for _i, _r in enumerate(debugger.X64_REGISTERS, 1):
        _rline.append(f"{_r:<6} 0x{regs.get(_r, 0):016x}")
        if _i % 3 == 0:
            dbg.out.appendPlainText("  ".join(_rline)); _rline = []
    if _rline:
        dbg.out.appendPlainText("  ".join(_rline))
    _code = bytes.fromhex("48895c2408 4889742410 57 4883ec20 488bda 488bf9 e8a4120000".replace(" ", ""))
    dbg.out.appendPlainText("── read @ 0x7ff6a1b2c3d0 (64 bytes) ──")
    dbg.out.appendPlainText(memvirt.format_hex(_code, base_addr=0x7FF6A1B2C3D0))
    w.tabs.setCurrentIndex(7); pump(0.3); shot("09-debugger.png")

    hunt = w.tabs.widget(8)
    hunt._populate([
        Finding(key="helper.exe", subject="helper.exe (pid 9002)",
                title="Correlated (4 signals): masquerading, c2, persistence, injection",
                score=100, category="correlated", technique="T1055",
                technique_name="Masquerading; App Layer Protocol; Autostart; Injection",
                evidence=["• Suspicious process: unsigned + temp/download directory [T1036]",
                          "    exe: C:\\Users\\user\\AppData\\Local\\Temp\\helper.exe",
                          "    Authenticode: unsigned",
                          "• Public outbound connection from an unsigned process [T1071]",
                          "    185.220.101.5:443 (RU · Moscow)",
                          "• Autostart persistence (unsigned) from temp [T1547]",
                          "    location: HKCU\\...\\CurrentVersion\\Run",
                          "• PE image in private memory (possible injected module) [T1055]",
                          "    region: 0x1a2b0000 +0x40000"],
                actions=["kill pid 9002", "isolate helper.exe", "disable Helper"]),
        Finding(key="upc", subject="UpcElevationService (service)",
                title="Unquoted service path (privilege-escalation candidate)",
                score=40, category="privesc", technique="T1574.009",
                technique_name="Path Interception (Unquoted Path)",
                evidence=["ImagePath: C:\\Program Files\\Vendor\\upc.exe", "start: auto"]),
        Finding(key="synctask", subject="SyncTask (task)",
                title="Suspicious scheduled task: obfuscated/encoded shell command",
                score=45, category="persistence", technique="T1053.005",
                technique_name="Scheduled Task",
                evidence=["task: \\Vendor\\SyncTask", "triggers: logon",
                          "action: powershell -enc SQBFAFgA..."],
                actions=["disable task \\Vendor\\SyncTask"]),
        Finding(key="wcast.exe", subject="wcast.exe (pid 3576)",
                title="Suspicious process: unsigned", score=30, category="masquerading",
                technique="T1036", technique_name="Masquerading",
                evidence=["exe: C:\\Tools\\wcast.exe", "Authenticode: unsigned"],
                actions=["kill pid 3576"]),
    ])
    hunt.table.selectRow(0)
    w.tabs.setCurrentIndex(8); pump(0.4); shot("10-hunt.png")

    plugins_tab = w.tabs.widget(9)
    for i in range(plugins_tab.list.count()):
        if plugins_tab.list.item(i).text().startswith("system-gauges"):
            plugins_tab.list.setCurrentRow(i)
            plugins_tab._run()
            break
    w.tabs.setCurrentIndex(9); pump(0.5); shot("11-plugins.png")

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
             "04-services.png", "05-persistence.png", "06-timeline.png",
             "07-autoshell.png", "08-dma.png", "09-debugger.png", "10-hunt.png",
             "11-plugins.png"]
    imgs = []
    for f in order:
        im = Image.open(OUT / f).convert("RGB")
        w2 = 1100
        imgs.append(im.resize((w2, int(im.height * w2 / im.width)), Image.LANCZOS))
    imgs[0].save(OUT / "walkthrough.gif", save_all=True, append_images=imgs[1:],
                 duration=2000, loop=0, optimize=True)
    print("saved walkthrough.gif")


if __name__ == "__main__":
    main()
