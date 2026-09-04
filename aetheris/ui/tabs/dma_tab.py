"""
Module 7 -- DMA / Physical Memory (PCILeech FPGA · MemProcFS).

Attaches a PCILeech FPGA DMA card (e.g. an Artix-7 100T board) through the
MemProcFS acquisition backend and exposes physical-memory read plus the
*guarded* physical-memory write. Every heavy call (device init, reads, the
write) runs on a Worker so the UI never blocks.

The write path is the most invasive action in the suite, so it is disabled until
a *writable* device is attached, always confirmed, honours global dry-run, and is
reversible via the Omega Rollback ledger (see ``forensics/dma.py``). Authorized
use only — systems you own or are cleared to test.
"""
from __future__ import annotations

from PySide6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from ...core import dryrun, logbus
from ...forensics import dma, memvirt
from ..workers import Worker

SRC = "ui.dma"


def _parse_addr(text: str) -> int | None:
    text = text.strip().lower().replace(" ", "")
    if not text:
        return None
    try:
        return int(text, 16)
    except ValueError:
        return None


def _parse_hex_bytes(text: str) -> bytes | None:
    cleaned = text.strip().lower().replace("0x", "").replace(",", " ")
    cleaned = "".join(cleaned.split())
    if not cleaned or len(cleaned) % 2 != 0:
        return None
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return None


class DmaTab(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._backend: memvirt.MemoryBackend | None = None
        self._worker: Worker | None = None
        self._build()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.addWidget(QLabel("DMA / Physical Memory", objectName="title"))
        root.addWidget(QLabel(
            "Attach a PCILeech FPGA card (Artix-7 100T) via MemProcFS to read — and, "
            "on a writable device, write — physical RAM. Authorized use only.",
            objectName="subtle"))

        dev = QHBoxLayout()
        self.attach_btn = QPushButton("Attach FPGA device")
        self.attach_btn.clicked.connect(self._attach)
        dev.addWidget(self.attach_btn)
        self.status = QLabel("No device attached — software backend only.",
                             objectName="subtle")
        dev.addWidget(self.status, 1)
        root.addLayout(dev)

        rg = QGroupBox("Physical read")
        rl = QHBoxLayout(rg)
        rl.addWidget(QLabel("Address 0x"))
        self.read_addr = QLineEdit("1000")
        self.read_addr.setMaximumWidth(160)
        rl.addWidget(self.read_addr)
        rl.addWidget(QLabel("Bytes"))
        self.read_size = QSpinBox()
        self.read_size.setRange(1, 4096)
        self.read_size.setValue(256)
        rl.addWidget(self.read_size)
        self.read_btn = QPushButton("Read")
        self.read_btn.clicked.connect(self._read)
        rl.addWidget(self.read_btn)
        rl.addStretch(1)
        root.addWidget(rg)

        wg = QGroupBox("Physical write  (guarded · confirmed · reversible)")
        wl = QVBoxLayout(wg)
        warn = QLabel(
            "⚠  DMA writes edit a live machine's RAM from outside its OS. A wrong "
            "address can crash or corrupt the target. Every write is confirmed, "
            "audited, and reversible via PANIC; enable Dry-run to rehearse.")
        warn.setWordWrap(True)
        warn.setObjectName("subtle")
        wl.addWidget(warn)
        row = QHBoxLayout()
        row.addWidget(QLabel("Address 0x"))
        self.write_addr = QLineEdit()
        self.write_addr.setMaximumWidth(160)
        self.write_addr.setPlaceholderText("1a2b3c")
        row.addWidget(self.write_addr)
        row.addWidget(QLabel("Bytes (hex)"))
        self.write_bytes = QLineEdit()
        self.write_bytes.setPlaceholderText("de ad be ef")
        row.addWidget(self.write_bytes, 1)
        self.write_btn = QPushButton("Write…")
        self.write_btn.clicked.connect(self._write)
        row.addWidget(self.write_btn)
        wl.addLayout(row)
        root.addWidget(wg)

        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        self.out.setPlaceholderText("Physical-memory output appears here.")
        root.addWidget(self.out, 1)

        self._refresh_capabilities()

    def _refresh_capabilities(self) -> None:
        be = self._backend
        writable = bool(be and dma.write_capable(be))
        physical = bool(be and getattr(be.capabilities, "physical", False))
        self.read_btn.setEnabled(physical)
        for w in (self.write_addr, self.write_bytes, self.write_btn):
            w.setEnabled(writable)
        if be is None:
            self.status.setText("No device attached — software backend only.")
        else:
            caps = []
            if physical:
                caps.append("physical read")
            if writable:
                caps.append("DMA write")
            if getattr(be.capabilities, "hidden_detection", False):
                caps.append("hidden-proc")
            self.status.setText(f"{be.name} — {', '.join(caps) or 'no physical access'}")

    def _busy(self) -> bool:
        return bool(self._worker and self._worker.isRunning())

    def _attach(self) -> None:
        if self._busy():
            return
        self.status.setText("attaching FPGA (MemProcFS -device fpga)…")
        self.attach_btn.setEnabled(False)
        self._worker = Worker(memvirt.get_backend, "fpga")
        self._worker.done.connect(self._on_attached)
        self._worker.failed.connect(self._on_attach_failed)
        self._worker.start()

    def _on_attached(self, backend) -> None:
        self.attach_btn.setEnabled(True)
        self._backend = backend
        self._refresh_capabilities()
        if not getattr(backend.capabilities, "physical", False):
            self.out.appendPlainText(
                "No acquisition device initialized — falling back to the software "
                "backend (no physical access).\n"
                "  • 'fpga' needs a PCILeech-flashed FPGA board (Artix-7 100T / 35T, "
                "Screamer PCIe Squirrel) seated in the TARGET machine and reached from "
                "here over USB3 (FTDI FT601). An ordinary DAQ / digital-I/O or NIC card "
                "cannot acquire memory, no matter which slot it is in.\n"
                "  • 'pmem' reads THIS machine's RAM but needs the signed WinPMEM driver: "
                "put winpmem_x64.sys beside leechcore.dll or set $AETHERIS_WINPMEM.\n"
                "  • A raw or crash dump file also works as a device.")

    def _on_attach_failed(self, err: str) -> None:
        self.attach_btn.setEnabled(True)
        self.status.setText(f"attach failed: {err}")

    def _read(self) -> None:
        if self._busy() or self._backend is None:
            return
        addr = _parse_addr(self.read_addr.text())
        if addr is None:
            self.out.appendPlainText("! invalid address (hex expected)")
            return
        size = self.read_size.value()
        self.read_btn.setEnabled(False)
        self._worker = Worker(self._backend.physical_read, addr, size)
        self._worker.done.connect(lambda data: self._on_read(addr, data))
        self._worker.failed.connect(lambda e: self.out.appendPlainText(f"! read failed: {e}"))
        self._worker.start()

    def _on_read(self, addr: int, data) -> None:
        self._refresh_capabilities()
        if not data:
            self.out.appendPlainText(f"! no data at 0x{addr:x} (device read returned nothing)")
            return
        self.out.appendPlainText(f"── physical read @ 0x{addr:x} ({len(data)} bytes) ──")
        self.out.appendPlainText(memvirt.format_hex(bytes(data), base_addr=addr))

    def _write(self) -> None:
        if self._busy() or self._backend is None:
            return
        addr = _parse_addr(self.write_addr.text())
        if addr is None:
            self.out.appendPlainText("! invalid write address (hex expected)")
            return
        data = _parse_hex_bytes(self.write_bytes.text())
        if not data:
            self.out.appendPlainText("! invalid bytes (even-length hex expected, e.g. 'de ad be ef')")
            return
        rehearse = dryrun.enabled()
        prefix = "[DRY-RUN] " if rehearse else ""
        body = (f"{prefix}Write {len(data)} byte(s) to PHYSICAL address 0x{addr:x}?\n\n"
                f"bytes: {data.hex(' ')}\n\n")
        body += ("Dry-run is ON: nothing will be written; the intent is logged."
                 if rehearse else
                 "This edits live physical RAM. It is audited and reversible via "
                 "PANIC, but a wrong address can crash the target. Proceed only on "
                 "a system you are authorized to modify.")
        if QMessageBox.warning(
            self, "Confirm DMA write", body,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        logbus.trace(SRC, f"operator confirmed DMA write @0x{addr:x} ({len(data)} bytes)")
        self.write_btn.setEnabled(False)
        self._worker = Worker(dma.physical_write, self._backend, addr, data)
        self._worker.done.connect(self._on_written)
        self._worker.failed.connect(lambda e: self.out.appendPlainText(f"! write failed: {e}"))
        self._worker.start()

    def _on_written(self, result) -> None:
        self._refresh_capabilities()
        ok, msg = result
        self.out.appendPlainText(("✓ " if ok else "✗ ") + str(msg))
