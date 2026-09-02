"""
Module 8 -- Debugger (attach to a running process).

Attaches to a process as a real debugger (see ``forensics/debugger.py``): set
software breakpoints, read/write its memory and x64 registers, single-step, and
watch its debug events (DLL loads, exceptions, output) live. Attach and every
write are confirmed; writes honour global dry-run and are PANIC-reversible;
system-critical processes are refused. Debug events cross from the loop thread to
the GUI via a queued signal. Authorized use only.
"""
from __future__ import annotations

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
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
from ...forensics import debugger, memvirt, processes
from ..workers import Worker

SRC = "ui.debugger"


def _parse_addr(text: str) -> int | None:
    text = text.strip().lower().replace(" ", "")
    if not text:
        return None
    try:
        return int(text, 16)
    except ValueError:
        return None


def _parse_hex_bytes(text: str) -> bytes | None:
    cleaned = "".join(text.strip().lower().replace("0x", "").replace(",", " ").split())
    if not cleaned or len(cleaned) % 2 != 0:
        return None
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return None


class DebuggerTab(QWidget):
    _event = pyqtSignal(object)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._session: debugger.DebugSession | None = None
        self._worker: Worker | None = None
        self._stopped = False
        self._build()
        self._event.connect(self._on_debug_event)
        self._refresh_processes()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.addWidget(QLabel("Debugger — Attach to a Process", objectName="title"))
        root.addWidget(QLabel(
            "Attach as a real debugger: breakpoints, memory + register read/write, "
            "single-step, live events. Authorized use only.", objectName="subtle"))

        bar = QHBoxLayout()
        self.proc = QComboBox()
        self.proc.setMinimumWidth(360)
        bar.addWidget(self.proc, 1)
        refresh = QPushButton("↻")
        refresh.setMaximumWidth(36)
        refresh.clicked.connect(self._refresh_processes)
        bar.addWidget(refresh)
        self.attach_btn = QPushButton("Attach")
        self.attach_btn.clicked.connect(self._attach)
        bar.addWidget(self.attach_btn)
        self.detach_btn = QPushButton("Detach")
        self.detach_btn.clicked.connect(self._detach)
        self.detach_btn.setEnabled(False)
        bar.addWidget(self.detach_btn)
        self.cont_btn = QPushButton("Continue")
        self.cont_btn.clicked.connect(lambda: self._resume("continue"))
        bar.addWidget(self.cont_btn)
        self.step_btn = QPushButton("Step")
        self.step_btn.clicked.connect(lambda: self._resume("step"))
        bar.addWidget(self.step_btn)
        root.addLayout(bar)
        self.status = QLabel("Not attached.", objectName="subtle")
        root.addWidget(self.status)

        bp = QGroupBox("Breakpoints")
        bl = QHBoxLayout(bp)
        bl.addWidget(QLabel("Address 0x"))
        self.bp_addr = QLineEdit()
        self.bp_addr.setMaximumWidth(180)
        bl.addWidget(self.bp_addr)
        set_bp = QPushButton("Set")
        set_bp.clicked.connect(self._set_bp)
        bl.addWidget(set_bp)
        clr_bp = QPushButton("Clear")
        clr_bp.clicked.connect(self._clear_bp)
        bl.addWidget(clr_bp)
        self.bp_list = QLabel("(none)", objectName="subtle")
        bl.addWidget(self.bp_list, 1)
        root.addWidget(bp)

        mem = QGroupBox("Memory")
        ml = QHBoxLayout(mem)
        ml.addWidget(QLabel("Address 0x"))
        self.mem_addr = QLineEdit()
        self.mem_addr.setMaximumWidth(180)
        ml.addWidget(self.mem_addr)
        ml.addWidget(QLabel("Bytes"))
        self.mem_size = QSpinBox()
        self.mem_size.setRange(1, 4096)
        self.mem_size.setValue(64)
        ml.addWidget(self.mem_size)
        read_btn = QPushButton("Read")
        read_btn.clicked.connect(self._read_mem)
        ml.addWidget(read_btn)
        ml.addWidget(QLabel("Write hex"))
        self.mem_bytes = QLineEdit()
        self.mem_bytes.setPlaceholderText("90 90")
        ml.addWidget(self.mem_bytes, 1)
        write_btn = QPushButton("Write…")
        write_btn.clicked.connect(self._write_mem)
        ml.addWidget(write_btn)
        root.addWidget(mem)

        reg = QGroupBox("Registers (valid while stopped at a breakpoint)")
        rl = QHBoxLayout(reg)
        read_regs = QPushButton("Read registers")
        read_regs.clicked.connect(self._read_regs)
        rl.addWidget(read_regs)
        rl.addWidget(QLabel("Set"))
        self.reg_name = QComboBox()
        self.reg_name.addItems(debugger.X64_REGISTERS)
        rl.addWidget(self.reg_name)
        rl.addWidget(QLabel("= 0x"))
        self.reg_val = QLineEdit()
        self.reg_val.setMaximumWidth(180)
        rl.addWidget(self.reg_val)
        set_reg = QPushButton("Set…")
        set_reg.clicked.connect(self._set_reg)
        rl.addWidget(set_reg)
        rl.addStretch(1)
        root.addWidget(reg)

        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        self.out.setPlaceholderText("Debug events and output appear here.")
        root.addWidget(self.out, 1)

        self._update_enabled()

    # -- helpers ------------------------------------------------------------
    def _busy(self) -> bool:
        return bool(self._worker and self._worker.isRunning())

    def _attached(self) -> bool:
        return bool(self._session and self._session.attached)

    def _update_enabled(self) -> None:
        att = self._attached()
        self.attach_btn.setEnabled(not att)
        self.detach_btn.setEnabled(att)
        self.cont_btn.setEnabled(att and self._stopped)
        self.step_btn.setEnabled(att and self._stopped)

    def _refresh_processes(self) -> None:
        if self._busy():
            return
        self._worker = Worker(processes.snapshot)
        self._worker.done.connect(self._fill_processes)
        self._worker.start()

    def _fill_processes(self, procs) -> None:
        cur = self.proc.currentData()
        self.proc.clear()
        for p in sorted(procs, key=lambda p: (p.name or "").lower()):
            if not debugger.can_debug(p.name or ""):
                continue
            self.proc.addItem(f"{p.pid:>6}  {p.name}", p.pid)
        idx = self.proc.findData(cur)
        if idx >= 0:
            self.proc.setCurrentIndex(idx)

    # -- attach / detach ----------------------------------------------------
    def _attach(self) -> None:
        if self._attached() or self._busy():
            return
        pid = self.proc.currentData()
        if pid is None:
            return
        parts = self.proc.currentText().split(None, 1)
        name = parts[1].strip() if len(parts) > 1 else str(pid)
        if QMessageBox.warning(
            self, "Attach debugger",
            f"Attach the debugger to {name} (pid {pid})?\n\n"
            "The target is controlled while stopped at a breakpoint; detach leaves "
            "it running. Only debug a process you're authorized to inspect.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        self._session = debugger.DebugSession(pid, name, on_event=self._event.emit)
        self.status.setText(f"attaching to {name} (pid {pid})…")
        self._worker = Worker(self._session.attach)
        self._worker.done.connect(self._on_attached)
        self._worker.failed.connect(lambda e: self.status.setText(f"attach failed: {e}"))
        self._worker.start()

    def _on_attached(self, result) -> None:
        ok, msg = result
        self.status.setText(msg)
        self._update_enabled()

    def _detach(self) -> None:
        if not self._session:
            return
        ok, msg = self._session.detach()
        self._session = None
        self._stopped = False
        self.status.setText(msg)
        self._update_enabled()

    def _resume(self, mode: str) -> None:
        if self._session and self._stopped:
            self._session.resume(mode)
            self._stopped = False
            self.out.appendPlainText(f"▸ {mode}")
            self._update_enabled()

    # -- breakpoints --------------------------------------------------------
    def _set_bp(self) -> None:
        if not self._require_session():
            return
        addr = _parse_addr(self.bp_addr.text())
        if addr is None:
            self.out.appendPlainText("! invalid breakpoint address (hex)")
            return
        ok, msg = self._session.set_breakpoint(addr)
        self.out.appendPlainText(("✓ " if ok else "✗ ") + msg)
        self._refresh_bps()

    def _clear_bp(self) -> None:
        if not self._require_session():
            return
        addr = _parse_addr(self.bp_addr.text())
        if addr is None:
            return
        ok, msg = self._session.clear_breakpoint(addr)
        self.out.appendPlainText(("✓ " if ok else "✗ ") + msg)
        self._refresh_bps()

    def _refresh_bps(self) -> None:
        if not self._session:
            self.bp_list.setText("(none)")
            return
        bps = self._session.breakpoints()
        self.bp_list.setText("  ".join(f"0x{a:x}" for a in bps) or "(none)")

    # -- memory -------------------------------------------------------------
    def _read_mem(self) -> None:
        if not self._require_session() or self._busy():
            return
        addr = _parse_addr(self.mem_addr.text())
        if addr is None:
            self.out.appendPlainText("! invalid memory address (hex)")
            return
        size = self.mem_size.value()
        self._worker = Worker(self._session.read_memory, addr, size)
        self._worker.done.connect(lambda data: self._on_mem(addr, data))
        self._worker.failed.connect(lambda e: self.out.appendPlainText(f"! read failed: {e}"))
        self._worker.start()

    def _on_mem(self, addr: int, data) -> None:
        if not data:
            self.out.appendPlainText(f"! no data at 0x{addr:x}")
            return
        self.out.appendPlainText(f"── read @ 0x{addr:x} ({len(data)} bytes) ──")
        self.out.appendPlainText(memvirt.format_hex(bytes(data), base_addr=addr))

    def _write_mem(self) -> None:
        if not self._require_session():
            return
        addr = _parse_addr(self.mem_addr.text())
        data = _parse_hex_bytes(self.mem_bytes.text())
        if addr is None or not data:
            self.out.appendPlainText("! invalid write address or bytes (even-length hex)")
            return
        rehearse = dryrun.enabled()
        prefix = "[DRY-RUN] " if rehearse else ""
        if QMessageBox.warning(
            self, "Confirm memory write",
            f"{prefix}Write {len(data)} byte(s) to 0x{addr:x} in {self._session.name}?\n\n"
            f"bytes: {data.hex(' ')}\n\n"
            + ("Dry-run is ON: nothing will be written."
               if rehearse else "Audited and PANIC-reversible."),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        ok, msg = self._session.write_memory(addr, data)
        self.out.appendPlainText(("✓ " if ok else "✗ ") + msg)

    # -- registers ----------------------------------------------------------
    def _read_regs(self) -> None:
        if not self._require_session():
            return
        regs = self._session.get_registers()
        if not regs:
            self.out.appendPlainText("! registers unavailable (stop at a breakpoint first)")
            return
        self.out.appendPlainText("── registers ──")
        line = []
        for i, name in enumerate(debugger.X64_REGISTERS, 1):
            line.append(f"{name:<6} 0x{regs.get(name, 0):016x}")
            if i % 3 == 0:
                self.out.appendPlainText("  ".join(line))
                line = []
        if line:
            self.out.appendPlainText("  ".join(line))

    def _set_reg(self) -> None:
        if not self._require_session():
            return
        name = self.reg_name.currentText()
        val = _parse_addr(self.reg_val.text())
        if val is None:
            self.out.appendPlainText("! invalid register value (hex)")
            return
        prefix = "[DRY-RUN] " if dryrun.enabled() else ""
        if QMessageBox.warning(
            self, "Confirm register write",
            f"{prefix}Set {name} = 0x{val:x} in {self._session.name}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        ok, msg = self._session.set_register(name, val)
        self.out.appendPlainText(("✓ " if ok else "✗ ") + msg)

    # -- events -------------------------------------------------------------
    def _require_session(self) -> bool:
        if not self._attached():
            self.out.appendPlainText("! attach to a process first")
            return False
        return True

    def _on_debug_event(self, evt) -> None:
        line = f"[{evt.kind}] tid {evt.tid}"
        if evt.address:
            line += f" @ 0x{evt.address:x}"
        if evt.detail:
            line += f"  {evt.detail}"
        self.out.appendPlainText(line)
        if evt.kind == "breakpoint":
            self._stopped = True
            self._update_enabled()
            self._read_regs()
        elif evt.kind == "exit-process":
            self._stopped = False
            self._session = None
            self.status.setText("target exited")
            self._update_enabled()
        logbus.trace(SRC, line)
