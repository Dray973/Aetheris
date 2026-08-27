"""
Assembly Studio backend — Capstone (disassemble) + Keystone (assemble).

Both engines are optional heavy native wheels. This module imports them lazily
and reports availability so the UI can show a "install capstone/keystone" hint
instead of crashing. Reading another process's memory to feed the disassembler
uses ReadProcessMemory and requires SeDebugPrivilege on an elevated token.

Inline patching (assemble → WriteProcessMemory) is intentionally routed through
``patch_memory`` which the UI only calls after an explicit confirmation dialog,
and which logs the exact address + bytes written to the audit console.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes

from ..core import logbus
from ..core import winapi as W

SRC = "forensics.disasm"

try:
    import capstone  # type: ignore
    _HAS_CAPSTONE = True
except Exception:
    capstone = None  # type: ignore
    _HAS_CAPSTONE = False

try:
    import keystone  # type: ignore
    _HAS_KEYSTONE = True
except Exception:
    keystone = None  # type: ignore
    _HAS_KEYSTONE = False


def engines_available() -> dict[str, bool]:
    return {"capstone": _HAS_CAPSTONE, "keystone": _HAS_KEYSTONE}


def disassemble_bytes(code: bytes, base_addr: int = 0x1000, x64: bool = True) -> list[str]:
    """Disassemble a byte buffer into readable 'addr: mnemonic operands' lines."""
    if not _HAS_CAPSTONE:
        return ["<capstone not installed — pip install capstone>"]
    mode = capstone.CS_MODE_64 if x64 else capstone.CS_MODE_32
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)
    lines = []
    for insn in md.disasm(code, base_addr):
        raw = insn.bytes.hex(" ")
        lines.append(f"0x{insn.address:012x}: {raw:<24} {insn.mnemonic} {insn.op_str}")
    return lines or ["<no instructions decoded>"]


def read_process_memory(pid: int, address: int, size: int) -> bytes | None:
    """Read ``size`` bytes at ``address`` from process ``pid``."""
    if not W.IS_WINDOWS:
        return None
    h = W.kernel32.OpenProcess(W.PROCESS_VM_READ | W.PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        logbus.warn(SRC, f"OpenProcess(read) pid {pid} failed", W.last_error_str())
        return None
    try:
        buf = (ctypes.c_ubyte * size)()
        read = ctypes.c_size_t(0)
        ok = W.kernel32.ReadProcessMemory(
            h, ctypes.c_void_p(address), buf, size, ctypes.byref(read)
        )
        if not ok:
            logbus.warn(SRC, f"ReadProcessMemory failed @0x{address:x}", W.last_error_str())
            return None
        logbus.trace(SRC, f"read {read.value} bytes @0x{address:x} from pid {pid}")
        return bytes(buf[: read.value])
    finally:
        W.kernel32.CloseHandle(h)


def disassemble_process(pid: int, address: int, size: int = 128, x64: bool = True) -> list[str]:
    data = read_process_memory(pid, address, size)
    if data is None:
        return [f"<could not read 0x{address:x} from pid {pid}>"]
    return disassemble_bytes(data, base_addr=address, x64=x64)


def assemble(asm: str, base_addr: int = 0x1000, x64: bool = True) -> tuple[bytes | None, str]:
    """Assemble a snippet with Keystone; returns (machine_code, status)."""
    if not _HAS_KEYSTONE:
        return None, "keystone not installed — pip install keystone-engine"
    mode = keystone.KS_MODE_64 if x64 else keystone.KS_MODE_32
    ks = keystone.Ks(keystone.KS_ARCH_X86, mode)
    try:
        encoding, _count = ks.asm(asm, base_addr)
        return bytes(encoding), f"assembled {len(encoding)} bytes"
    except Exception as exc:  # noqa: BLE001
        return None, f"assembly error: {exc}"


def patch_memory(pid: int, address: int, data: bytes) -> tuple[bool, str]:
    """
    Write ``data`` at ``address`` in process ``pid``. UI-gated behind confirm.
    Logs the exact bytes written for the audit trail.
    """
    if not W.IS_WINDOWS:
        return False, "Windows only"
    access = W.PROCESS_VM_WRITE | W.PROCESS_VM_OPERATION | W.PROCESS_QUERY_INFORMATION
    h = W.kernel32.OpenProcess(access, False, pid)
    if not h:
        return False, f"OpenProcess(write) failed: {W.last_error_str()}"
    try:
        buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        written = ctypes.c_size_t(0)
        ok = W.kernel32.WriteProcessMemory(
            h, ctypes.c_void_p(address), buf, len(data), ctypes.byref(written)
        )
        if not ok:
            return False, f"WriteProcessMemory failed: {W.last_error_str()}"
        logbus.action(SRC, f"PATCHED pid {pid} @0x{address:x}", data.hex(" "))
        return True, f"wrote {written.value} bytes @0x{address:x}"
    finally:
        W.kernel32.CloseHandle(h)


if W.IS_WINDOWS:
    W.kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
    ]
    W.kernel32.ReadProcessMemory.restype = wintypes.BOOL
    W.kernel32.WriteProcessMemory.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
    ]
    W.kernel32.WriteProcessMemory.restype = wintypes.BOOL
