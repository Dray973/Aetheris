"""
Live debugger (attach to a running process).

Attaches to a process with the Win32 debugging API (``DebugActiveProcess`` on an
elevated token with SeDebugPrivilege), runs a debug-event loop on a dedicated
thread, and exposes software breakpoints, read/write of the target's memory and
registers, single-step, and exception reporting. Detach is clean:
``DebugSetProcessKillOnExit(FALSE)`` + ``DebugActiveProcessStop`` leaves the
target running.

The pure decision logic -- breakpoint bookkeeping (save original byte / restore),
debug-event decoding, the RIP fix-up after an int3, and the single-step trap-flag
math -- carries no OS dependency and is unit-tested off-Windows. The native
``DebugSession`` wraps it behind the suite's safety model: attach and every write
are confirmed by the UI, refuse system-critical processes, honour global dry-run,
are audited, and register a rollback so PANIC restores original bytes and detaches.

Authorized use only: debugging and analysing processes you own or are cleared to
inspect.
"""
from __future__ import annotations

import ctypes
import queue
import threading
from collections.abc import Callable
from ctypes import wintypes
from dataclasses import dataclass

from ..core import dryrun, logbus, safety
from ..core import winapi as W
from ..storage.unlock import CRITICAL_PROCESSES

SRC = "forensics.debugger"

BREAKPOINT_BYTE = 0xCC
TRAP_FLAG = 0x100

EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
OUTPUT_DEBUG_STRING_EVENT = 8
RIP_EVENT = 9

EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004
EXCEPTION_ACCESS_VIOLATION = 0xC0000005

DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

_EVENT_KINDS = {
    CREATE_THREAD_DEBUG_EVENT: "create-thread",
    CREATE_PROCESS_DEBUG_EVENT: "create-process",
    EXIT_THREAD_DEBUG_EVENT: "exit-thread",
    EXIT_PROCESS_DEBUG_EVENT: "exit-process",
    LOAD_DLL_DEBUG_EVENT: "load-dll",
    UNLOAD_DLL_DEBUG_EVENT: "unload-dll",
    OUTPUT_DEBUG_STRING_EVENT: "output",
    RIP_EVENT: "rip",
}

_EXCEPTION_NAMES = {
    EXCEPTION_BREAKPOINT: "breakpoint",
    EXCEPTION_SINGLE_STEP: "single-step",
    EXCEPTION_ACCESS_VIOLATION: "access-violation",
}

X64_REGISTERS = (
    "Rax", "Rbx", "Rcx", "Rdx", "Rsi", "Rdi", "Rbp", "Rsp", "Rip",
    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "EFlags",
)


# --- pure decision logic (no OS dependency, unit-tested) -------------------
def decode_event(code: int, exception_code: int = 0) -> str:
    """Human label for a debug event; exceptions resolve to their sub-kind."""
    if code == EXCEPTION_DEBUG_EVENT:
        return _EXCEPTION_NAMES.get(exception_code, f"exception 0x{exception_code:08x}")
    return _EVENT_KINDS.get(code, f"event {code}")


def rip_after_break(rip: int) -> int:
    """A software breakpoint (0xCC) traps with RIP one byte *past* the int3;
    back it up so the original instruction re-executes."""
    return rip - 1


def set_trap_flag(eflags: int) -> int:
    return eflags | TRAP_FLAG


def clear_trap_flag(eflags: int) -> int:
    return eflags & ~TRAP_FLAG


@dataclass
class DebugEvent:
    kind: str
    pid: int
    tid: int
    address: int = 0
    detail: str = ""


@dataclass
class Breakpoint:
    address: int
    original_byte: int | None = None
    enabled: bool = True
    hits: int = 0


class BreakpointManager:
    """Tracks software breakpoints over a (read_mem, write_mem) byte interface,
    saving each original byte so it can be restored exactly. Pure enough to test
    against a bytearray standing in for target memory."""

    def __init__(self, read_mem: Callable[[int, int], bytes | None],
                 write_mem: Callable[[int, bytes], bool]) -> None:
        self._read = read_mem
        self._write = write_mem
        self._bps: dict[int, Breakpoint] = {}

    def addresses(self) -> list[int]:
        return sorted(self._bps)

    def get(self, address: int) -> Breakpoint | None:
        return self._bps.get(address)

    def is_ours(self, address: int) -> bool:
        bp = self._bps.get(address)
        return bp is not None and bp.enabled

    def set(self, address: int) -> tuple[bool, str]:
        if address in self._bps:
            return False, f"breakpoint already set @ 0x{address:x}"
        orig = self._read(address, 1)
        if not orig:
            return False, f"cannot read target byte @ 0x{address:x}"
        if not self._write(address, bytes([BREAKPOINT_BYTE])):
            return False, f"cannot write breakpoint @ 0x{address:x}"
        self._bps[address] = Breakpoint(address, orig[0])
        return True, f"breakpoint set @ 0x{address:x}"

    def clear(self, address: int) -> tuple[bool, str]:
        bp = self._bps.pop(address, None)
        if bp is None:
            return False, f"no breakpoint @ 0x{address:x}"
        if bp.original_byte is not None:
            self._write(address, bytes([bp.original_byte]))
        return True, f"breakpoint cleared @ 0x{address:x}"

    def on_hit(self, address: int) -> Breakpoint | None:
        bp = self._bps.get(address)
        if bp is not None:
            bp.hits += 1
        return bp

    def restore_all(self) -> None:
        for address, bp in list(self._bps.items()):
            if bp.original_byte is not None:
                self._write(address, bytes([bp.original_byte]))
        self._bps.clear()


# --- native x64 CONTEXT + debug structures ---------------------------------
CONTEXT_AMD64 = 0x00100000
CONTEXT_CONTROL = CONTEXT_AMD64 | 0x1
CONTEXT_INTEGER = CONTEXT_AMD64 | 0x2
CONTEXT_FULL = CONTEXT_AMD64 | 0x1 | 0x2 | 0x8

THREAD_GET_CONTEXT = 0x0008
THREAD_SET_CONTEXT = 0x0010
THREAD_QUERY_INFORMATION = 0x0040
THREAD_ALL = THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION


class _M128A(ctypes.Structure):
    _fields_ = [("Low", ctypes.c_ulonglong), ("High", ctypes.c_longlong)]


class _XMM_SAVE_AREA32(ctypes.Structure):
    _fields_ = [
        ("ControlWord", ctypes.c_ushort), ("StatusWord", ctypes.c_ushort),
        ("TagWord", ctypes.c_ubyte), ("Reserved1", ctypes.c_ubyte),
        ("ErrorOpcode", ctypes.c_ushort), ("ErrorOffset", ctypes.c_ulong),
        ("ErrorSelector", ctypes.c_ushort), ("Reserved2", ctypes.c_ushort),
        ("DataOffset", ctypes.c_ulong), ("DataSelector", ctypes.c_ushort),
        ("Reserved3", ctypes.c_ushort), ("MxCsr", ctypes.c_ulong),
        ("MxCsr_Mask", ctypes.c_ulong), ("FloatRegisters", _M128A * 8),
        ("XmmRegisters", _M128A * 16), ("Reserved4", ctypes.c_ubyte * 96),
    ]


class CONTEXT(ctypes.Structure):
    _pack_ = 16
    _fields_ = [
        ("P1Home", ctypes.c_ulonglong), ("P2Home", ctypes.c_ulonglong),
        ("P3Home", ctypes.c_ulonglong), ("P4Home", ctypes.c_ulonglong),
        ("P5Home", ctypes.c_ulonglong), ("P6Home", ctypes.c_ulonglong),
        ("ContextFlags", ctypes.c_ulong), ("MxCsr", ctypes.c_ulong),
        ("SegCs", ctypes.c_ushort), ("SegDs", ctypes.c_ushort),
        ("SegEs", ctypes.c_ushort), ("SegFs", ctypes.c_ushort),
        ("SegGs", ctypes.c_ushort), ("SegSs", ctypes.c_ushort),
        ("EFlags", ctypes.c_ulong),
        ("Dr0", ctypes.c_ulonglong), ("Dr1", ctypes.c_ulonglong),
        ("Dr2", ctypes.c_ulonglong), ("Dr3", ctypes.c_ulonglong),
        ("Dr6", ctypes.c_ulonglong), ("Dr7", ctypes.c_ulonglong),
        ("Rax", ctypes.c_ulonglong), ("Rcx", ctypes.c_ulonglong),
        ("Rdx", ctypes.c_ulonglong), ("Rbx", ctypes.c_ulonglong),
        ("Rsp", ctypes.c_ulonglong), ("Rbp", ctypes.c_ulonglong),
        ("Rsi", ctypes.c_ulonglong), ("Rdi", ctypes.c_ulonglong),
        ("R8", ctypes.c_ulonglong), ("R9", ctypes.c_ulonglong),
        ("R10", ctypes.c_ulonglong), ("R11", ctypes.c_ulonglong),
        ("R12", ctypes.c_ulonglong), ("R13", ctypes.c_ulonglong),
        ("R14", ctypes.c_ulonglong), ("R15", ctypes.c_ulonglong),
        ("Rip", ctypes.c_ulonglong),
        ("FltSave", _XMM_SAVE_AREA32),
        ("VectorRegister", _M128A * 26), ("VectorControl", ctypes.c_ulonglong),
        ("DebugControl", ctypes.c_ulonglong), ("LastBranchToRip", ctypes.c_ulonglong),
        ("LastBranchFromRip", ctypes.c_ulonglong), ("LastExceptionToRip", ctypes.c_ulonglong),
        ("LastExceptionFromRip", ctypes.c_ulonglong),
    ]


class _EXCEPTION_RECORD(ctypes.Structure):
    pass


_EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", wintypes.DWORD), ("ExceptionFlags", wintypes.DWORD),
    ("ExceptionRecord", ctypes.POINTER(_EXCEPTION_RECORD)),
    ("ExceptionAddress", ctypes.c_void_p), ("NumberParameters", wintypes.DWORD),
    ("ExceptionInformation", ctypes.c_ulonglong * 15),
]


class _EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("ExceptionRecord", _EXCEPTION_RECORD), ("dwFirstChance", wintypes.DWORD)]


class _EXIT_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("dwExitCode", wintypes.DWORD)]


class _DEBUG_EVENT_UNION(ctypes.Union):
    _fields_ = [("Exception", _EXCEPTION_DEBUG_INFO),
                ("ExitProcess", _EXIT_PROCESS_DEBUG_INFO),
                ("_raw", ctypes.c_ubyte * 160)]


class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [
        ("dwDebugEventCode", wintypes.DWORD), ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD), ("u", _DEBUG_EVENT_UNION),
    ]


# --- native debug session --------------------------------------------------
class DebugSession:
    """A live debugger attached to one process. The debug loop runs on its own
    thread (WaitForDebugEvent/ContinueDebugEvent are thread-affine); the UI drives
    it through thread-safe commands and receives events via ``on_event``."""

    def __init__(self, pid: int, name: str = "",
                 on_event: Callable[[DebugEvent], None] | None = None) -> None:
        self.pid = pid
        self.name = name or str(pid)
        self._on_event = on_event or (lambda e: None)
        self.attached = False
        self.status = "not attached"
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._resume: queue.Queue[str] = queue.Queue()
        self._stopped_tid = 0
        self._hproc = None
        self._bps = BreakpointManager(self._read_mem_raw, self._write_mem_raw)
        self._pending_rearm: int | None = None
        self._expect_step = False
        self._step_mode = False

    # -- lifecycle ----------------------------------------------------------
    def attach(self) -> tuple[bool, str]:
        if self.name.lower() in CRITICAL_PROCESSES:
            return False, f"refused: {self.name} is system-critical"
        if not W.IS_WINDOWS:
            return False, "Windows only"
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        for _ in range(50):
            if self.attached or self.status.startswith("attach failed"):
                break
            self._stop.wait(0.05)
        return (self.attached, self.status)

    def detach(self) -> tuple[bool, str]:
        self._stop.set()
        self._resume.put("continue")
        if self._thread is not None:
            self._thread.join(3)
        return True, f"detached from {self.name}"

    # -- memory + registers (valid while the target is stopped) -------------
    def _open(self):
        if self._hproc is None:
            self._hproc = W.kernel32.OpenProcess(
                W.PROCESS_VM_READ | W.PROCESS_VM_WRITE | W.PROCESS_VM_OPERATION
                | W.PROCESS_QUERY_INFORMATION, False, self.pid)
        return self._hproc

    def _read_mem_raw(self, address: int, size: int) -> bytes | None:
        h = self._open()
        if not h:
            return None
        buf = (ctypes.c_ubyte * size)()
        got = ctypes.c_size_t(0)
        if not W.kernel32.ReadProcessMemory(h, ctypes.c_void_p(address), buf, size,
                                            ctypes.byref(got)):
            return None
        return bytes(buf[:got.value])

    def _write_mem_raw(self, address: int, data: bytes) -> bool:
        h = self._open()
        if not h:
            return False
        buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        wrote = ctypes.c_size_t(0)
        return bool(W.kernel32.WriteProcessMemory(
            h, ctypes.c_void_p(address), buf, len(data), ctypes.byref(wrote)))

    def read_memory(self, address: int, size: int) -> bytes | None:
        return self._read_mem_raw(address, size)

    def write_memory(self, address: int, data: bytes) -> tuple[bool, str]:
        n = len(data)
        if n == 0:
            return False, "nothing to write"
        if dryrun.skip(SRC, f"write {n} bytes @ 0x{address:x} in pid {self.pid}",
                       data.hex(" ")):
            return True, f"[dry-run] would write {n} bytes @ 0x{address:x}"
        original = self._read_mem_raw(address, n)
        if not self._write_mem_raw(address, data):
            return False, f"write failed @ 0x{address:x}"
        before = original.hex(" ") if original else "<unreadable>"
        logbus.action(SRC, f"wrote {n} bytes @ 0x{address:x} in pid {self.pid}",
                      f"{before} -> {data.hex(' ')}")
        if original is not None:
            snap = original
            safety.ledger.register(
                f"debug write @ 0x{address:x} (pid {self.pid})",
                lambda: self._write_mem_raw(address, snap))
        return True, f"wrote {n} bytes @ 0x{address:x}"

    def get_registers(self, tid: int = 0) -> dict[str, int]:
        tid = tid or self._stopped_tid
        if not tid:
            return {}
        hthr = W.kernel32.OpenThread(THREAD_ALL, False, tid)
        if not hthr:
            return {}
        try:
            ctx = CONTEXT()
            ctx.ContextFlags = CONTEXT_FULL
            if not W.kernel32.GetThreadContext(hthr, ctypes.byref(ctx)):
                return {}
            return {r: int(getattr(ctx, r)) for r in X64_REGISTERS}
        finally:
            W.kernel32.CloseHandle(hthr)

    def set_register(self, name: str, value: int, tid: int = 0) -> tuple[bool, str]:
        if name not in X64_REGISTERS:
            return False, f"unknown register {name!r}"
        tid = tid or self._stopped_tid
        if not tid:
            return False, "target is not stopped"
        if dryrun.skip(SRC, f"set {name}=0x{value:x} in pid {self.pid}"):
            return True, f"[dry-run] would set {name}=0x{value:x}"
        prior: list[int] = []

        def _mut(c: CONTEXT) -> None:
            prior.append(int(getattr(c, name)))
            setattr(c, name, value)

        if not self._with_context(tid, _mut):
            return False, "set register failed"
        was = prior[0] if prior else 0
        logbus.action(SRC, f"set {name}=0x{value:x} in pid {self.pid}", f"was 0x{was:x}")
        safety.ledger.register(
            f"debug reg {name} (pid {self.pid})",
            lambda p=was: self._with_context(tid, lambda c: setattr(c, name, p)))
        return True, f"{name} = 0x{value:x}"

    # -- breakpoints --------------------------------------------------------
    def set_breakpoint(self, address: int) -> tuple[bool, str]:
        if dryrun.skip(SRC, f"set breakpoint @ 0x{address:x} in pid {self.pid}"):
            return True, f"[dry-run] would set breakpoint @ 0x{address:x}"
        ok, msg = self._bps.set(address)
        if ok:
            logbus.action(SRC, f"breakpoint set @ 0x{address:x} in pid {self.pid}")
            safety.ledger.register(f"debug breakpoint @ 0x{address:x}",
                                   lambda: self._bps.clear(address))
        return ok, msg

    def clear_breakpoint(self, address: int) -> tuple[bool, str]:
        ok, msg = self._bps.clear(address)
        if ok:
            logbus.action(SRC, f"breakpoint cleared @ 0x{address:x} in pid {self.pid}")
        return ok, msg

    def breakpoints(self) -> list[int]:
        return self._bps.addresses()

    def resume(self, mode: str = "continue") -> None:
        self._resume.put(mode)

    # -- debug loop (own thread) --------------------------------------------
    def _emit(self, kind: str, tid: int, address: int = 0, detail: str = "") -> None:
        try:
            self._on_event(DebugEvent(kind, self.pid, tid, address, detail))
        except Exception:  # noqa: BLE001
            pass

    def _loop(self) -> None:
        if not W.kernel32.DebugActiveProcess(self.pid):
            self.status = f"attach failed: {W.last_error_str()}"
            logbus.warn(SRC, self.status)
            return
        W.kernel32.DebugSetProcessKillOnExit(False)
        self.attached = True
        self.status = f"attached to {self.name} (pid {self.pid})"
        logbus.action(SRC, self.status)
        evt = DEBUG_EVENT()
        while not self._stop.is_set():
            if not W.kernel32.WaitForDebugEvent(ctypes.byref(evt), 200):
                continue
            cont = self._dispatch(evt)
            W.kernel32.ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, cont)
        try:
            W.kernel32.DebugActiveProcessStop(self.pid)
        except Exception:  # noqa: BLE001
            pass
        if self._hproc:
            W.kernel32.CloseHandle(self._hproc)
            self._hproc = None
        self.attached = False
        self.status = "detached"

    def _dispatch(self, evt: DEBUG_EVENT) -> int:
        code = evt.dwDebugEventCode
        tid = evt.dwThreadId
        if code == EXIT_PROCESS_DEBUG_EVENT:
            self._stop.set()
            self._emit("exit-process", tid, detail=f"exit {evt.u.ExitProcess.dwExitCode}")
            return DBG_CONTINUE
        if code != EXCEPTION_DEBUG_EVENT:
            self._emit(decode_event(code), tid)
            return DBG_CONTINUE
        rec = evt.u.Exception.ExceptionRecord
        excode = int(rec.ExceptionCode)
        addr = int(rec.ExceptionAddress or 0)
        if excode == EXCEPTION_SINGLE_STEP and self._expect_step:
            self._expect_step = False
            if self._pending_rearm is not None:
                self._write_mem_raw(self._pending_rearm, bytes([BREAKPOINT_BYTE]))
                self._pending_rearm = None
            if self._step_mode:
                self._step_mode = False
                return self._stop_and_wait(tid, addr, "single-step", fixup=False)
            return DBG_CONTINUE
        if excode == EXCEPTION_BREAKPOINT and self._bps.is_ours(addr):
            self._bps.on_hit(addr)
            return self._stop_and_wait(tid, addr, "breakpoint", fixup=True)
        if excode == EXCEPTION_BREAKPOINT:
            return DBG_CONTINUE
        self._emit(decode_event(code, excode), tid, addr,
                   "first-chance" if evt.u.Exception.dwFirstChance else "last-chance")
        return DBG_EXCEPTION_NOT_HANDLED

    def _stop_and_wait(self, tid: int, addr: int, kind: str, fixup: bool) -> int:
        """Report a stop, block until the UI resumes, then set up the resume:
        step over a live breakpoint (restore byte + trap flag + re-arm) or
        single-step, honouring continue/step."""
        self._stopped_tid = tid
        if fixup:
            self._with_context(tid, lambda c: setattr(c, "Rip", rip_after_break(int(c.Rip))))
        self._emit(kind, tid, addr)
        try:
            mode = self._resume.get(timeout=600)
        except queue.Empty:
            mode = "continue"
        self._stopped_tid = 0
        if self._stop.is_set():
            return DBG_CONTINUE
        bp = self._bps.get(addr)
        if bp is not None and bp.original_byte is not None:
            self._write_mem_raw(addr, bytes([bp.original_byte]))
            self._pending_rearm = addr
        else:
            self._pending_rearm = None
        if mode == "step" or self._pending_rearm is not None:
            self._with_context(tid, lambda c: setattr(c, "EFlags", set_trap_flag(int(c.EFlags))))
            self._expect_step = True
            self._step_mode = (mode == "step")
        return DBG_CONTINUE

    def _with_context(self, tid: int, mutate: Callable[[CONTEXT], None]) -> bool:
        hthr = W.kernel32.OpenThread(THREAD_ALL, False, tid)
        if not hthr:
            return False
        try:
            ctx = CONTEXT()
            ctx.ContextFlags = CONTEXT_FULL
            if not W.kernel32.GetThreadContext(hthr, ctypes.byref(ctx)):
                return False
            mutate(ctx)
            return bool(W.kernel32.SetThreadContext(hthr, ctypes.byref(ctx)))
        finally:
            W.kernel32.CloseHandle(hthr)


def can_debug(name: str) -> bool:
    return name.lower() not in CRITICAL_PROCESSES


_STRUCTS_BOUND = False


def _bind() -> None:
    global _STRUCTS_BOUND
    if _STRUCTS_BOUND or not W.IS_WINDOWS:
        return
    k = W.kernel32
    k.DebugActiveProcess.argtypes = [wintypes.DWORD]
    k.DebugActiveProcess.restype = wintypes.BOOL
    k.DebugActiveProcessStop.argtypes = [wintypes.DWORD]
    k.DebugActiveProcessStop.restype = wintypes.BOOL
    k.DebugSetProcessKillOnExit.argtypes = [wintypes.BOOL]
    k.DebugSetProcessKillOnExit.restype = wintypes.BOOL
    k.WaitForDebugEvent.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    k.WaitForDebugEvent.restype = wintypes.BOOL
    k.ContinueDebugEvent.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.DWORD]
    k.ContinueDebugEvent.restype = wintypes.BOOL
    k.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k.OpenThread.restype = wintypes.HANDLE
    k.GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    k.GetThreadContext.restype = wintypes.BOOL
    k.SetThreadContext.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    k.SetThreadContext.restype = wintypes.BOOL
    _STRUCTS_BOUND = True


_bind()
