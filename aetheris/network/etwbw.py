"""
Per-process TCP bandwidth via ETW (Microsoft-Windows-Kernel-Network).

A real-time ETW consumer that attributes every TCP send/receive to its owning
PID — the build-independent alternative to the (frequently gated) IP-Helper
EStats path. Works on client Windows, including builds where
SetPerTcpConnectionEStats is disabled.

Design:
  * A private real-time trace session enables the Kernel-Network provider.
  * ProcessTrace runs on a background thread; the EVENT_RECORD callback reads
    the leading (PID, size) of each data-transfer event and accumulates
    cumulative sent/recv bytes per PID under a lock.
  * ``sample()`` returns {pid: (up_Bps, down_Bps)} as deltas since the last call.

Requires an elevated token (ETW sessions do). Falls back to ``available=False``
with a status string when the session can't start.
"""
from __future__ import annotations

import atexit
import ctypes
import threading
import time
from ctypes import wintypes

from ..core import logbus

SRC = "network.etwbw"

EVENT_TRACE_REAL_TIME_MODE = 0x00000100
PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000
WNODE_FLAG_TRACED_GUID = 0x00020000
EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
EVENT_TRACE_CONTROL_STOP = 1
TRACE_LEVEL_VERBOSE = 5
ERROR_ALREADY_EXISTS = 183
ERROR_ACCESS_DENIED = 5
INVALID_HANDLE = 0xFFFFFFFFFFFFFFFF

TRACEHANDLE = ctypes.c_ulonglong
SEND_IDS = frozenset({10, 26})     # TCP data sent, IPv4 / IPv6
RECV_IDS = frozenset({11, 27})     # TCP data received, IPv4 / IPv6

_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True) if \
    __import__("sys").platform == "win32" else None


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]


def _guid(s: str) -> GUID:
    g = GUID()
    ctypes.windll.ole32.CLSIDFromString(s, ctypes.byref(g))
    return g


class _WNODE_HEADER(ctypes.Structure):
    _fields_ = [("BufferSize", wintypes.DWORD), ("ProviderId", wintypes.DWORD),
                ("HistoricalContext", ctypes.c_ulonglong),
                ("TimeStamp", ctypes.c_longlong), ("Guid", GUID),
                ("ClientContext", wintypes.DWORD), ("Flags", wintypes.DWORD)]


class EVENT_TRACE_PROPERTIES(ctypes.Structure):
    _fields_ = [("Wnode", _WNODE_HEADER),
                ("BufferSize", wintypes.DWORD), ("MinimumBuffers", wintypes.DWORD),
                ("MaximumBuffers", wintypes.DWORD), ("MaximumFileSize", wintypes.DWORD),
                ("LogFileMode", wintypes.DWORD), ("FlushTimer", wintypes.DWORD),
                ("EnableFlags", wintypes.DWORD), ("AgeLimit", wintypes.LONG),
                ("NumberOfBuffers", wintypes.DWORD), ("FreeBuffers", wintypes.DWORD),
                ("EventsLost", wintypes.DWORD), ("BuffersWritten", wintypes.DWORD),
                ("LogBuffersLost", wintypes.DWORD), ("RealTimeBuffersLost", wintypes.DWORD),
                ("LoggerThreadId", wintypes.HANDLE),
                ("LogFileNameOffset", wintypes.DWORD), ("LoggerNameOffset", wintypes.DWORD)]


class _EVENT_DESCRIPTOR(ctypes.Structure):
    _fields_ = [("Id", wintypes.USHORT), ("Version", ctypes.c_ubyte),
                ("Channel", ctypes.c_ubyte), ("Level", ctypes.c_ubyte),
                ("Opcode", ctypes.c_ubyte), ("Task", wintypes.USHORT),
                ("Keyword", ctypes.c_ulonglong)]


class _EVENT_HEADER(ctypes.Structure):
    _fields_ = [("Size", wintypes.USHORT), ("HeaderType", wintypes.USHORT),
                ("Flags", wintypes.USHORT), ("EventProperty", wintypes.USHORT),
                ("ThreadId", wintypes.DWORD), ("ProcessId", wintypes.DWORD),
                ("TimeStamp", ctypes.c_longlong), ("ProviderId", GUID),
                ("EventDescriptor", _EVENT_DESCRIPTOR),
                ("ProcessorTime", ctypes.c_ulonglong), ("ActivityId", GUID)]


class _ETW_BUFFER_CONTEXT(ctypes.Structure):
    _fields_ = [("ProcessorNumber", ctypes.c_ubyte), ("Alignment", ctypes.c_ubyte),
                ("LoggerId", wintypes.USHORT)]


class EVENT_RECORD(ctypes.Structure):
    _fields_ = [("EventHeader", _EVENT_HEADER), ("BufferContext", _ETW_BUFFER_CONTEXT),
                ("ExtendedDataCount", wintypes.USHORT), ("UserDataLength", wintypes.USHORT),
                ("ExtendedData", ctypes.c_void_p), ("UserData", ctypes.c_void_p),
                ("UserContext", ctypes.c_void_p)]


class EVENT_TRACE_LOGFILEW(ctypes.Structure):
    # CurrentEvent (EVENT_TRACE, 88) and LogfileHeader (TRACE_LOGFILE_HEADER, 280)
    # are opaque blobs of their exact x64 sizes so the callback fields land right.
    _fields_ = [("LogFileName", wintypes.LPWSTR), ("LoggerName", wintypes.LPWSTR),
                ("CurrentTime", ctypes.c_longlong), ("BuffersRead", wintypes.DWORD),
                ("ProcessTraceMode", wintypes.DWORD),
                ("CurrentEvent", ctypes.c_ubyte * 88),
                ("LogfileHeader", ctypes.c_ubyte * 280),
                ("BufferCallback", ctypes.c_void_p),
                ("BufferSize", wintypes.DWORD), ("Filled", wintypes.DWORD),
                ("EventsLost", wintypes.DWORD),
                ("EventRecordCallback", ctypes.c_void_p),
                ("IsKernelTrace", wintypes.DWORD), ("Context", ctypes.c_void_p)]


_EVENT_RECORD_CALLBACK = ctypes.CFUNCTYPE(None, ctypes.POINTER(EVENT_RECORD))

if _advapi32 is not None:
    KERNEL_NETWORK_GUID = _guid("{7DD42A49-5329-4832-8DFD-43D979153A88}")
    _advapi32.StartTraceW.argtypes = [ctypes.POINTER(TRACEHANDLE), wintypes.LPCWSTR,
                                      ctypes.POINTER(EVENT_TRACE_PROPERTIES)]
    _advapi32.StartTraceW.restype = wintypes.ULONG
    _advapi32.EnableTraceEx2.argtypes = [TRACEHANDLE, ctypes.POINTER(GUID), wintypes.ULONG,
                                         ctypes.c_ubyte, ctypes.c_ulonglong,
                                         ctypes.c_ulonglong, wintypes.ULONG, ctypes.c_void_p]
    _advapi32.EnableTraceEx2.restype = wintypes.ULONG
    _advapi32.OpenTraceW.argtypes = [ctypes.POINTER(EVENT_TRACE_LOGFILEW)]
    _advapi32.OpenTraceW.restype = TRACEHANDLE
    _advapi32.ProcessTrace.argtypes = [ctypes.POINTER(TRACEHANDLE), wintypes.ULONG,
                                       ctypes.c_void_p, ctypes.c_void_p]
    _advapi32.ProcessTrace.restype = wintypes.ULONG
    _advapi32.CloseTrace.argtypes = [TRACEHANDLE]
    _advapi32.CloseTrace.restype = wintypes.ULONG
    _advapi32.ControlTraceW.argtypes = [TRACEHANDLE, wintypes.LPCWSTR,
                                        ctypes.POINTER(EVENT_TRACE_PROPERTIES), wintypes.ULONG]
    _advapi32.ControlTraceW.restype = wintypes.ULONG


class EtwBandwidth:
    """Live per-process TCP bandwidth sampler backed by an ETW session."""

    def __init__(self, name: str | None = None) -> None:
        import os
        self.name = name or f"AetherisNet_{os.getpid()}"
        self.available = False
        self.status = "not started"
        self._session = TRACEHANDLE(0)
        self._htrace = 0
        self._props_buf = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._totals: dict[int, list[int]] = {}     # pid -> [sent, recv] cumulative
        self._prev: dict[int, tuple[int, int]] = {}
        self._t = time.monotonic()
        # Keep the ctypes callback alive for the session's lifetime.
        self._cb = _EVENT_RECORD_CALLBACK(self._on_event)
        if _advapi32 is not None:
            self._start()

    # -- session lifecycle --------------------------------------------------
    def _make_props(self):
        size = ctypes.sizeof(EVENT_TRACE_PROPERTIES) + 2 * (len(self.name) + 1) + 8
        buf = (ctypes.c_ubyte * size)()
        props = ctypes.cast(buf, ctypes.POINTER(EVENT_TRACE_PROPERTIES))
        p = props.contents
        p.Wnode.BufferSize = size
        p.Wnode.Flags = WNODE_FLAG_TRACED_GUID
        p.Wnode.ClientContext = 1                    # QPC timestamps
        p.BufferSize = 64
        p.MinimumBuffers = 4
        p.MaximumBuffers = 16
        p.FlushTimer = 1                             # flush real-time buffers every 1 s
        p.LogFileMode = EVENT_TRACE_REAL_TIME_MODE
        p.LoggerNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES)
        return buf, props

    def _start(self) -> None:
        buf, props = self._make_props()
        rc = _advapi32.StartTraceW(ctypes.byref(self._session), self.name, props)
        if rc == ERROR_ALREADY_EXISTS:               # clean up a stale session
            _advapi32.ControlTraceW(0, self.name, props, EVENT_TRACE_CONTROL_STOP)
            buf, props = self._make_props()
            rc = _advapi32.StartTraceW(ctypes.byref(self._session), self.name, props)
        if rc != 0:
            self.status = ("ETW session needs elevation" if rc == ERROR_ACCESS_DENIED
                           else f"StartTrace failed (rc={rc})")
            logbus.trace(SRC, self.status)
            return
        self._props_buf = buf

        rc = _advapi32.EnableTraceEx2(
            self._session, ctypes.byref(KERNEL_NETWORK_GUID),
            EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE,
            0xFFFFFFFFFFFFFFFF, 0, 0, None)
        if rc != 0:
            self.status = f"EnableTraceEx2 failed (rc={rc})"
            self._stop_session()
            return

        logfile = EVENT_TRACE_LOGFILEW()
        logfile.LoggerName = self.name
        logfile.ProcessTraceMode = (PROCESS_TRACE_MODE_REAL_TIME |
                                    PROCESS_TRACE_MODE_EVENT_RECORD)
        logfile.EventRecordCallback = ctypes.cast(self._cb, ctypes.c_void_p)
        self._logfile = logfile                       # keep alive
        self._htrace = _advapi32.OpenTraceW(ctypes.byref(logfile))
        if self._htrace == INVALID_HANDLE:
            self.status = f"OpenTrace failed (err={ctypes.get_last_error()})"
            self._stop_session()
            return

        self._thread = threading.Thread(target=self._pump, daemon=True)
        self._thread.start()
        self.available = True
        self.status = "ETW (Kernel-Network) live"
        atexit.register(self.stop)
        logbus.success(SRC, "per-process bandwidth: ETW session live")

    def _pump(self) -> None:
        h = TRACEHANDLE(self._htrace)
        _advapi32.ProcessTrace(ctypes.byref(h), 1, None, None)

    def _stop_session(self) -> None:
        if self._props_buf is not None:
            props = ctypes.cast(self._props_buf, ctypes.POINTER(EVENT_TRACE_PROPERTIES))
            _advapi32.ControlTraceW(self._session, self.name, props,
                                    EVENT_TRACE_CONTROL_STOP)

    def stop(self) -> None:
        if not self.available and self._htrace == 0:
            return
        self.available = False
        try:
            self._stop_session()
            if self._htrace:
                _advapi32.CloseTrace(TRACEHANDLE(self._htrace))
                self._htrace = 0
        except Exception:
            pass

    # -- event ingestion ----------------------------------------------------
    def _on_event(self, rec_ptr) -> None:
        try:
            rec = rec_ptr.contents
            eid = rec.EventHeader.EventDescriptor.Id
            send = eid in SEND_IDS
            if not send and eid not in RECV_IDS:
                return
            if rec.UserDataLength < 8 or not rec.UserData:
                return
            data = ctypes.string_at(rec.UserData, 8)
            pid = int.from_bytes(data[0:4], "little")
            size = int.from_bytes(data[4:8], "little")
            with self._lock:
                t = self._totals.get(pid)
                if t is None:
                    t = self._totals[pid] = [0, 0]
                t[0 if send else 1] += size
        except Exception:
            pass

    # -- sampling -----------------------------------------------------------
    def sample(self) -> dict[int, tuple[float, float]]:
        """Return {pid: (up_Bps, down_Bps)} since the previous sample."""
        if not self.available:
            return {}
        with self._lock:
            cur = {pid: (t[0], t[1]) for pid, t in self._totals.items()}
        now = time.monotonic()
        dt = max(now - self._t, 1e-6)
        out: dict[int, tuple[float, float]] = {}
        for pid, (sent, recv) in cur.items():
            ps, pr = self._prev.get(pid, (sent, recv))
            up = max(sent - ps, 0) / dt
            down = max(recv - pr, 0) / dt
            if up or down:
                out[pid] = (up, down)
        self._prev = cur
        self._t = now
        return out
