"""
Virtual Memory Scanner backend (Module 1 core).

A backend abstraction with two implementations behind one interface:

  * MemProcFSBackend — wraps the native ``memprocfs`` (Vmm) API to virtualize
    *physical* RAM: process list recovered from a physical scan (so hidden /
    unlinked processes surface), page/VAD maps, and physical-address reads.
    Requires the memprocfs package **and** an acquisition device (the WinPMEM
    driver for live memory, or a raw/crash dump file).

  * LiveBackend — a fully-functional fallback built only on Win32
    (VirtualQueryEx region maps + ReadProcessMemory), so the scanner works out
    of the box on any elevated session. It cannot see unlinked processes or
    physical memory (those are the MemProcFS-only capabilities).

``get_backend()`` returns MemProcFS when it initializes, else Live. The UI reads
``backend.name`` / ``backend.capabilities`` to label what's active.
"""
from __future__ import annotations

import ctypes
from abc import ABC, abstractmethod
from ctypes import wintypes
from dataclasses import dataclass

from ..core import logbus
from ..core import winapi as W

SRC = "forensics.memvirt"


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------
@dataclass
class MemoryRegion:
    base: int
    size: int
    state: str
    protect: str
    type: str

    @property
    def end(self) -> int:
        return self.base + self.size


@dataclass
class MemoryProcess:
    pid: int
    name: str
    ppid: int = 0
    path: str = ""
    hidden: bool = False       # only meaningful on physical-scan backends


@dataclass
class Capabilities:
    physical: bool = False
    hidden_detection: bool = False
    page_tables: bool = False


# --------------------------------------------------------------------------
# Win32 constants + structures for the live backend
# --------------------------------------------------------------------------
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("__alignment1", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("__alignment2", wintypes.DWORD),
    ]


_STATE = {0x1000: "commit", 0x2000: "reserve", 0x10000: "free"}
_TYPE = {0x20000: "private", 0x40000: "mapped", 0x1000000: "image"}
_PROT = {
    0x01: "---", 0x02: "r--", 0x04: "rw-", 0x08: "rwc",
    0x10: "--x", 0x20: "r-x", 0x40: "rwx", 0x80: "rwxc", 0x00: "?",
}
MEM_FREE = 0x10000
USER_SPACE_MAX = 0x00007FFFFFFF0000


def _protect_str(flags: int) -> str:
    base = _PROT.get(flags & 0xFF, hex(flags))
    if flags & 0x100:
        base += "+guard"
    return base


# --------------------------------------------------------------------------
# Backend interface
# --------------------------------------------------------------------------
class MemoryBackend(ABC):
    name: str = "abstract"
    capabilities: Capabilities = Capabilities()

    @abstractmethod
    def list_processes(self) -> list[MemoryProcess]: ...

    @abstractmethod
    def memory_map(self, pid: int) -> list[MemoryRegion]: ...

    @abstractmethod
    def read(self, pid: int, address: int, size: int) -> bytes | None: ...

    def physical_read(self, address: int, size: int) -> bytes | None:
        return None

    def close(self) -> None:
        pass


# --------------------------------------------------------------------------
# Live Win32 backend (always available on Windows, elevated)
# --------------------------------------------------------------------------
class LiveBackend(MemoryBackend):
    name = "Live Win32 (VirtualQueryEx / ReadProcessMemory)"
    capabilities = Capabilities(physical=False, hidden_detection=False, page_tables=False)

    def list_processes(self) -> list[MemoryProcess]:
        import psutil
        out: list[MemoryProcess] = []
        for p in psutil.process_iter(["pid", "name", "ppid", "exe"]):
            try:
                out.append(MemoryProcess(
                    pid=p.info["pid"], name=p.info.get("name") or "?",
                    ppid=p.info.get("ppid") or 0, path=p.info.get("exe") or "",
                ))
            except Exception:
                continue
        return out

    def memory_map(self, pid: int) -> list[MemoryRegion]:
        if not W.IS_WINDOWS:
            return []
        access = W.PROCESS_QUERY_INFORMATION | W.PROCESS_VM_READ
        h = W.kernel32.OpenProcess(access, False, pid)
        if not h:
            h = W.kernel32.OpenProcess(W.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            logbus.warn(SRC, f"OpenProcess pid {pid} failed", W.last_error_str())
            return []
        try:
            regions: list[MemoryRegion] = []
            addr = 0
            mbi = MEMORY_BASIC_INFORMATION()
            size = ctypes.sizeof(mbi)
            guard = 0
            while addr < USER_SPACE_MAX and guard < 200000:
                guard += 1
                ret = W.kernel32.VirtualQueryEx(h, ctypes.c_void_p(addr),
                                                ctypes.byref(mbi), size)
                if ret != size:
                    break
                region_base = mbi.BaseAddress or 0
                region_size = mbi.RegionSize or 0
                if region_size == 0:
                    break
                if mbi.State != MEM_FREE:
                    regions.append(MemoryRegion(
                        base=region_base, size=region_size,
                        state=_STATE.get(mbi.State, hex(mbi.State)),
                        protect=_protect_str(mbi.Protect),
                        type=_TYPE.get(mbi.Type, "-"),
                    ))
                addr = region_base + region_size
            logbus.trace(SRC, f"mapped {len(regions)} regions for pid {pid}")
            return regions
        finally:
            W.kernel32.CloseHandle(h)

    def read(self, pid: int, address: int, size: int) -> bytes | None:
        if not W.IS_WINDOWS:
            return None
        h = W.kernel32.OpenProcess(W.PROCESS_VM_READ | W.PROCESS_QUERY_INFORMATION,
                                   False, pid)
        if not h:
            return None
        try:
            buf = (ctypes.c_ubyte * size)()
            read = ctypes.c_size_t(0)
            ok = W.kernel32.ReadProcessMemory(h, ctypes.c_void_p(address), buf, size,
                                              ctypes.byref(read))
            if not ok:
                logbus.trace(SRC, f"read @0x{address:x} failed", W.last_error_str())
                return None
            return bytes(buf[: read.value])
        finally:
            W.kernel32.CloseHandle(h)


# --------------------------------------------------------------------------
# MemProcFS physical-memory backend (activates when the library initializes)
# --------------------------------------------------------------------------
class MemProcFSBackend(MemoryBackend):
    name = "MemProcFS (physical RAM virtualization)"
    capabilities = Capabilities(physical=True, hidden_detection=True, page_tables=True)

    def __init__(self, vmm) -> None:
        self._vmm = vmm

    @classmethod
    def try_create(cls, device: str | None = None) -> MemProcFSBackend | None:
        """
        Attempt to initialize MemProcFS. ``device`` is a raw/crash dump path, or
        a live-acquisition device such as 'pmem' (WinPMEM) / 'fpga'. Returns None
        (so the caller falls back to LiveBackend) on any failure.
        """
        try:
            import memprocfs  # type: ignore
        except Exception:
            logbus.trace(SRC, "memprocfs not installed; using live backend")
            return None
        # Candidate devices: explicit first, then live WinPMEM.
        candidates = [device] if device else []
        candidates += ["pmem"]
        for dev in candidates:
            try:
                vmm = memprocfs.Vmm(["-device", dev])
                logbus.success(SRC, f"MemProcFS initialized on device '{dev}'")
                return cls(vmm)
            except Exception as exc:  # noqa: BLE001
                logbus.trace(SRC, f"MemProcFS device '{dev}' unavailable", str(exc))
        logbus.warn(SRC, "MemProcFS present but no acquisition device initialized")
        return None

    def list_processes(self) -> list[MemoryProcess]:
        out: list[MemoryProcess] = []
        try:
            for proc in self._vmm.process_list():
                out.append(MemoryProcess(
                    pid=getattr(proc, "pid", 0),
                    name=getattr(proc, "name", "?"),
                    ppid=getattr(proc, "ppid", 0),
                    path=getattr(proc, "fullname", "") or "",
                    # A physically-scanned process absent from the API-linked
                    # list is the classic "unlinked" signal.
                    hidden=bool(getattr(proc, "is_usermode", True) is False),
                ))
        except Exception as exc:  # noqa: BLE001
            logbus.error(SRC, "MemProcFS process_list failed", str(exc))
        return out

    def memory_map(self, pid: int) -> list[MemoryRegion]:
        regions: list[MemoryRegion] = []
        try:
            proc = self._vmm.process(pid)
            for vad in proc.maps.vad():
                base = vad.get("start", 0)
                end = vad.get("end", base)
                regions.append(MemoryRegion(
                    base=base, size=max(end - base, 0),
                    state="commit",
                    protect=vad.get("protection", "?"),
                    type=vad.get("tag", "-"),
                ))
        except Exception as exc:  # noqa: BLE001
            logbus.error(SRC, f"MemProcFS vad map pid {pid} failed", str(exc))
        return regions

    def read(self, pid: int, address: int, size: int) -> bytes | None:
        try:
            return bytes(self._vmm.process(pid).memory.read(address, size))
        except Exception as exc:  # noqa: BLE001
            logbus.trace(SRC, f"MemProcFS read failed @0x{address:x}", str(exc))
            return None

    def physical_read(self, address: int, size: int) -> bytes | None:
        try:
            return bytes(self._vmm.memory.read(address, size))
        except Exception as exc:  # noqa: BLE001
            logbus.trace(SRC, f"MemProcFS physical read failed @0x{address:x}", str(exc))
            return None

    def close(self) -> None:
        try:
            self._vmm.close()
        except Exception:
            pass


def get_backend(device: str | None = None, prefer_memprocfs: bool = True) -> MemoryBackend:
    if prefer_memprocfs:
        b = MemProcFSBackend.try_create(device)
        if b is not None:
            return b
    return LiveBackend()


# --------------------------------------------------------------------------
# Hex-dump formatter (shared by the UI)
# --------------------------------------------------------------------------
def format_hex(data: bytes, base_addr: int = 0, width: int = 16) -> str:
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = f"{hex_part:<{width*3-1}}"
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"0x{base_addr + off:012x}  {hex_part}  {ascii_part}")
    return "\n".join(lines) or "<no data>"


if W.IS_WINDOWS:
    W.kernel32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p,
        ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t,
    ]
    W.kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    W.kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    W.kernel32.OpenProcess.restype = wintypes.HANDLE
    W.kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
    ]
    W.kernel32.ReadProcessMemory.restype = wintypes.BOOL
