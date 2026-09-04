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
import importlib.util
import os
from abc import ABC, abstractmethod
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path

from ..core import logbus
from ..core import winapi as W
from ..native import win as nativewin

SRC = "forensics.memvirt"

_WINPMEM_NAMES = ("winpmem_x64.sys", "winpmem_x86.sys")


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
    hidden: bool = False


@dataclass
class Capabilities:
    physical: bool = False
    hidden_detection: bool = False
    page_tables: bool = False
    physical_write: bool = False


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


def _package_dir(name: str) -> Path | None:
    """Directory of an installed package, without importing it."""
    try:
        spec = importlib.util.find_spec(name)
    except Exception:  # noqa: BLE001 - a broken/partial install must not raise here
        return None
    if spec is None or not spec.origin:
        return None
    return Path(spec.origin).resolve().parent


def find_winpmem() -> str | None:
    """
    Locate the WinPMEM kernel driver that LeechCore's 'pmem' device loads.

    Neither the ``memprocfs`` nor the ``leechcorepyc`` wheel ships
    ``winpmem_x64.sys`` (it is a signed kernel driver), so a bare ``-device
    pmem`` can never initialize: LeechCore takes the literal string as the
    driver filename and reports "unable to locate the winpmem driver file
    'pmem'". Discovery order mirrors the other optional engines:

      1. $AETHERIS_WINPMEM (explicit path)
      2. beside leechcore.dll / vmm.dll (LeechCore's own convention)
      3. a ``drivers/`` folder next to the installed package
      4. the current working directory
    """
    env = os.environ.get("AETHERIS_WINPMEM")
    if env and os.path.isfile(env):
        return str(Path(env).resolve())
    roots = [d for d in (_package_dir("leechcorepyc"), _package_dir("memprocfs")) if d]
    roots.append(Path(__file__).resolve().parent.parent / "drivers")
    roots.append(Path.cwd())
    for root in roots:
        for name in _WINPMEM_NAMES:
            p = root / name
            if p.is_file():
                return str(p)
    return None


def ft601_devices() -> int | None:
    """
    Count PCILeech-capable FTDI FT601 endpoints, or None if FTD3XX is missing.

    LeechCore's 'fpga' device speaks FT601/FT2232H **over USB3** — never over
    the host's own PCIe bus — so a DMA board is reachable only from the machine
    at the other end of its USB cable. Asking FTDI directly turns the useless
    generic "Initialization of vmm failed" into "no board is plugged in".
    Counts FT601 only; an older FT2232H rig enumerates through FTD2XX instead,
    so a zero here is a strong hint, not proof, and never blocks an attach.
    """
    d = _package_dir("leechcorepyc")
    if d is None:
        return None
    for name in ("FTD3XX.dll", "FTD3XXWU.dll"):
        lib_path = d / name
        if not lib_path.is_file():
            continue
        try:
            lib = ctypes.WinDLL(str(lib_path))
            n = ctypes.c_ulong(0)
            if lib.FT_CreateDeviceInfoList(ctypes.byref(n)) == 0:
                return int(n.value)
        except Exception:  # noqa: BLE001 - probing must never break an attach
            continue
    return None


#: Selectable acquisition devices: (device string, label, needs a path/host).
DEVICES: tuple[tuple[str, str, bool], ...] = (
    ("fpga", "PCILeech FPGA — USB3/FT601 to a board in the target", False),
    ("pmem", "WinPMEM — this machine's live RAM (needs winpmem_x64.sys)", False),
    ("rawtcp", "LeechAgent over TCP — rawtcp://<host>", True),
    ("hvsavedstate", "Hyper-V saved state — hvsavedstate://<file>", True),
    ("vmware", "VMware guest — a .vmem / .vmss / .vmsn file", True),
    ("usb3380", "USB3380 hardware DMA bridge", False),
    ("totalmeltdown", "CVE-2018-1038 (unpatched Win7 x64 only)", False),
    ("<file>", "Raw or crash dump file — .raw / .dmp / .core", True),
)


def probe_devices() -> list[tuple[str, bool, str]]:
    """
    Report which acquisition devices could plausibly work here, without
    attaching. Returns ``(device, likely_available, reason)`` per entry —
    cheap enough to run on every tab paint.
    """
    out: list[tuple[str, bool, str]] = []
    ft = ft601_devices()
    if ft is None:
        fpga_ok, fpga_why = True, "FTDI FT601 driver not found — cannot pre-check"
    elif ft > 0:
        fpga_ok, fpga_why = True, f"{ft} FT601 device(s) connected"
    else:
        fpga_ok, fpga_why = False, ("no FT601 device on USB — connect the board's "
                                    "USB3 port to this machine")
    out.append(("fpga", fpga_ok, fpga_why))
    driver = find_winpmem()
    out.append(("pmem", bool(driver),
                driver or "winpmem_x64.sys not found (set $AETHERIS_WINPMEM)"))
    for dev, label, needs_arg in DEVICES:
        if dev in ("fpga", "pmem"):
            continue
        out.append((dev, True, label if not needs_arg else f"{label} — supply a target"))
    return out


def _device_arg(dev: str) -> tuple[str, str]:
    """
    Expand a short device name into the string LeechCore actually expects.

    Returns ``(device_arg, blocked_reason)``. A non-empty reason means the
    device cannot possibly initialize on this host, so the caller skips it
    instead of paying a native call that fails with a generic message.
    """
    if dev.lower() != "pmem":
        return dev, ""
    driver = find_winpmem()
    if not driver:
        return dev, ("winpmem driver not found — put winpmem_x64.sys beside "
                     "leechcore.dll or set $AETHERIS_WINPMEM")
    return f"pmem://{driver}", ""


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

    def physical_write(self, address: int, data: bytes) -> bool:
        """Write ``data`` at a *physical* address. Only writable acquisition
        devices (a PCILeech FPGA card) support this; the default refuses."""
        return False

    def close(self) -> None:
        pass


class LiveBackend(MemoryBackend):
    name = "Live Win32 (VirtualQueryEx / ReadProcessMemory)"
    capabilities = Capabilities(physical=False, hidden_detection=False, page_tables=False)

    def list_processes(self) -> list[MemoryProcess]:
        native = nativewin.enum_processes()
        if native:
            return [
                MemoryProcess(pid=p.pid, name=p.name or "?", ppid=p.ppid, path=p.exe)
                for p in native
            ]
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
        # The native engine runs the same VirtualQueryEx walk without a ctypes
        # round-trip per region, which matters on the processes that have tens
        # of thousands of them. It returns raw Win32 constants and the labels
        # are applied here, so both paths emit identical strings.
        native = nativewin.memory_map(pid)
        if native is not None:
            regions = [
                MemoryRegion(
                    base=r.base, size=r.size,
                    state=_STATE.get(r.state, hex(r.state)),
                    protect=_protect_str(r.protect),
                    type=_TYPE.get(r.type, "-"),
                )
                for r in native
            ]
            logbus.trace(SRC, f"mapped {len(regions)} regions for pid {pid} (native)")
            return regions
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
        if nativewin.available():
            data = nativewin.read_memory(pid, address, size)
            if data is None:
                # Same outcome the ctypes path below would reach, minus a second
                # OpenProcess; keep the trace so a failed read is still visible.
                logbus.trace(SRC, f"read @0x{address:x} failed (native)")
            return data
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


class MemProcFSBackend(MemoryBackend):
    name = "MemProcFS (physical RAM virtualization)"
    capabilities = Capabilities(physical=True, hidden_detection=True,
                                page_tables=True, physical_write=False)

    def __init__(self, vmm, device: str = "") -> None:
        self._vmm = vmm
        self._device = device

    @classmethod
    def try_create(cls, device: str | None = None) -> MemProcFSBackend | None:
        """
        Attempt to initialize MemProcFS. ``device`` is a raw/crash dump path, or
        a live-acquisition device: 'fpga' (a PCILeech-flashed FPGA DMA card,
        e.g. an Artix-7 100T board, reached over USB3/FT601) or 'pmem' (the
        WinPMEM driver, located by :func:`find_winpmem`). Returns None (so the
        caller falls back to LiveBackend) on any failure.
        """
        try:
            import memprocfs  # type: ignore
        except Exception:
            logbus.trace(SRC, "memprocfs not installed; using live backend")
            return None
        candidates = [device] if device else []
        candidates += ["pmem"]
        for dev in candidates:
            if not dev:
                continue
            arg, blocked = _device_arg(dev)
            if blocked:
                logbus.trace(SRC, f"MemProcFS device '{dev}' unavailable", blocked)
                continue
            try:
                vmm = memprocfs.Vmm(["-device", arg])
                backend = cls(vmm, device=dev)
                backend.capabilities = Capabilities(
                    physical=True, hidden_detection=True, page_tables=True,
                    physical_write=dev.lower().split("://")[0] in ("fpga", "pmem"),
                )
                logbus.success(SRC, f"MemProcFS initialized on device '{dev}'")
                return backend
            except Exception as exc:  # noqa: BLE001
                detail = str(exc)
                if dev.lower().startswith("fpga") and ft601_devices() == 0:
                    detail += ("  — no FTDI FT601 device is connected over USB; a "
                               "DMA board cannot be reached from the machine it is "
                               "seated in, only from the far end of its USB3 cable")
                logbus.trace(SRC, f"MemProcFS device '{dev}' unavailable", detail)
        logbus.warn(
            SRC, "MemProcFS present but no acquisition device initialized",
            "'fpga' needs a PCILeech-flashed FPGA board reached over USB3/FT601 "
            "(a DAQ or digital-I/O card cannot acquire memory); 'pmem' needs the "
            "winpmem driver. Using the live Win32 backend — no physical access.")
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

    def physical_write(self, address: int, data: bytes) -> bool:
        if not self.capabilities.physical_write:
            logbus.warn(SRC, f"device '{self._device}' is read-only; write refused")
            return False
        try:
            self._vmm.memory.write(address, bytes(data))
            return True
        except Exception as exc:  # noqa: BLE001
            logbus.error(SRC, f"MemProcFS physical write failed @0x{address:x}", str(exc))
            return False

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
