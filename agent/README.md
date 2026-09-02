# Aetheris in-process API-monitor agent

A small native (C++) DLL that the Aetheris host injects into a **user-chosen,
non-critical** process to *observe* a curated set of Win32 calls for forensic
analysis. It is the native half of the API-monitor feature; the host half lives
in [`aetheris/forensics/apimonitor.py`](../aetheris/forensics/apimonitor.py).

## What it does
- On load, connects to a host-owned named pipe (`\\.\pipe\aetheris_agent_<pid>`).
- Installs **IAT hooks by resolved address** (robust against API-set forwarders)
  on: `CreateFileW`, `LoadLibraryW`, `VirtualAlloc`, `WriteProcessMemory`,
  `CreateProcessW` (spawns) and `connect` (outbound network).
- Streams each observed call as one line of NDJSON back to the host, each tagged
  with the **immediate caller** (`module+0xoffset`, via `_ReturnAddress`).
- Un-hooks cleanly when the host signals stop. The DLL stays resident and loops
  one session per attach, so **re-attaching to the same process works**.

It **only observes** — every hook forwards to the real function and returns its
result unchanged. A per-thread reentrancy guard prevents recursive logging, and
the agent's own module is never patched.

**Scope:** catches statically-imported calls (the common case). Calls made
through a hand-resolved `GetProcAddress` pointer are not covered — that needs
inline hooking (a later iteration).

**Authorized use only.** Injection is gated in the host by a confirm dialog, the
tamper-evident audit log, global dry-run, and the same system-critical-process
refusal list as the debugger and DMA write.

## Build
Requires the MSVC C++ toolset (Visual Studio Build Tools → *Desktop development
with C++*).

```powershell
powershell -ExecutionPolicy Bypass -File agent\build.ps1
```

Outputs `dist\aetheris_agent.dll` (git-ignored). The host finds it via
`AETHERIS_AGENT_DLL`, next to a frozen exe, or in `dist\`.
