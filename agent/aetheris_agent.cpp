// Aetheris Quantum Core — in-process API-monitor agent (injected DLL).
//
// Authorized use only. This DLL is injected by the Aetheris host into a
// user-chosen, non-critical process to *observe* a curated set of Win32 calls
// for forensic analysis. It installs Import-Address-Table (IAT) hooks by
// resolved function address (robust against API-set forwarders), logs each call
// as one line of NDJSON to a host-owned named pipe, and un-hooks cleanly when
// the host signals stop. It never blocks or alters the observed calls — every
// hook forwards to the real function and returns its result unchanged.
//
// Each event carries the immediate caller (module+offset, via _ReturnAddress)
// so the analyst sees *who* made the call, not just that it happened. The DLL
// stays resident and loops one session per host attach, so re-attaching to the
// same process works.
//
// Scope: catches statically-imported calls (the common case). Calls made through
// a hand-resolved GetProcAddress pointer are not covered — that needs inline
// hooking (a later iteration). Honest by design.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <psapi.h>
#include <intrin.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <utility>

#pragma comment(lib, "psapi.lib")
#pragma intrinsic(_ReturnAddress)

namespace {

HMODULE g_self = nullptr;          // our own module — never patch it
HANDLE  g_pipe = INVALID_HANDLE_VALUE;
HANDLE  g_stop = nullptr;          // host sets this to request un-hook
HANDLE  g_go = nullptr;            // host sets this to start a session (re-attach)
CRITICAL_SECTION g_write_cs;       // serialises pipe writes (hooks are multi-threaded)
CRITICAL_SECTION g_patch_cs;
DWORD   g_tls = TLS_OUT_OF_INDEXES;  // per-thread "already logging" guard

std::vector<std::pair<void**, void*>> g_patches;  // (slot, original) for restore

bool in_hook() { return TlsGetValue(g_tls) != nullptr; }
void set_in_hook(bool v) { TlsSetValue(g_tls, v ? (LPVOID)1 : (LPVOID)0); }

// ---- event emission (NDJSON over the pipe) -------------------------------
void append_json_str(std::string& out, const char* utf8) {
    out += '"';
    for (const char* p = utf8; *p; ++p) {
        unsigned char c = (unsigned char)*p;
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) { char b[8]; sprintf_s(b, "\\u%04x", c); out += b; }
                else out += (char)c;
        }
    }
    out += '"';
}

std::string wide_to_utf8(const wchar_t* w) {
    if (!w) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return std::string();
    std::string s((size_t)n - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], n, nullptr, nullptr);
    return s;
}

// The caller of a hooked call, resolved to "module+0xoffset" (or a raw address).
std::string resolve_caller(void* addr) {
    HMODULE mod = nullptr;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)addr, &mod) && mod) {
        wchar_t path[MAX_PATH];
        if (GetModuleFileNameW(mod, path, MAX_PATH)) {
            const wchar_t* base = path;
            for (const wchar_t* p = path; *p; ++p)
                if (*p == L'\\' || *p == L'/') base = p + 1;
            char off[24];
            sprintf_s(off, "+0x%llx",
                      (unsigned long long)((uintptr_t)addr - (uintptr_t)mod));
            return wide_to_utf8(base) + off;
        }
    }
    char b[24];
    sprintf_s(b, "0x%llx", (unsigned long long)(uintptr_t)addr);
    return std::string(b);
}

void emit(const std::string& body) {  // body = the inner fields, no braces
    if (g_pipe == INVALID_HANDLE_VALUE) return;
    std::string line = "{\"tid\":";
    line += std::to_string((unsigned long)GetCurrentThreadId());
    line += ',';
    line += body;
    line += "}\n";
    EnterCriticalSection(&g_write_cs);
    DWORD wrote = 0;
    WriteFile(g_pipe, line.data(), (DWORD)line.size(), &wrote, nullptr);
    LeaveCriticalSection(&g_write_cs);
}

std::string head(const char* api, void* ret) {
    std::string b = "\"api\":\"";
    b += api;
    b += "\",\"caller\":";
    append_json_str(b, resolve_caller(ret).c_str());
    return b;
}

void emit_path(const char* api, const wchar_t* path, void* ret) {
    if (in_hook()) return;
    set_in_hook(true);
    std::string b = head(api, ret);
    b += ",\"path\":";
    append_json_str(b, wide_to_utf8(path).c_str());
    emit(b);
    set_in_hook(false);
}

void emit_kv2(const char* api, const char* k1, unsigned long long v1,
              const char* k2, unsigned long long v2, void* ret) {
    if (in_hook()) return;
    set_in_hook(true);
    std::string b = head(api, ret);
    char x[96];
    sprintf_s(x, ",\"%s\":%llu,\"%s\":%llu", k1, v1, k2, v2);
    b += x;
    emit(b);
    set_in_hook(false);
}

void emit_proc(const wchar_t* app, const wchar_t* cmd, void* ret) {
    if (in_hook()) return;
    set_in_hook(true);
    std::string b = head("CreateProcessW", ret);
    b += ",\"app\":";
    append_json_str(b, wide_to_utf8(app ? app : L"").c_str());
    b += ",\"cmdline\":";
    append_json_str(b, wide_to_utf8(cmd ? cmd : L"").c_str());
    emit(b);
    set_in_hook(false);
}

std::string format_endpoint(const sockaddr* name, int len) {
    char buf[80];
    if (name && name->sa_family == AF_INET && len >= (int)sizeof(sockaddr_in)) {
        auto* a = (const sockaddr_in*)name;
        const unsigned char* ip = (const unsigned char*)&a->sin_addr;
        const unsigned char* pr = (const unsigned char*)&a->sin_port;
        sprintf_s(buf, "%u.%u.%u.%u:%u", ip[0], ip[1], ip[2], ip[3],
                  (unsigned)((pr[0] << 8) | pr[1]));
        return std::string(buf);
    }
    if (name && name->sa_family == AF_INET6 && len >= (int)sizeof(sockaddr_in6)) {
        auto* a = (const sockaddr_in6*)name;
        const unsigned char* pr = (const unsigned char*)&a->sin6_port;
        sprintf_s(buf, "[ipv6]:%u", (unsigned)((pr[0] << 8) | pr[1]));
        return std::string(buf);
    }
    return "(non-ip)";
}

void emit_connect(const sockaddr* name, int len, void* ret) {
    if (in_hook()) return;
    set_in_hook(true);
    std::string b = head("connect", ret);
    b += ",\"endpoint\":";
    append_json_str(b, format_endpoint(name, len).c_str());
    emit(b);
    set_in_hook(false);
}

// ---- the hooks -----------------------------------------------------------
typedef HANDLE (WINAPI *CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
                                       DWORD, DWORD, HANDLE);
typedef HMODULE (WINAPI *LoadLibraryW_t)(LPCWSTR);
typedef LPVOID (WINAPI *VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *WriteProcessMemory_t)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef BOOL (WINAPI *CreateProcessW_t)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                                        LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
                                        LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef int (WINAPI *connect_t)(SOCKET, const sockaddr*, int);

CreateFileW_t        o_CreateFileW = nullptr;
LoadLibraryW_t       o_LoadLibraryW = nullptr;
VirtualAlloc_t       o_VirtualAlloc = nullptr;
WriteProcessMemory_t o_WriteProcessMemory = nullptr;
CreateProcessW_t     o_CreateProcessW = nullptr;
connect_t            o_connect = nullptr;

HANDLE WINAPI h_CreateFileW(LPCWSTR name, DWORD access, DWORD share,
                            LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags, HANDLE tmpl) {
    void* ret = _ReturnAddress();
    emit_path("CreateFileW", name, ret);
    return o_CreateFileW(name, access, share, sa, disp, flags, tmpl);
}
HMODULE WINAPI h_LoadLibraryW(LPCWSTR name) {
    void* ret = _ReturnAddress();
    emit_path("LoadLibraryW", name, ret);
    return o_LoadLibraryW(name);
}
LPVOID WINAPI h_VirtualAlloc(LPVOID addr, SIZE_T size, DWORD type, DWORD protect) {
    void* ret = _ReturnAddress();
    emit_kv2("VirtualAlloc", "size", (unsigned long long)size, "protect", protect, ret);
    return o_VirtualAlloc(addr, size, type, protect);
}
BOOL WINAPI h_WriteProcessMemory(HANDLE proc, LPVOID base, LPCVOID buf,
                                 SIZE_T size, SIZE_T* written) {
    void* ret = _ReturnAddress();
    emit_kv2("WriteProcessMemory", "size", (unsigned long long)size,
             "pid", GetProcessId(proc), ret);
    return o_WriteProcessMemory(proc, base, buf, size, written);
}
BOOL WINAPI h_CreateProcessW(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa,
                             LPSECURITY_ATTRIBUTES ta, BOOL inh, DWORD flags,
                             LPVOID env, LPCWSTR dir, LPSTARTUPINFOW si,
                             LPPROCESS_INFORMATION pi) {
    void* ret = _ReturnAddress();
    emit_proc(app, cmd, ret);
    return o_CreateProcessW(app, cmd, pa, ta, inh, flags, env, dir, si, pi);
}
int WINAPI h_connect(SOCKET s, const sockaddr* name, int namelen) {
    void* ret = _ReturnAddress();
    emit_connect(name, namelen, ret);
    return o_connect(s, name, namelen);
}

// ---- IAT patching by resolved address ------------------------------------
void patch_module(HMODULE mod, void* oldf, void* newf) {
    if (mod == g_self || !oldf) return;
    BYTE* base = (BYTE*)mod;
    auto dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    auto nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    auto dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress || !dir.Size) return;
    auto imp = (PIMAGE_IMPORT_DESCRIPTOR)(base + dir.VirtualAddress);
    for (; imp->Name; ++imp) {
        if (!imp->FirstThunk) continue;
        auto thunk = (PIMAGE_THUNK_DATA)(base + imp->FirstThunk);
        for (; thunk->u1.Function; ++thunk) {
            void** slot = (void**)&thunk->u1.Function;
            if (*slot != oldf) continue;
            DWORD old;
            if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &old)) continue;
            g_patches.push_back({slot, *slot});
            *slot = newf;
            VirtualProtect(slot, sizeof(void*), old, &old);
        }
    }
}

void patch_all(void* oldf, void* newf) {
    HMODULE mods[512];
    DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) return;
    DWORD count = needed / sizeof(HMODULE);
    if (count > 512) count = 512;
    for (DWORD i = 0; i < count; ++i) patch_module(mods[i], oldf, newf);
}

void install_hooks() {
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    o_CreateFileW        = (CreateFileW_t)GetProcAddress(k32, "CreateFileW");
    o_LoadLibraryW       = (LoadLibraryW_t)GetProcAddress(k32, "LoadLibraryW");
    o_VirtualAlloc       = (VirtualAlloc_t)GetProcAddress(k32, "VirtualAlloc");
    o_WriteProcessMemory = (WriteProcessMemory_t)GetProcAddress(k32, "WriteProcessMemory");
    o_CreateProcessW     = (CreateProcessW_t)GetProcAddress(k32, "CreateProcessW");
    HMODULE ws2 = GetModuleHandleW(L"ws2_32.dll");
    o_connect = ws2 ? (connect_t)GetProcAddress(ws2, "connect") : nullptr;
    EnterCriticalSection(&g_patch_cs);
    patch_all((void*)o_CreateFileW,        (void*)h_CreateFileW);
    patch_all((void*)o_LoadLibraryW,       (void*)h_LoadLibraryW);
    patch_all((void*)o_VirtualAlloc,       (void*)h_VirtualAlloc);
    patch_all((void*)o_WriteProcessMemory, (void*)h_WriteProcessMemory);
    patch_all((void*)o_CreateProcessW,     (void*)h_CreateProcessW);
    if (o_connect) patch_all((void*)o_connect, (void*)h_connect);
    LeaveCriticalSection(&g_patch_cs);
    char b[80];
    sprintf_s(b, "\"api\":\"__ready__\",\"hooks\":%u", (unsigned)g_patches.size());
    emit(std::string(b));
}

void remove_hooks() {
    EnterCriticalSection(&g_patch_cs);
    for (auto& p : g_patches) {
        DWORD old;
        if (VirtualProtect(p.first, sizeof(void*), PAGE_READWRITE, &old)) {
            *p.first = p.second;
            VirtualProtect(p.first, sizeof(void*), old, &old);
        }
    }
    g_patches.clear();
    LeaveCriticalSection(&g_patch_cs);
}

DWORD WINAPI worker(LPVOID) {
    wchar_t pipe[128];
    swprintf_s(pipe, L"\\\\.\\pipe\\aetheris_agent_%u", GetCurrentProcessId());
    // One session per host attach. The DLL stays resident and loops here, so a
    // re-attach to the same process works (LoadLibrary on an already-loaded DLL
    // never re-runs DllMain). Between sessions we block on g_go (no polling); on
    // stop we un-hook and wait for the next attach. No unload → no unload race.
    for (;;) {
        WaitForSingleObject(g_go, INFINITE);   // host signals a new session
        for (int i = 0; i < 50 && g_pipe == INVALID_HANDLE_VALUE; ++i) {
            HANDLE h = CreateFileW(pipe, GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            if (h != INVALID_HANDLE_VALUE) { g_pipe = h; break; }
            if (GetLastError() == ERROR_PIPE_BUSY) WaitNamedPipeW(pipe, 500);
            else Sleep(100);
        }
        if (g_pipe == INVALID_HANDLE_VALUE) continue;   // host pipe never came up
        ResetEvent(g_stop);
        install_hooks();
        WaitForSingleObject(g_stop, INFINITE);
        remove_hooks();
        EnterCriticalSection(&g_write_cs);
        if (g_pipe != INVALID_HANDLE_VALUE) { CloseHandle(g_pipe); g_pipe = INVALID_HANDLE_VALUE; }
        LeaveCriticalSection(&g_write_cs);
    }
}

}  // namespace

BOOL APIENTRY DllMain(HMODULE mod, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_self = mod;
        DisableThreadLibraryCalls(mod);
        g_tls = TlsAlloc();
        InitializeCriticalSection(&g_write_cs);
        InitializeCriticalSection(&g_patch_cs);
        wchar_t ev[128];
        swprintf_s(ev, L"aetheris_agent_stop_%u", GetCurrentProcessId());
        g_stop = CreateEventW(nullptr, TRUE, FALSE, ev);        // manual-reset
        swprintf_s(ev, L"aetheris_agent_go_%u", GetCurrentProcessId());
        g_go = CreateEventW(nullptr, FALSE, FALSE, ev);         // auto-reset session trigger
        CreateThread(nullptr, 0, worker, nullptr, 0, nullptr);
    } else if (reason == DLL_PROCESS_DETACH) {
        if (g_stop) SetEvent(g_stop);
    }
    return TRUE;
}
