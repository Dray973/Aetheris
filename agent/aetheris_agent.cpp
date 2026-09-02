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
// Scope (v1): catches statically-imported calls (the common case). Calls made
// through a hand-resolved GetProcAddress pointer are not covered — that needs
// inline hooking (a later iteration). Honest by design.
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <utility>

#pragma comment(lib, "psapi.lib")

namespace {

HMODULE g_self = nullptr;          // our own module — never patch it
HANDLE  g_pipe = INVALID_HANDLE_VALUE;
HANDLE  g_stop = nullptr;          // host sets this to request un-hook
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

void emit_path(const char* api, const wchar_t* path) {
    if (in_hook()) return;
    set_in_hook(true);
    std::string b = "\"api\":\"";
    b += api;
    b += "\",\"path\":";
    append_json_str(b, wide_to_utf8(path).c_str());
    emit(b);
    set_in_hook(false);
}

void emit_kv2(const char* api, const char* k1, unsigned long long v1,
              const char* k2, unsigned long long v2) {
    if (in_hook()) return;
    set_in_hook(true);
    char b[160];
    sprintf_s(b, "\"api\":\"%s\",\"%s\":%llu,\"%s\":%llu", api, k1, v1, k2, v2);
    emit(std::string(b));
    set_in_hook(false);
}

// ---- the hooks -----------------------------------------------------------
typedef HANDLE (WINAPI *CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
                                       DWORD, DWORD, HANDLE);
typedef HMODULE (WINAPI *LoadLibraryW_t)(LPCWSTR);
typedef LPVOID (WINAPI *VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *WriteProcessMemory_t)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);

CreateFileW_t        o_CreateFileW = nullptr;
LoadLibraryW_t       o_LoadLibraryW = nullptr;
VirtualAlloc_t       o_VirtualAlloc = nullptr;
WriteProcessMemory_t o_WriteProcessMemory = nullptr;

HANDLE WINAPI h_CreateFileW(LPCWSTR name, DWORD access, DWORD share,
                            LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags, HANDLE tmpl) {
    emit_path("CreateFileW", name);
    return o_CreateFileW(name, access, share, sa, disp, flags, tmpl);
}
HMODULE WINAPI h_LoadLibraryW(LPCWSTR name) {
    emit_path("LoadLibraryW", name);
    return o_LoadLibraryW(name);
}
LPVOID WINAPI h_VirtualAlloc(LPVOID addr, SIZE_T size, DWORD type, DWORD protect) {
    emit_kv2("VirtualAlloc", "size", (unsigned long long)size, "protect", protect);
    return o_VirtualAlloc(addr, size, type, protect);
}
BOOL WINAPI h_WriteProcessMemory(HANDLE proc, LPVOID base, LPCVOID buf,
                                 SIZE_T size, SIZE_T* written) {
    emit_kv2("WriteProcessMemory", "size", (unsigned long long)size,
             "pid", GetProcessId(proc));
    return o_WriteProcessMemory(proc, base, buf, size, written);
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
    EnterCriticalSection(&g_patch_cs);
    patch_all((void*)o_CreateFileW,        (void*)h_CreateFileW);
    patch_all((void*)o_LoadLibraryW,       (void*)h_LoadLibraryW);
    patch_all((void*)o_VirtualAlloc,       (void*)h_VirtualAlloc);
    patch_all((void*)o_WriteProcessMemory, (void*)h_WriteProcessMemory);
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
    for (int i = 0; i < 50 && g_pipe == INVALID_HANDLE_VALUE; ++i) {
        HANDLE h = CreateFileW(pipe, GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) { g_pipe = h; break; }
        if (GetLastError() != ERROR_PIPE_BUSY) Sleep(100);
        else WaitNamedPipeW(pipe, 500);
    }
    if (g_pipe == INVALID_HANDLE_VALUE) return 0;   // host not listening; stay inert
    install_hooks();
    WaitForSingleObject(g_stop, INFINITE);
    remove_hooks();
    EnterCriticalSection(&g_write_cs);
    if (g_pipe != INVALID_HANDLE_VALUE) { CloseHandle(g_pipe); g_pipe = INVALID_HANDLE_VALUE; }
    LeaveCriticalSection(&g_write_cs);
    return 0;
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
        g_stop = CreateEventW(nullptr, TRUE, FALSE, ev);
        CreateThread(nullptr, 0, worker, nullptr, 0, nullptr);
    } else if (reason == DLL_PROCESS_DETACH) {
        if (g_stop) SetEvent(g_stop);
    }
    return TRUE;
}
