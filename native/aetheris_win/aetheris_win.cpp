// Aetheris Quantum Core — native Win32 engine (dist\aetheris_win.dll).
//
// The C++ half of the native migration: the Win32-heavy forensics that used to
// live in `forensics/processes.py`, `forensics/memvirt.py` (LiveBackend) and
// `storage/handles.py`. C++ rather than Rust because this layer is nothing but
// Windows headers — NtQuerySystemInformation, VirtualQueryEx, NtQueryObject —
// where bindings would be pure overhead.
//
// Called from Python over ctypes. Every export is `extern "C"`, takes a
// caller-owned output buffer with its capacity, and returns the item count or a
// negative error code. Nothing crosses the boundary that the host must free.
//
// The centrepiece is hang-safe handle-name resolution. NtQueryObject blocks
// forever on certain handles (classically a synchronous named pipe with no
// peer), which is why the Python implementation had to scope itself to a
// caller-supplied PID set and skip known-hazardous access masks. Here every
// query runs on a worker the caller can abandon, so a full system-wide sweep is
// safe for the first time. See `query_object` for why the access-mask heuristic
// those implementations rely on is not sufficient, and how abandonment avoids
// the use-after-free that the obvious implementation invites.
//
// Authorized use only — systems you own or are cleared to test.
// winsock2 and ws2tcpip must precede windows.h, which would otherwise pull in
// the incompatible winsock v1 headers (the same ordering agent/ uses).
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <winsvc.h>
#include <iphlpapi.h>
#include <stdint.h>
#include <string.h>
#include <unordered_map>
#include <string>
#include <vector>
#include <mutex>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define AW_EXPORT extern "C" __declspec(dllexport)

// Bumped when the export surface changes at all — a changed signature, or (as
// in v2) added exports. Adding is backward compatible at the C level, but the
// Python binding resolves every symbol up front, so a host expecting v2 against
// a v1 DLL would fail on a missing name. Versioning the addition lets the
// loader refuse it cleanly and fall back instead.
//
//   v1 — processes, memory, handle table
//   v2 — + signature verification, handle search by name, forced close;
//        name/type queries dropped their granted_access parameter when the
//        access-mask heuristic was replaced by an always-bounded worker
//   v3 — + services and driver enumeration, socket tables, privilege enable
//   v4 — + registry subtree snapshot
static const uint32_t AW_ABI_VERSION = 4;

static const int32_t AW_ERR_INVALID   = -1;  // null pointer / nonsense capacity
static const int32_t AW_ERR_UNSUPPORTED = -2;  // an ntdll entry point is missing
static const int32_t AW_ERR_DENIED    = -3;  // the OS refused the query
static const int32_t AW_ERR_TIMEOUT   = -4;  // NtQueryObject had to be abandoned

// Signature verdicts. Embedded and catalog are reported separately because the
// distinction is forensically interesting — most OS binaries carry no embedded
// signature at all and are trusted purely through a signed system catalog — even
// though the Python caller collapses both to "signed".
static const int32_t AW_SIG_NONE     = 0;
static const int32_t AW_SIG_EMBEDDED = 1;
static const int32_t AW_SIG_CATALOG  = 2;

// A registry DWORD that is not present at all. The host maps this back to -1,
// which its label tables render as "unknown" — distinct from the value 0.
static const uint32_t AW_VALUE_ABSENT = 0xFFFFFFFFu;

// --- ntdll -----------------------------------------------------------------

typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
static const NTSTATUS STATUS_INFO_LENGTH_MISMATCH = (NTSTATUS)0xC0000004L;

static const ULONG SystemExtendedHandleInformation = 64;
static const ULONG ObjectNameInformation = 1;
static const ULONG ObjectTypeInformation = 2;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID     Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG     GrantedAccess;
    USHORT    CreatorBackTraceIndex;
    USHORT    ObjectTypeIndex;
    ULONG     HandleAttributes;
    ULONG     Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX;

typedef NTSTATUS(NTAPI* PFN_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* PFN_NtQueryObject)(HANDLE, ULONG, PVOID, ULONG, PULONG);

namespace {

PFN_NtQuerySystemInformation g_NtQuerySystemInformation = nullptr;
PFN_NtQueryObject            g_NtQueryObject = nullptr;
std::once_flag               g_ntdll_once;

void load_ntdll() {
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt) return;
    g_NtQuerySystemInformation =
        (PFN_NtQuerySystemInformation)GetProcAddress(nt, "NtQuerySystemInformation");
    g_NtQueryObject = (PFN_NtQueryObject)GetProcAddress(nt, "NtQueryObject");
}

bool ensure_ntdll() {
    std::call_once(g_ntdll_once, load_ntdll);
    return g_NtQuerySystemInformation != nullptr && g_NtQueryObject != nullptr;
}

void copy_wide(wchar_t* dst, size_t cap, const wchar_t* src, size_t src_chars) {
    if (!dst || cap == 0) return;
    if (!src || src_chars == 0) { dst[0] = L'\0'; return; }
    size_t n = src_chars < (cap - 1) ? src_chars : (cap - 1);
    memcpy(dst, src, n * sizeof(wchar_t));
    dst[n] = L'\0';
}

// --- hang-safe NtQueryObject ----------------------------------------------

// The query helper returns the *decoded string*, never the raw buffer.
//
// This is deliberate and load-bearing. NtQueryObject fills a UNICODE_STRING
// whose Buffer points back into the very buffer it was handed, so copying the
// struct out and dereferencing Buffer afterwards reads memory that has since
// been freed. Extracting here, while the buffer is provably alive, removes
// that whole class of bug rather than patching up pointer arithmetic later.
void extract_unicode(const BYTE* buf, ULONG buf_size, std::wstring& out) {
    out.clear();
    if (buf_size < sizeof(UNICODE_STRING)) return;
    const UNICODE_STRING* us = (const UNICODE_STRING*)buf;
    if (!us->Buffer || us->Length == 0) return;
    // Buffer must point inside the buffer we supplied; anything else means a
    // layout we do not understand, and we would rather report nothing.
    //
    // The length check is written as a subtraction rather than `start +
    // Length > end`: that form can wrap for a pointer near the top of the
    // address space and pass a bounds check it should fail. Nothing observed
    // produces such a pointer — the kernel fills this buffer — but this is the
    // guard standing between a malformed reply and a wild read, so it should
    // not have an arithmetic hole in it.
    const BYTE* start = (const BYTE*)us->Buffer;
    const BYTE* end = buf + buf_size;
    if (start < buf || start >= end) return;
    if ((size_t)us->Length > (size_t)(end - start)) return;
    out.assign(us->Buffer, us->Length / sizeof(wchar_t));
}

// A persistent worker thread that runs every NtQueryObject call.
//
// NtQueryObject can block forever — classically on a synchronous named pipe
// with no peer. The usual mitigation is to recognise those handles by their
// granted-access mask and only guard those. That heuristic is *not sound*: it
// is what the Python implementation used, and a system-wide sweep on a real
// machine still hangs on handles the mask does not match. So every query is
// bounded here rather than only the ones we guessed at.
//
// One thread per query would also be correct but costs more than the query
// itself at six-figure handle counts. Instead a single worker serves the whole
// sweep across a pair of events. If a query does hang, that worker is retired —
// abandoned, never TerminateThread'd, which could leave the heap or loader lock
// held — and a fresh one takes over. Both sides hold a reference and the last
// one out frees the block, so an abandoned worker cannot write into freed
// memory no matter when it finally returns.
struct QWorker {
    LONG     refs;
    LONG     retired;
    HANDLE   req;        // signalled: a request is ready
    HANDLE   done;       // signalled: the result is ready
    HANDLE   target;     // handle to query; owned by the worker once posted
    ULONG    info_class;
    NTSTATUS status;
    ULONG    ret_len;
    BYTE     buf[4096];
};

void worker_release(QWorker* w) {
    if (InterlockedDecrement(&w->refs) == 0) {
        if (w->req) CloseHandle(w->req);
        if (w->done) CloseHandle(w->done);
        free(w);
    }
}

DWORD WINAPI query_worker(LPVOID param) {
    QWorker* w = (QWorker*)param;
    for (;;) {
        WaitForSingleObject(w->req, INFINITE);
        if (InterlockedCompareExchange(&w->retired, 0, 0)) break;
        if (!w->target) break;  // shutdown request

        w->status = g_NtQueryObject(w->target, w->info_class, w->buf,
                                    sizeof(w->buf), &w->ret_len);
        CloseHandle(w->target);
        w->target = nullptr;
        // Re-check after the call. This is the path a hung query eventually
        // returns on, long after the caller gave up and retired us: signalling
        // `done` then would wake nobody, and looping would leak the thread.
        if (InterlockedCompareExchange(&w->retired, 0, 0)) break;
        SetEvent(w->done);
    }
    worker_release(w);
    return 0;
}

QWorker* g_worker = nullptr;
std::mutex g_worker_mutex;  // serialises use of the single worker

// Duplicates we had to abandon, by their handle value *in this process*.
//
// Retiring a worker leaks the duplicate it was querying — unavoidable, since
// closing a handle another thread is blocked inside is not safe. The
// consequence is subtle and compounds: a hang-prone handle from some other
// process is now a handle in *ours*, so the next enumeration of our own
// process finds it, tries to name it, and hangs again. Two sweeps in a row
// measurably degrade: 164 handles and 39 ms became 743 handles and 11.6 s.
// Remembering what we abandoned lets later sweeps step over it.
std::unordered_map<uint64_t, bool> g_abandoned;
// Source handles known to wedge, keyed (pid, handle). Recording only our own
// duplicate stops a sweep tripping over its own debris but still re-duplicates
// the original every time — leaking a fresh handle per sweep, forever.
// Remembering the source means the second sweep never touches it at all.
std::unordered_map<uint64_t, bool> g_hung_sources;
std::mutex g_abandoned_mutex;

uint64_t source_key(uint32_t pid, uint64_t handle) {
    return ((uint64_t)pid << 32) ^ (handle & 0xFFFFFFFFull);
}

void mark_abandoned(HANDLE dup, uint32_t pid, uint64_t source) {
    std::lock_guard<std::mutex> lock(g_abandoned_mutex);
    g_abandoned[(uint64_t)(ULONG_PTR)dup] = true;
    g_hung_sources[source_key(pid, source)] = true;
}

bool was_abandoned(uint64_t handle_value) {
    std::lock_guard<std::mutex> lock(g_abandoned_mutex);
    return g_abandoned.find(handle_value) != g_abandoned.end();
}

bool source_hangs(uint32_t pid, uint64_t handle) {
    std::lock_guard<std::mutex> lock(g_abandoned_mutex);
    return g_hung_sources.find(source_key(pid, handle)) != g_hung_sources.end();
}

// The access mask of a synchronous named pipe with no peer — the handle shape
// that most reliably wedges NtQueryObject. This is *not* a correctness
// mechanism (the bounded worker is; the mask provably misses cases). It is an
// optimisation: skipping the known-bad shape avoids creating the abandoned
// duplicates above, which is what keeps repeat sweeps from degrading.
//
// The cost is a false negative — a handle carrying exactly this access will
// not be named even if it is the file being searched for. The Python
// implementation made the same trade, and a missed row beats a wedged sweep.
static const ULONG AW_PIPE_ACCESS = 0x0012019F;

bool is_hang_prone(ULONG granted_access) {
    return (granted_access & AW_PIPE_ACCESS) == AW_PIPE_ACCESS;
}

QWorker* spawn_worker() {
    QWorker* w = (QWorker*)calloc(1, sizeof(QWorker));
    if (!w) return nullptr;
    w->refs = 2;  // one for us, one for the thread
    w->req = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    w->done = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!w->req || !w->done) { worker_release(w); worker_release(w); return nullptr; }
    HANDLE t = CreateThread(nullptr, 0, query_worker, w, 0, nullptr);
    if (!t) { worker_release(w); worker_release(w); return nullptr; }
    CloseHandle(t);  // the thread keeps itself alive via its reference
    return w;
}

// Run NtQueryObject with a deadline. Takes ownership of `dup` in all paths.
// `pid`/`source` identify where the handle came from, so a wedge can be
// remembered and never duplicated again.
bool query_object(HANDLE dup, ULONG info_class, std::wstring& out, DWORD timeout_ms,
                  uint32_t pid, uint64_t source) {
    if (!ensure_ntdll()) { if (dup) CloseHandle(dup); return false; }
    std::lock_guard<std::mutex> lock(g_worker_mutex);
    if (!g_worker) g_worker = spawn_worker();
    if (!g_worker) { CloseHandle(dup); return false; }

    QWorker* w = g_worker;
    w->target = dup;  // ownership passes to the worker
    w->info_class = info_class;
    w->status = 0;
    w->ret_len = 0;
    SetEvent(w->req);

    if (WaitForSingleObject(w->done, timeout_ms) != WAIT_OBJECT_0) {
        // Stuck inside NtQueryObject and never reusable. It owns `dup` and will
        // close it if it ever returns; we start a fresh worker on next use, and
        // record the leaked duplicate so later sweeps do not trip over it.
        InterlockedExchange(&w->retired, 1);
        mark_abandoned(dup, pid, source);
        worker_release(w);
        g_worker = nullptr;
        return false;
    }
    if (!NT_SUCCESS(w->status)) return false;
    extract_unicode(w->buf, sizeof(w->buf), out);
    return true;
}

// PROCESS_DUP_HANDLE handles, kept open across a sweep. Resolving names one at
// a time otherwise pays an OpenProcess/CloseHandle pair per handle, which
// dominates the cost — and the *negative* entries matter just as much: the
// System process owns six figures of handles and refuses every open, so
// remembering that refusal once saves ~27k failing syscalls per sweep.
//
// A cached handle pins the pid against reuse, so an entry is only as fresh as
// the sweep it belongs to. Call aw_reset_cache() between sweeps.
std::unordered_map<DWORD, HANDLE> g_proc_cache;
std::mutex g_proc_mutex;

// Duplicate a handle out of `pid` into this process. The source process handle
// stays in the cache; only the duplicate is returned to the caller to own.
//
// The cache lookup and the DuplicateHandle are done under one lock. Releasing
// it in between would let aw_reset_cache close the process handle while this
// call is still using it — a narrow window, but the kind that turns into an
// invalid-handle crash only under load. DuplicateHandle is cheap enough that
// serialising it costs far less than the OpenProcess this cache removes.
HANDLE dup_from(DWORD pid, HANDLE remote) {
    std::lock_guard<std::mutex> lock(g_proc_mutex);
    HANDLE hp = nullptr;
    auto it = g_proc_cache.find(pid);
    if (it != g_proc_cache.end()) {
        hp = it->second;  // nullptr = known-denied, remembered so we stop asking
    } else {
        hp = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
        g_proc_cache[pid] = hp;
    }
    if (!hp) return nullptr;
    HANDLE dup = nullptr;
    BOOL ok = DuplicateHandle(hp, remote, GetCurrentProcess(), &dup, 0, FALSE,
                              DUPLICATE_SAME_ACCESS);
    return ok ? dup : nullptr;
}

// Object type names keyed by the table's ObjectTypeIndex. There are a few dozen
// types against a handle table of six figures, so resolving each index once
// turns the type column from the dominant cost into a rounding error.
std::unordered_map<USHORT, std::wstring> g_type_cache;
std::mutex g_type_mutex;

// The catalog admin context is expensive to acquire and the Python
// implementation paid for it once per file. Holding one costs nothing between
// checks and turns a signature sweep over a services or autoruns list from
// hundreds of acquisitions into one. CryptCATAdmin* is not documented as
// thread-safe, so a shared context is used under a lock.
HCATADMIN g_cat_admin = nullptr;
std::mutex g_cat_mutex;

bool catalog_signed(const wchar_t* path) {
    std::lock_guard<std::mutex> lock(g_cat_mutex);
    if (!g_cat_admin && !CryptCATAdminAcquireContext(&g_cat_admin, nullptr, 0)) {
        return false;
    }
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;

    bool found = false;
    DWORD size = 0;
    // First call sizes the hash; it "fails" by design with the length out.
    CryptCATAdminCalcHashFromFileHandle(f, &size, nullptr, 0);
    if (size) {
        std::vector<BYTE> hash(size);
        if (CryptCATAdminCalcHashFromFileHandle(f, &size, hash.data(), 0)) {
            HCATINFO info =
                CryptCATAdminEnumCatalogFromHash(g_cat_admin, hash.data(), size, 0, nullptr);
            if (info) {
                CryptCATAdminReleaseCatalogContext(g_cat_admin, info, 0);
                found = true;
            }
        }
    }
    CloseHandle(f);
    return found;
}

// Snapshot the global handle table into `out`. Shared by the enumeration and
// search exports so the retry-on-growth logic exists once.
bool enum_handles_raw(std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>& out) {
    out.clear();
    if (!ensure_ntdll()) return false;

    ULONG size = 1 << 20;
    BYTE* buf = nullptr;
    NTSTATUS st = STATUS_INFO_LENGTH_MISMATCH;
    // The table grows between the sizing call and the real one, so retry with
    // the length it asks for rather than trusting a single probe.
    for (int attempt = 0; attempt < 8; ++attempt) {
        free(buf);
        buf = (BYTE*)malloc(size);
        if (!buf) return false;
        ULONG needed = 0;
        st = g_NtQuerySystemInformation(SystemExtendedHandleInformation, buf, size, &needed);
        if (st != STATUS_INFO_LENGTH_MISMATCH) break;
        size = (needed > size) ? (needed + (needed / 8) + 65536) : (size * 2);
    }
    if (!NT_SUCCESS(st)) { free(buf); return false; }

    SYSTEM_HANDLE_INFORMATION_EX* info = (SYSTEM_HANDLE_INFORMATION_EX*)buf;
    out.reserve((size_t)info->NumberOfHandles);
    for (ULONG_PTR i = 0; i < info->NumberOfHandles; ++i) {
        out.push_back(info->Handles[i]);
    }
    free(buf);
    return true;
}

}  // namespace

// --- version ---------------------------------------------------------------

AW_EXPORT uint32_t aw_abi_version() { return AW_ABI_VERSION; }

// Drop every cached process handle. Call between sweeps: cached handles pin
// their pids against reuse, so a long-lived cache would slowly answer for
// processes that have since exited.
AW_EXPORT void aw_reset_cache() {
    {
        std::lock_guard<std::mutex> lock(g_proc_mutex);
        for (auto& kv : g_proc_cache) {
            if (kv.second) CloseHandle(kv.second);
        }
        g_proc_cache.clear();
    }
    {
        std::lock_guard<std::mutex> lock(g_cat_mutex);
        if (g_cat_admin) {
            CryptCATAdminReleaseContext(g_cat_admin, 0);
            g_cat_admin = nullptr;
        }
    }
}

// --- processes -------------------------------------------------------------

#pragma pack(push, 8)
struct AwProcess {
    uint32_t pid;
    uint32_t ppid;
    uint32_t threads;
    uint32_t reserved;
    wchar_t  name[260];
    wchar_t  exe[520];
};

struct AwRegion {
    uint64_t base;
    uint64_t size;
    uint32_t state;
    uint32_t protect;
    uint32_t type;
    uint32_t reserved;
};

struct AwHandleRaw {
    uint64_t handle;
    uint64_t object;
    uint32_t pid;
    uint32_t granted_access;
    uint32_t attributes;
    uint16_t type_index;
    uint16_t reserved;
};

// One service or driver. Fixed-width strings keep the whole table crossing the
// boundary in a single copy with nothing for the host to free.
struct AwService {
    wchar_t  name[256];
    wchar_t  display_name[256];
    wchar_t  image_path[520];
    wchar_t  account[256];
    uint32_t service_type;
    uint32_t start_type;
    uint32_t state;          // SERVICE_RUNNING etc; 0 for a registry-only row
};

// One socket. Addresses are raw network-order bytes — 4 used for IPv4, all 16
// for IPv6 — so formatting stays on the Python side where inet_ntop lives.
struct AwConnection {
    uint32_t pid;
    uint32_t state;
    uint32_t family;         // 4 or 6
    uint32_t proto;          // IPPROTO_TCP (6) or IPPROTO_UDP (17)
    uint16_t local_port;     // host order
    uint16_t remote_port;    // host order
    uint8_t  local_addr[16];
    uint8_t  remote_addr[16];
};
#pragma pack(pop)

// Snapshot every visible process. Returns the count written; a table larger
// than `cap` is truncated, so pass a generous buffer.
AW_EXPORT int32_t aw_enum_processes(AwProcess* out, size_t cap) {
    if (!out || cap == 0) return AW_ERR_INVALID;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return AW_ERR_DENIED;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    int32_t n = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if ((size_t)n >= cap) break;
            AwProcess& p = out[n];
            memset(&p, 0, sizeof(p));
            p.pid = pe.th32ProcessID;
            p.ppid = pe.th32ParentProcessID;
            p.threads = pe.cntThreads;
            copy_wide(p.name, 260, pe.szExeFile, wcslen(pe.szExeFile));

            // Full image path is best-effort: it needs a handle, and the
            // protected/system processes that refuse one are exactly the ones
            // a non-elevated session cannot open. An empty path is normal.
            HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (hp) {
                wchar_t path[520];
                DWORD len = 520;
                if (QueryFullProcessImageNameW(hp, 0, path, &len)) {
                    copy_wide(p.exe, 520, path, len);
                }
                CloseHandle(hp);
            }
            ++n;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return n;
}

// DEP/ASLR mitigation state: 0 = off, 1 = on, 2 = unknown.
AW_EXPORT int32_t aw_process_mitigations(uint32_t pid, uint32_t* dep, uint32_t* aslr) {
    if (!dep || !aslr) return AW_ERR_INVALID;
    *dep = 2;
    *aslr = 2;
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h) h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return AW_ERR_DENIED;
    PROCESS_MITIGATION_DEP_POLICY dp{};
    if (GetProcessMitigationPolicy(h, ProcessDEPPolicy, &dp, sizeof(dp))) {
        *dep = dp.Enable ? 1u : 0u;
    }
    PROCESS_MITIGATION_ASLR_POLICY ap{};
    if (GetProcessMitigationPolicy(h, ProcessASLRPolicy, &ap, sizeof(ap))) {
        *aslr = ap.EnableBottomUpRandomization ? 1u : 0u;
    }
    CloseHandle(h);
    return 0;
}

// --- process memory --------------------------------------------------------

// Upper bound of the x64 user address space, and a hard cap on iterations so a
// pathological map can never spin — both carried over from the Python original.
static const uint64_t AW_USER_SPACE_MAX = 0x00007FFFFFFF0000ULL;
static const int      AW_REGION_GUARD = 200000;

AW_EXPORT int32_t aw_memory_map(uint32_t pid, AwRegion* out, size_t cap) {
    if (!out || cap == 0) return AW_ERR_INVALID;
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return AW_ERR_DENIED;

    int32_t n = 0;
    uint64_t addr = 0;
    int guard = 0;
    MEMORY_BASIC_INFORMATION mbi{};
    while (addr < AW_USER_SPACE_MAX && guard < AW_REGION_GUARD && (size_t)n < cap) {
        ++guard;
        if (VirtualQueryEx(h, (LPCVOID)addr, &mbi, sizeof(mbi)) != sizeof(mbi)) break;
        uint64_t base = (uint64_t)mbi.BaseAddress;
        uint64_t size = (uint64_t)mbi.RegionSize;
        if (size == 0) break;
        if (mbi.State != MEM_FREE) {
            AwRegion& r = out[n++];
            r.base = base;
            r.size = size;
            r.state = mbi.State;
            r.protect = mbi.Protect;
            r.type = mbi.Type;
            r.reserved = 0;
        }
        addr = base + size;
    }
    CloseHandle(h);
    return n;
}

// Read `size` bytes at `address`. Returns bytes read, or a negative code.
// A short read is success: ReadProcessMemory fills what it can before hitting
// an unreadable page, and a partial region is still evidence.
AW_EXPORT int64_t aw_read_memory(uint32_t pid, uint64_t address, uint8_t* out, size_t size) {
    if (!out || size == 0) return AW_ERR_INVALID;
    HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h) return AW_ERR_DENIED;
    SIZE_T got = 0;
    BOOL ok = ReadProcessMemory(h, (LPCVOID)address, out, size, &got);
    CloseHandle(h);
    if (!ok && got == 0) return AW_ERR_DENIED;
    return (int64_t)got;
}

// --- handles ---------------------------------------------------------------

// Enumerate the global handle table. `pid_filter` of 0 means every process —
// the system-wide view the Python implementation had to avoid. Returns the
// count written; if the table is larger than `cap` the extra entries are
// dropped, so pass a generous buffer (six figures is normal).
AW_EXPORT int32_t aw_enum_handles(uint32_t pid_filter, AwHandleRaw* out, size_t cap) {
    if (!out || cap == 0) return AW_ERR_INVALID;
    if (!ensure_ntdll()) return AW_ERR_UNSUPPORTED;

    std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> table;
    if (!enum_handles_raw(table)) return AW_ERR_DENIED;

    int32_t n = 0;
    for (const auto& e : table) {
        if ((size_t)n >= cap) break;
        if (pid_filter && (uint32_t)e.UniqueProcessId != pid_filter) continue;
        AwHandleRaw& r = out[n++];
        r.handle = (uint64_t)e.HandleValue;
        r.object = (uint64_t)e.Object;
        r.pid = (uint32_t)e.UniqueProcessId;
        r.granted_access = e.GrantedAccess;
        r.attributes = e.HandleAttributes;
        r.type_index = e.ObjectTypeIndex;
        r.reserved = 0;
    }
    return n;
}

// Find every handle whose object name equals `target` (compared
// case-insensitively; pass an NT device path such as
// \Device\HarddiskVolume3\dir\file).
//
// The whole search runs here rather than in the caller. Resolving names from
// Python meant one FFI round-trip per handle across a table of six figures;
// doing the loop natively means one call, and the pid filter plus the
// known-hazardous access mask are applied before any name query is attempted.
AW_EXPORT int32_t aw_find_handles_by_name(const wchar_t* target,
                                          const uint32_t* pids, size_t pid_count,
                                          AwHandleRaw* out, size_t cap,
                                          uint32_t timeout_ms) {
    if (!target || !out || cap == 0) return AW_ERR_INVALID;
    if (!ensure_ntdll()) return AW_ERR_UNSUPPORTED;

    std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> table;
    if (!enum_handles_raw(table)) return AW_ERR_DENIED;

    int32_t n = 0;
    std::wstring name;
    for (const auto& e : table) {
        if ((size_t)n >= cap) break;
        uint32_t pid = (uint32_t)e.UniqueProcessId;
        if (pids && pid_count) {
            bool wanted = false;
            for (size_t i = 0; i < pid_count; ++i) {
                if (pids[i] == pid) { wanted = true; break; }
            }
            if (!wanted) continue;
        }
        // Step over the known-wedging shape, over handles a previous sweep
        // already learned will hang, and over duplicates abandoned into this
        // process. Together these keep repeat sweeps flat instead of each one
        // leaking a fresh handle and paying the timeout again.
        if (is_hang_prone(e.GrantedAccess)) continue;
        if (source_hangs(pid, (uint64_t)e.HandleValue)) continue;
        if (pid == GetCurrentProcessId() && was_abandoned((uint64_t)e.HandleValue)) continue;

        HANDLE dup = dup_from(pid, (HANDLE)e.HandleValue);
        if (!dup) continue;
        if (!query_object(dup, ObjectNameInformation, name, timeout_ms, pid,
                          (uint64_t)e.HandleValue))
            continue;
        if (name.empty()) continue;
        if (_wcsicmp(name.c_str(), target) != 0) continue;

        AwHandleRaw& r = out[n++];
        r.handle = (uint64_t)e.HandleValue;
        r.object = (uint64_t)e.Object;
        r.pid = pid;
        r.granted_access = e.GrantedAccess;
        r.attributes = e.HandleAttributes;
        r.type_index = e.ObjectTypeIndex;
        r.reserved = 0;
    }
    return n;
}

// Force a handle shut inside another process. Destructive by nature — the
// caller (storage.unlock) is responsible for the critical-process and
// protected-path guardrails before this is reached.
AW_EXPORT int32_t aw_close_handle_in_process(uint32_t pid, uint64_t handle) {
    HANDLE hp = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
    if (!hp) return AW_ERR_DENIED;
    BOOL ok = DuplicateHandle(hp, (HANDLE)(ULONG_PTR)handle, nullptr, nullptr, 0, FALSE,
                              DUPLICATE_CLOSE_SOURCE);
    CloseHandle(hp);
    return ok ? 0 : AW_ERR_DENIED;
}

// --- code signing ----------------------------------------------------------

// Authenticode verdict for a file: AW_SIG_EMBEDDED, AW_SIG_CATALOG,
// AW_SIG_NONE, or AW_ERR_INVALID when the path is unusable.
//
// Matches the Python original's semantics exactly, including the part that
// looks like a bug and is not: a catalog lookup that *fails* (unreadable file,
// no catalog service) reports "not signed" rather than "unknown", because the
// embedded check already came back negative.
AW_EXPORT int32_t aw_verify_signature(const wchar_t* path) {
    if (!path || !*path) return AW_ERR_INVALID;
    DWORD attrs = GetFileAttributesW(path);
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        return AW_ERR_INVALID;
    }

    WINTRUST_FILE_INFO fi{};
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = path;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wd{};
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_SAFER_FLAG;

    LONG rc = WinVerifyTrust(nullptr, &action, &wd);
    // The verify allocates state that must be released with a second call, or
    // the provider leaks for the life of the process.
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &wd);

    if (rc == ERROR_SUCCESS) return AW_SIG_EMBEDDED;
    return catalog_signed(path) ? AW_SIG_CATALOG : AW_SIG_NONE;
}

// Resolve an object's name. The query runs on the shared worker bounded by
// `timeout_ms`; on expiry it is abandoned and AW_ERR_TIMEOUT returned, leaving
// the row unnamed rather than hanging the caller.
AW_EXPORT int32_t aw_handle_object_name(uint32_t pid, uint64_t handle, wchar_t* out,
                                        size_t cap, uint32_t timeout_ms) {
    if (!out || cap == 0) return AW_ERR_INVALID;
    out[0] = L'\0';
    if (!ensure_ntdll()) return AW_ERR_UNSUPPORTED;

    // A duplicate a previous query had to abandon lives on in this process and
    // would wedge again; report it rather than spending the timeout re-learning
    // that. This is what stops repeat sweeps compounding.
    if (source_hangs(pid, handle)) return AW_ERR_TIMEOUT;
    if (pid == GetCurrentProcessId() && was_abandoned(handle)) return AW_ERR_TIMEOUT;

    HANDLE dup = dup_from(pid, (HANDLE)(ULONG_PTR)handle);
    if (!dup) return AW_ERR_DENIED;

    std::wstring name;
    if (!query_object(dup, ObjectNameInformation, name, timeout_ms, pid, handle)) {
        return AW_ERR_TIMEOUT;
    }
    if (name.empty()) return 0;  // unnamed object — normal
    copy_wide(out, cap, name.c_str(), name.size());
    return (int32_t)wcslen(out);
}

// Resolve an ObjectTypeIndex to its type name, caching by index.
AW_EXPORT int32_t aw_handle_type_name(uint32_t pid, uint64_t handle, uint16_t type_index,
                                      wchar_t* out, size_t cap, uint32_t timeout_ms) {
    if (!out || cap == 0) return AW_ERR_INVALID;
    out[0] = L'\0';
    {
        std::lock_guard<std::mutex> lock(g_type_mutex);
        auto it = g_type_cache.find(type_index);
        if (it != g_type_cache.end()) {
            copy_wide(out, cap, it->second.c_str(), it->second.size());
            return (int32_t)wcslen(out);
        }
    }
    if (!ensure_ntdll()) return AW_ERR_UNSUPPORTED;
    HANDLE dup = dup_from(pid, (HANDLE)(ULONG_PTR)handle);
    if (!dup) return AW_ERR_DENIED;

    // TypeName leads PUBLIC_OBJECT_TYPE_INFORMATION, so the same extraction
    // applies to both information classes.
    std::wstring name;
    if (!query_object(dup, ObjectTypeInformation, name, timeout_ms, pid, handle)) {
        return AW_ERR_TIMEOUT;
    }
    if (name.empty()) return 0;
    {
        std::lock_guard<std::mutex> lock(g_type_mutex);
        g_type_cache[type_index] = name;
    }
    copy_wide(out, cap, name.c_str(), name.size());
    return (int32_t)wcslen(out);
}

// For a Process-type handle, the pid it points at — 0 if it cannot be
// determined. This is what turns the handle table into a detection: a handle
// into lsass.exe held by something that has no business holding one is the
// classic credential-theft tell, and a Process object has no *name* to report,
// only a target.
AW_EXPORT uint32_t aw_handle_process_target(uint32_t pid, uint64_t handle) {
    HANDLE dup = dup_from(pid, (HANDLE)(ULONG_PTR)handle);
    if (!dup) return 0;
    DWORD target = GetProcessId(dup);
    CloseHandle(dup);
    return (uint32_t)target;
}

// --- services and drivers --------------------------------------------------

namespace {

// Read one REG_SZ / REG_EXPAND_SZ / REG_DWORD value from an open key.
bool reg_str(HKEY key, const wchar_t* value, wchar_t* out, DWORD out_chars) {
    if (out && out_chars) out[0] = L'\0';
    DWORD type = 0, cb = out_chars * sizeof(wchar_t);
    if (RegQueryValueExW(key, value, nullptr, &type, (LPBYTE)out, &cb) != ERROR_SUCCESS) {
        return false;
    }
    if (type != REG_SZ && type != REG_EXPAND_SZ) {
        if (out && out_chars) out[0] = L'\0';
        return false;
    }
    // RegQueryValueExW does not guarantee termination when the stored value
    // was written without one — a real occurrence in service keys.
    DWORD chars = cb / sizeof(wchar_t);
    if (chars >= out_chars) chars = out_chars - 1;
    out[chars] = L'\0';
    return true;
}

bool reg_dword(HKEY key, const wchar_t* value, DWORD* out) {
    DWORD type = 0, data = 0, cb = sizeof(data);
    if (RegQueryValueExW(key, value, nullptr, &type, (LPBYTE)&data, &cb) != ERROR_SUCCESS) {
        return false;
    }
    if (type != REG_DWORD) return false;
    *out = data;
    return true;
}

}  // namespace

// Enumerate win32 services through the SCM, with each one's configuration.
//
// The Python path went through psutil, which issues QueryServiceConfig per
// service from Python. Here EnumServicesStatusExW returns the whole live table
// in one buffer and the per-service config query stays native, so the caller
// pays one FFI call for the lot.
AW_EXPORT int32_t aw_enum_services(AwService* out, size_t cap) {
    if (!out || cap == 0) return AW_ERR_INVALID;
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return AW_ERR_DENIED;

    DWORD needed = 0, count = 0, resume = 0;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                          nullptr, 0, &needed, &count, &resume, nullptr);
    if (needed == 0) { CloseServiceHandle(scm); return 0; }

    std::vector<BYTE> buf(needed);
    if (!EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                               buf.data(), needed, &needed, &count, &resume, nullptr)) {
        CloseServiceHandle(scm);
        return AW_ERR_DENIED;
    }

    ENUM_SERVICE_STATUS_PROCESSW* svc = (ENUM_SERVICE_STATUS_PROCESSW*)buf.data();
    int32_t n = 0;
    std::vector<BYTE> cfgbuf(8192);
    for (DWORD i = 0; i < count && (size_t)n < cap; ++i) {
        AwService& r = out[n];
        memset(&r, 0, sizeof(r));
        copy_wide(r.name, 256, svc[i].lpServiceName,
                  svc[i].lpServiceName ? wcslen(svc[i].lpServiceName) : 0);
        copy_wide(r.display_name, 256, svc[i].lpDisplayName,
                  svc[i].lpDisplayName ? wcslen(svc[i].lpDisplayName) : 0);
        r.state = svc[i].ServiceStatusProcess.dwCurrentState;
        r.service_type = svc[i].ServiceStatusProcess.dwServiceType;
        r.start_type = SERVICE_DEMAND_START;  // corrected below when readable

        SC_HANDLE h = OpenServiceW(scm, svc[i].lpServiceName, SERVICE_QUERY_CONFIG);
        if (h) {
            DWORD cb = 0;
            QueryServiceConfigW(h, nullptr, 0, &cb);
            if (cb > cfgbuf.size()) cfgbuf.resize(cb);
            if (cb && QueryServiceConfigW(h, (QUERY_SERVICE_CONFIGW*)cfgbuf.data(),
                                          (DWORD)cfgbuf.size(), &cb)) {
                QUERY_SERVICE_CONFIGW* cfg = (QUERY_SERVICE_CONFIGW*)cfgbuf.data();
                r.start_type = cfg->dwStartType;
                r.service_type = cfg->dwServiceType;
                if (cfg->lpBinaryPathName) {
                    copy_wide(r.image_path, 520, cfg->lpBinaryPathName,
                              wcslen(cfg->lpBinaryPathName));
                }
                if (cfg->lpServiceStartName) {
                    copy_wide(r.account, 256, cfg->lpServiceStartName,
                              wcslen(cfg->lpServiceStartName));
                }
            }
            CloseServiceHandle(h);
        }
        ++n;
    }
    CloseServiceHandle(scm);
    return n;
}

// Enumerate driver entries from HKLM\System\CurrentControlSet\Services.
//
// This is the batch that most needed moving: the Python version opened the
// Services key, walked ~700 subkeys, and issued five QueryValueEx calls per
// subkey through `winreg` — roughly 4,900 registry round-trips, each crossing
// into Python. Here it is one call. `state` is left 0; whether a driver is
// loaded is decided by the caller against the loaded-module list.
AW_EXPORT int32_t aw_enum_driver_services(AwService* out, size_t cap) {
    if (!out || cap == 0) return AW_ERR_INVALID;
    HKEY services = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Services", 0,
                      KEY_READ, &services) != ERROR_SUCCESS) {
        return AW_ERR_DENIED;
    }

    int32_t n = 0;
    wchar_t name[256];
    for (DWORD i = 0; (size_t)n < cap; ++i) {
        DWORD name_len = 256;
        LONG rc = RegEnumKeyExW(services, i, name, &name_len,
                                nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) continue;

        HKEY key = nullptr;
        if (RegOpenKeyExW(services, name, 0, KEY_READ, &key) != ERROR_SUCCESS) continue;

        // Absent must stay distinguishable from 0: a key with no Start value
        // is "unknown", not SERVICE_BOOT_START. Sentinel, not a default.
        DWORD stype = 0, start = AW_VALUE_ABSENT;
        bool has_type = reg_dword(key, L"Type", &stype);
        reg_dword(key, L"Start", &start);
        if (has_type) {
            AwService& r = out[n];
            memset(&r, 0, sizeof(r));
            copy_wide(r.name, 256, name, name_len);
            r.service_type = stype;
            r.start_type = start;
            r.state = 0;
            reg_str(key, L"ImagePath", r.image_path, 520);
            reg_str(key, L"DisplayName", r.display_name, 256);
            reg_str(key, L"ObjectName", r.account, 256);
            ++n;
        }
        RegCloseKey(key);
    }
    RegCloseKey(services);
    return n;
}

// --- registry snapshot -----------------------------------------------------

namespace {

const HKEY AW_HIVES[] = {
    HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS,
};

void put_u32(std::vector<uint8_t>& b, uint32_t v) {
    b.insert(b.end(), (uint8_t*)&v, (uint8_t*)&v + 4);
}

void put_bytes(std::vector<uint8_t>& b, const void* p, size_t n) {
    if (n) b.insert(b.end(), (const uint8_t*)p, (const uint8_t*)p + n);
}

// Append one key's values to the stream, then recurse into its subkeys.
//
// Stream layout, little-endian throughout, no padding:
//   per key:   u32 key_bytes, u32 value_count, <key utf-16>
//   per value: u32 name_bytes, u32 type, u32 data_bytes, <name utf-16><data>
//
// The key path is written once per key rather than once per value — a key with
// forty values would otherwise repeat its path forty times, and paths dominate
// the byte count on a deep tree.
void reg_walk(HKEY hive, const std::wstring& path, uint32_t depth, uint32_t max_depth,
              std::vector<uint8_t>& out) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(hive, path.empty() ? nullptr : path.c_str(), 0,
                      KEY_READ, &key) != ERROR_SUCCESS) {
        return;
    }

    // Size the key up front so the value loop does not reallocate per entry.
    DWORD subkeys = 0, values = 0, max_name = 0, max_data = 0;
    RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, &subkeys, nullptr, nullptr,
                     &values, &max_name, &max_data, nullptr, nullptr);

    std::vector<wchar_t> name(max_name + 2);
    std::vector<uint8_t> data(max_data + 2);

    size_t count_at = out.size() + 4;  // patched once the real count is known
    put_u32(out, (uint32_t)(path.size() * sizeof(wchar_t)));
    put_u32(out, 0);
    put_bytes(out, path.data(), path.size() * sizeof(wchar_t));

    uint32_t written = 0;
    for (DWORD i = 0; i < values; ++i) {
        DWORD name_len = (DWORD)name.size();
        DWORD data_len = (DWORD)data.size();
        DWORD type = 0;
        LONG rc = RegEnumValueW(key, i, name.data(), &name_len, nullptr, &type,
                                data.data(), &data_len);
        if (rc == ERROR_MORE_DATA) {
            // The key grew between the sizing call and now.
            name.resize(name_len + 2);
            data.resize(data_len + 2);
            name_len = (DWORD)name.size();
            data_len = (DWORD)data.size();
            rc = RegEnumValueW(key, i, name.data(), &name_len, nullptr, &type,
                               data.data(), &data_len);
        }
        if (rc != ERROR_SUCCESS) continue;
        put_u32(out, name_len * (uint32_t)sizeof(wchar_t));
        put_u32(out, type);
        put_u32(out, data_len);
        put_bytes(out, name.data(), name_len * sizeof(wchar_t));
        put_bytes(out, data.data(), data_len);
        ++written;
    }
    memcpy(out.data() + count_at, &written, 4);

    if (depth < max_depth) {
        std::vector<std::wstring> children;
        wchar_t sub[256];
        for (DWORD j = 0;; ++j) {
            DWORD len = 256;
            LONG rc = RegEnumKeyExW(key, j, sub, &len, nullptr, nullptr, nullptr, nullptr);
            if (rc == ERROR_NO_MORE_ITEMS) break;
            if (rc != ERROR_SUCCESS) continue;
            children.emplace_back(sub, len);
        }
        // Enumerate fully before recursing: holding an open key across the
        // whole subtree walk would pin a handle per level of depth.
        RegCloseKey(key);
        key = nullptr;
        for (const auto& child : children) {
            reg_walk(hive, path.empty() ? child : path + L"\\" + child,
                     depth + 1, max_depth, out);
        }
    }
    if (key) RegCloseKey(key);
}

}  // namespace

// Snapshot a registry subtree into a packed stream.
//
// `hive` indexes AW_HIVES (0 HKCR, 1 HKCU, 2 HKLM, 3 HKU). Returns the byte
// count and sets `*out_ptr` to a buffer the caller must release with
// aw_reg_free. This is the one export that hands back memory rather than
// filling a caller buffer: the size is not knowable without doing the walk,
// and the walk is the entire cost — a size-then-fill protocol would do it
// twice.
//
// Only raw typed data crosses the boundary, never a rendered string. The host
// formats values with Python's own repr(), because snapshots are saved to disk
// and compared across app versions, so the rendering must stay byte-identical
// to what the pure-Python path produces.
AW_EXPORT int64_t aw_reg_snapshot(uint32_t hive, const wchar_t* subkey,
                                  uint32_t max_depth, uint8_t** out_ptr) {
    if (!out_ptr) return AW_ERR_INVALID;
    *out_ptr = nullptr;
    if (hive >= (sizeof(AW_HIVES) / sizeof(AW_HIVES[0])) || !subkey) {
        return AW_ERR_INVALID;
    }
    std::vector<uint8_t> buf;
    buf.reserve(1 << 20);
    reg_walk(AW_HIVES[hive], std::wstring(subkey), 0, max_depth, buf);
    if (buf.empty()) return 0;

    uint8_t* mem = (uint8_t*)malloc(buf.size());
    if (!mem) return AW_ERR_DENIED;
    memcpy(mem, buf.data(), buf.size());
    *out_ptr = mem;
    return (int64_t)buf.size();
}

// Release a buffer from aw_reg_snapshot. Freeing it on the host side would
// cross allocators; it must come back here.
AW_EXPORT void aw_reg_free(uint8_t* p) { free(p); }

// --- sockets ---------------------------------------------------------------

// Every TCP and UDP socket with its owning pid, over both address families.
// Four IP-Helper tables in one call; addresses come back as raw bytes so the
// caller formats them with inet_ntop rather than us guessing a text form.
AW_EXPORT int32_t aw_enum_connections(AwConnection* out, size_t cap) {
    if (!out || cap == 0) return AW_ERR_INVALID;
    int32_t n = 0;
    std::vector<BYTE> buf;

    auto fetch = [&](bool tcp, ULONG family) -> BYTE* {
        ULONG size = 0;
        DWORD rc = tcp ? GetExtendedTcpTable(nullptr, &size, FALSE, family,
                                             TCP_TABLE_OWNER_PID_ALL, 0)
                       : GetExtendedUdpTable(nullptr, &size, FALSE, family,
                                             UDP_TABLE_OWNER_PID, 0);
        if (rc != ERROR_INSUFFICIENT_BUFFER || size == 0) return nullptr;
        buf.assign(size, 0);
        rc = tcp ? GetExtendedTcpTable(buf.data(), &size, FALSE, family,
                                       TCP_TABLE_OWNER_PID_ALL, 0)
                 : GetExtendedUdpTable(buf.data(), &size, FALSE, family,
                                       UDP_TABLE_OWNER_PID, 0);
        return rc == NO_ERROR ? buf.data() : nullptr;
    };

    if (BYTE* p = fetch(true, AF_INET)) {
        MIB_TCPTABLE_OWNER_PID* t = (MIB_TCPTABLE_OWNER_PID*)p;
        for (DWORD i = 0; i < t->dwNumEntries && (size_t)n < cap; ++i) {
            AwConnection& r = out[n++];
            memset(&r, 0, sizeof(r));
            r.pid = t->table[i].dwOwningPid;
            r.state = t->table[i].dwState;
            r.family = 4;
            r.proto = IPPROTO_TCP;
            r.local_port = ntohs((u_short)t->table[i].dwLocalPort);
            r.remote_port = ntohs((u_short)t->table[i].dwRemotePort);
            memcpy(r.local_addr, &t->table[i].dwLocalAddr, 4);
            memcpy(r.remote_addr, &t->table[i].dwRemoteAddr, 4);
        }
    }
    if (BYTE* p = fetch(true, AF_INET6)) {
        MIB_TCP6TABLE_OWNER_PID* t = (MIB_TCP6TABLE_OWNER_PID*)p;
        for (DWORD i = 0; i < t->dwNumEntries && (size_t)n < cap; ++i) {
            AwConnection& r = out[n++];
            memset(&r, 0, sizeof(r));
            r.pid = t->table[i].dwOwningPid;
            r.state = t->table[i].dwState;
            r.family = 6;
            r.proto = IPPROTO_TCP;
            r.local_port = ntohs((u_short)t->table[i].dwLocalPort);
            r.remote_port = ntohs((u_short)t->table[i].dwRemotePort);
            memcpy(r.local_addr, t->table[i].ucLocalAddr, 16);
            memcpy(r.remote_addr, t->table[i].ucRemoteAddr, 16);
        }
    }
    if (BYTE* p = fetch(false, AF_INET)) {
        MIB_UDPTABLE_OWNER_PID* t = (MIB_UDPTABLE_OWNER_PID*)p;
        for (DWORD i = 0; i < t->dwNumEntries && (size_t)n < cap; ++i) {
            AwConnection& r = out[n++];
            memset(&r, 0, sizeof(r));
            r.pid = t->table[i].dwOwningPid;
            r.family = 4;
            r.proto = IPPROTO_UDP;
            r.local_port = ntohs((u_short)t->table[i].dwLocalPort);
            memcpy(r.local_addr, &t->table[i].dwLocalAddr, 4);
        }
    }
    if (BYTE* p = fetch(false, AF_INET6)) {
        MIB_UDP6TABLE_OWNER_PID* t = (MIB_UDP6TABLE_OWNER_PID*)p;
        for (DWORD i = 0; i < t->dwNumEntries && (size_t)n < cap; ++i) {
            AwConnection& r = out[n++];
            memset(&r, 0, sizeof(r));
            r.pid = t->table[i].dwOwningPid;
            r.family = 6;
            r.proto = IPPROTO_UDP;
            r.local_port = ntohs((u_short)t->table[i].dwLocalPort);
            memcpy(r.local_addr, t->table[i].ucLocalAddr, 16);
        }
    }
    return n;
}

// --- privileges ------------------------------------------------------------

// Enable a named privilege on this process token.
// 0 = enabled, 1 = the token does not hold it (ERROR_NOT_ALL_ASSIGNED),
// AW_ERR_DENIED = the call failed, AW_ERR_INVALID = bad name.
AW_EXPORT int32_t aw_enable_privilege(const wchar_t* name) {
    if (!name || !*name) return AW_ERR_INVALID;
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return AW_ERR_DENIED;
    }
    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, name, &luid)) {
        CloseHandle(token);
        return AW_ERR_DENIED;
    }
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, 0, nullptr, nullptr);
    // AdjustTokenPrivileges reports success even when it changed nothing, so
    // the real answer is in GetLastError.
    DWORD err = GetLastError();
    CloseHandle(token);
    if (!ok) return AW_ERR_DENIED;
    return err == ERROR_NOT_ALL_ASSIGNED ? 1 : 0;
}

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID) { return TRUE; }
