// Unit tests for the Aetheris native Win32 engine.
//
//     powershell -ExecutionPolicy Bypass -File native\aetheris_win\build.ps1 -Tests
//
// The engine's helpers live in anonymous namespaces so they stay private to the
// DLL, so this translation unit #includes the implementation rather than
// linking against it. That keeps the production build free of test code — no
// self-test export ships in aetheris_win.dll — at the cost of compiling the
// implementation twice, which for one file is not worth avoiding.
//
// The focus is the pure helpers and the invariants that Python cannot observe:
// buffer truncation, bounds rejection, and the stream layout the host decodes
// by offset. The Win32 surface itself is covered by the Python parity suites,
// which can diff it against winreg / psutil / the SCM on a live machine.
#include "aetheris_win.cpp"

#include <stdio.h>

namespace {

int g_failures = 0;
int g_checks = 0;

void check(bool ok, const char* what, int line) {
    ++g_checks;
    if (!ok) {
        ++g_failures;
        printf("  FAIL (line %d): %s\n", line, what);
    }
}

#define CHECK(expr) check((expr), #expr, __LINE__)

// --- copy_wide: the buffer-truncation guard --------------------------------

void test_copy_wide() {
    wchar_t out[8];

    copy_wide(out, 8, L"abc", 3);
    CHECK(wcscmp(out, L"abc") == 0);

    // Exactly filling the buffer must still leave room for the terminator.
    copy_wide(out, 8, L"abcdefghij", 10);
    CHECK(wcslen(out) == 7);
    CHECK(out[7] == L'\0');

    // A one-char buffer can hold only the terminator.
    wchar_t tiny[1];
    copy_wide(tiny, 1, L"abc", 3);
    CHECK(tiny[0] == L'\0');

    // Degenerate inputs must not write anywhere.
    copy_wide(nullptr, 8, L"abc", 3);
    copy_wide(out, 0, L"abc", 3);
    copy_wide(out, 8, nullptr, 4);
    CHECK(out[0] == L'\0');
    copy_wide(out, 8, L"abc", 0);
    CHECK(out[0] == L'\0');
}

// --- extract_unicode: where the use-after-free was --------------------------

// Lay a UNICODE_STRING at the head of a buffer with its text following, the
// way NtQueryObject fills one.
void put_unicode(BYTE* buf, ULONG buf_size, const wchar_t* text, bool point_outside = false) {
    memset(buf, 0, buf_size);
    UNICODE_STRING* us = (UNICODE_STRING*)buf;
    size_t chars = wcslen(text);
    us->Length = (USHORT)(chars * sizeof(wchar_t));
    us->MaximumLength = us->Length;
    wchar_t* text_at = (wchar_t*)(buf + sizeof(UNICODE_STRING));
    memcpy(text_at, text, chars * sizeof(wchar_t));
    // A Buffer pointing outside the supplied buffer is the shape that made the
    // obvious implementation read freed memory.
    us->Buffer = point_outside ? (PWSTR)0x1000 : text_at;
}

void test_extract_unicode() {
    BYTE buf[512];
    std::wstring out;

    put_unicode(buf, sizeof(buf), L"\\Device\\HarddiskVolume3");
    extract_unicode(buf, sizeof(buf), out);
    CHECK(out == L"\\Device\\HarddiskVolume3");

    // A Buffer outside the region must yield nothing, not a wild read.
    put_unicode(buf, sizeof(buf), L"\\Device\\Whatever", /*point_outside=*/true);
    extract_unicode(buf, sizeof(buf), out);
    CHECK(out.empty());

    // Zero length is an unnamed object — ordinary, not an error.
    put_unicode(buf, sizeof(buf), L"");
    extract_unicode(buf, sizeof(buf), out);
    CHECK(out.empty());

    // A buffer too small to even hold the struct must be rejected.
    out = L"sentinel";
    extract_unicode(buf, 4, out);
    CHECK(out.empty());

    // A Length running past the end of the buffer must be rejected.
    put_unicode(buf, sizeof(buf), L"abc");
    ((UNICODE_STRING*)buf)->Length = (USHORT)(sizeof(buf) * 2);
    out = L"sentinel";
    extract_unicode(buf, sizeof(buf), out);
    CHECK(out.empty());

    // Embedded NULs are preserved: Length is authoritative, not a terminator.
    put_unicode(buf, sizeof(buf), L"a");
    UNICODE_STRING* us = (UNICODE_STRING*)buf;
    wchar_t* at = (wchar_t*)(buf + sizeof(UNICODE_STRING));
    at[0] = L'a'; at[1] = L'\0'; at[2] = L'b';
    us->Length = 3 * sizeof(wchar_t);
    extract_unicode(buf, sizeof(buf), out);
    CHECK(out.size() == 3 && out[1] == L'\0' && out[2] == L'b');
}

// --- hang-prone classification ---------------------------------------------

void test_is_hang_prone() {
    CHECK(is_hang_prone(0x0012019F));            // the synchronous-pipe mask
    CHECK(is_hang_prone(0x0013019F));            // superset also matches
    CHECK(!is_hang_prone(0x00120089));           // ordinary file read
    CHECK(!is_hang_prone(0));
    CHECK(!is_hang_prone(0x0012019E));           // one bit short
}

// --- abandoned-handle bookkeeping ------------------------------------------

void test_source_key() {
    // Distinct (pid, handle) pairs must not collide, including the swap.
    CHECK(source_key(100, 200) != source_key(200, 100));
    CHECK(source_key(4, 0xC0) != source_key(4, 0xC4));
    CHECK(source_key(4, 0xC0) == source_key(4, 0xC0));
    // Only the low 32 bits of a handle participate; handle values are small,
    // but the pairing must still separate different pids.
    CHECK(source_key(1, 0x1234) != source_key(2, 0x1234));
}

void test_abandoned_tracking() {
    CHECK(!was_abandoned(0xDEAD1));
    CHECK(!source_hangs(4242, 0xBEEF));
    mark_abandoned((HANDLE)(ULONG_PTR)0xDEAD1, 4242, 0xBEEF);
    CHECK(was_abandoned(0xDEAD1));
    CHECK(source_hangs(4242, 0xBEEF));
    // A different pid holding the same handle value is a different handle.
    CHECK(!source_hangs(4243, 0xBEEF));
}

// --- registry stream layout -------------------------------------------------

void test_stream_primitives() {
    std::vector<uint8_t> b;
    put_u32(b, 0x11223344);
    CHECK(b.size() == 4);
    CHECK(b[0] == 0x44 && b[3] == 0x11);          // little-endian
    put_bytes(b, "xy", 2);
    CHECK(b.size() == 6 && b[4] == 'x');
    put_bytes(b, nullptr, 0);                      // no-op, must not crash
    CHECK(b.size() == 6);
}

// Walk a key that exists on every Windows install and verify the stream
// parses by the same offsets aetheris/native/win.py decodes with.
void test_reg_walk_stream() {
    std::vector<uint8_t> buf;
    reg_walk(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
             0, 1, buf);
    CHECK(!buf.empty());

    size_t pos = 0, keys = 0, values = 0;
    bool ok = true;
    while (pos + 8 <= buf.size()) {
        uint32_t key_bytes, count;
        memcpy(&key_bytes, buf.data() + pos, 4);
        memcpy(&count, buf.data() + pos + 4, 4);
        pos += 8;
        if (pos + key_bytes > buf.size()) { ok = false; break; }
        pos += key_bytes;
        for (uint32_t i = 0; i < count; ++i) {
            if (pos + 12 > buf.size()) { ok = false; break; }
            uint32_t name_bytes, type, data_bytes;
            memcpy(&name_bytes, buf.data() + pos, 4);
            memcpy(&type, buf.data() + pos + 4, 4);
            memcpy(&data_bytes, buf.data() + pos + 8, 4);
            pos += 12;
            if (pos + name_bytes + data_bytes > buf.size()) { ok = false; break; }
            pos += name_bytes + data_bytes;
            ++values;
        }
        if (!ok) break;
        ++keys;
    }
    CHECK(ok);
    CHECK(pos == buf.size());   // the stream must consume exactly, no slack
    CHECK(keys >= 1);
    printf("  (reg_walk: %zu keys, %zu values, %zu bytes)\n", keys, values, buf.size());
}

// --- struct layout ----------------------------------------------------------

// These sizes are duplicated as literals in aetheris/native/win.py, which
// decodes the buffers by offset. A field reordered on one side and not the
// other would misread every row rather than raise.
void test_struct_layout() {
    CHECK(sizeof(AwProcess) == 1576);
    CHECK(sizeof(AwRegion) == 32);
    CHECK(sizeof(AwHandleRaw) == 32);
    CHECK(sizeof(AwService) == 2588);
    CHECK(sizeof(AwConnection) == 52);
}

void test_abi_version() {
    // Bumped whenever the export surface changes; aetheris/native/loader.py
    // must list this value in SUPPORTED_ABI or the host refuses the library.
    CHECK(aw_abi_version() == AW_ABI_VERSION);
    CHECK(AW_ABI_VERSION == 4);
}

struct Case { const char* name; void (*fn)(); };

const Case CASES[] = {
    {"copy_wide", test_copy_wide},
    {"extract_unicode", test_extract_unicode},
    {"is_hang_prone", test_is_hang_prone},
    {"source_key", test_source_key},
    {"abandoned_tracking", test_abandoned_tracking},
    {"stream_primitives", test_stream_primitives},
    {"reg_walk_stream", test_reg_walk_stream},
    {"struct_layout", test_struct_layout},
    {"abi_version", test_abi_version},
};

}  // namespace

int main() {
    printf("aetheris_win self-tests\n");
    for (const auto& c : CASES) {
        int before = g_failures;
        printf("- %s\n", c.name);
        c.fn();
        if (g_failures != before) printf("  ^ %d failure(s)\n", g_failures - before);
    }
    printf("\n%d checks, %d failure(s)\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
