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

// Walk a subtree this test creates, so the expected contents are exact.
//
// An earlier version walked HKCU\...\CurrentVersion\Run on the assumption that
// it exists everywhere. It does not: a fresh CI profile has no such key, the
// walk returned nothing, and the test failed for lack of data rather than for
// a defect. Building the fixture removes the machine dependence entirely and
// lets the stream be checked against known values instead of just parsed.
const wchar_t* TEST_KEY = L"Software\\AetherisSelfTest";

bool make_fixture() {
    HKEY root = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, TEST_KEY, 0, nullptr, 0,
                        KEY_WRITE, nullptr, &root, nullptr) != ERROR_SUCCESS) {
        return false;
    }
    const wchar_t* sz = L"hello";
    RegSetValueExW(root, L"AString", 0, REG_SZ, (const BYTE*)sz,
                   (DWORD)((wcslen(sz) + 1) * sizeof(wchar_t)));
    DWORD dw = 1234;
    RegSetValueExW(root, L"ANumber", 0, REG_DWORD, (const BYTE*)&dw, sizeof(dw));
    const BYTE bin[3] = {1, 2, 3};
    RegSetValueExW(root, L"ABlob", 0, REG_BINARY, bin, sizeof(bin));

    HKEY child = nullptr;
    if (RegCreateKeyExW(root, L"Child", 0, nullptr, 0, KEY_WRITE,
                        nullptr, &child, nullptr) == ERROR_SUCCESS) {
        DWORD one = 1;
        RegSetValueExW(child, L"Nested", 0, REG_DWORD, (const BYTE*)&one, sizeof(one));
        RegCloseKey(child);
    }
    RegCloseKey(root);
    return true;
}

void drop_fixture() {
    RegDeleteTreeW(HKEY_CURRENT_USER, TEST_KEY);
}

void test_reg_walk_stream() {
    if (!make_fixture()) {
        printf("  SKIP: could not create the fixture key\n");
        return;
    }

    std::vector<uint8_t> buf;
    reg_walk(HKEY_CURRENT_USER, TEST_KEY, 0, 1, buf);
    CHECK(!buf.empty());

    // Decode by the same offsets aetheris/native/win.py uses.
    size_t pos = 0, keys = 0, values = 0;
    bool ok = true, saw_string = false, saw_dword = false, saw_binary = false;
    bool saw_child = false;
    while (pos + 8 <= buf.size()) {
        uint32_t key_bytes, count;
        memcpy(&key_bytes, buf.data() + pos, 4);
        memcpy(&count, buf.data() + pos + 4, 4);
        pos += 8;
        if (pos + key_bytes > buf.size()) { ok = false; break; }
        std::wstring key((const wchar_t*)(buf.data() + pos), key_bytes / sizeof(wchar_t));
        if (key.find(L"Child") != std::wstring::npos) saw_child = true;
        pos += key_bytes;
        for (uint32_t i = 0; i < count; ++i) {
            if (pos + 12 > buf.size()) { ok = false; break; }
            uint32_t name_bytes, type, data_bytes;
            memcpy(&name_bytes, buf.data() + pos, 4);
            memcpy(&type, buf.data() + pos + 4, 4);
            memcpy(&data_bytes, buf.data() + pos + 8, 4);
            pos += 12;
            if (pos + name_bytes + data_bytes > buf.size()) { ok = false; break; }
            std::wstring name((const wchar_t*)(buf.data() + pos), name_bytes / sizeof(wchar_t));
            const BYTE* data = buf.data() + pos + name_bytes;
            if (name == L"AString" && type == REG_SZ) {
                saw_string = std::wstring((const wchar_t*)data,
                                          data_bytes / sizeof(wchar_t)).rfind(L"hello", 0) == 0;
            } else if (name == L"ANumber" && type == REG_DWORD && data_bytes == 4) {
                DWORD v; memcpy(&v, data, 4);
                saw_dword = (v == 1234);
            } else if (name == L"ABlob" && type == REG_BINARY && data_bytes == 3) {
                saw_binary = (data[0] == 1 && data[1] == 2 && data[2] == 3);
            }
            pos += name_bytes + data_bytes;
            ++values;
        }
        if (!ok) break;
        ++keys;
    }

    CHECK(ok);
    CHECK(pos == buf.size());   // the stream must consume exactly, no slack
    CHECK(keys == 2);           // the key itself plus Child, at depth 1
    CHECK(values == 4);
    CHECK(saw_child);
    CHECK(saw_string);
    CHECK(saw_dword);
    CHECK(saw_binary);
    printf("  (reg_walk: %zu keys, %zu values, %zu bytes)\n", keys, values, buf.size());

    drop_fixture();
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
