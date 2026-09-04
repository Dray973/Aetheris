"""
Large-scale native/Python parity sweeps against live system data.

The per-rule unit tests elsewhere cover the divergences that are already known.
These cover the ones that are not: they run both implementations over real
data at a scale where undocumented behaviour surfaces, and demand exact
agreement. Every value-decoding rule in ``aetheris.native.win`` was found this
way, and none of them would have been found by hand-written fixtures --
"REG_SZ truncates at the first NUL" only appears once some installer has
written a value with the wrong length.

That matters most for the registry, where the native path reproduces CPython's
``winreg`` conversions rather than a documented contract. If a future CPython
changes how it decodes a value, the snapshot/diff workflow would silently start
reporting phantom "modified" rows. This sweep is what catches that.

Marked ``slow`` -- they take a few seconds. Run only the fast suite with
``pytest -m "not slow"``.
"""
import os
import sys

import pytest

from aetheris.core import registry, services, signing
from aetheris.native import core, win

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(
        not win.available() or sys.platform != "win32",
        reason="aetheris_win.dll not built, or not Windows",
    ),
]


# --- registry ---------------------------------------------------------------

# Subtrees chosen for rule coverage, not just size. Measured by disabling each
# value-decoding rule in turn and counting the divergences that appear:
#
#   tree                                     values   SZ  MULTI  EMPTY
#   HKCU\Software                            11,101    2     14      4
#   HKCU\...\Windows\CurrentVersion           6,758    1     12      4
#   HKLM\SOFTWARE\...\CurrentVersion         97,798    0      3      5
#   HKLM\SYSTEM\CurrentControlSet\Services    9,485    0      4      0
#
# HKCU\Software is the densest: it exercises all three rules in a ninth of the
# values the big HKLM tree needs. The HKLM trees are kept for breadth -- an
# undiscovered rule is as likely to live in machine-wide state as in the user
# hive, and finding those is the point of sweeping rather than fixture-testing.
SWEEP_TREES = [
    ("HKCU", r"Software", 5),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion", 5),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion", 3),
    ("HKLM", r"SYSTEM\CurrentControlSet\Services", 2),
]

# Below this a tree is too sparse to conclude anything, so the sweep skips
# rather than fails. Coverage here depends on what the machine happens to
# contain -- a fresh CI runner has an almost empty HKCU -- and a sweep that
# failed for lack of data would train people to ignore it. The deterministic
# guards for the rules we already know about are the unit tests in
# tests/test_native_registry.py; these sweeps exist to find the ones we do not.
MIN_VALUES = 200


@pytest.mark.parametrize("root,sub,depth", SWEEP_TREES)
def test_registry_sweep_is_byte_identical(monkeypatch, root, sub, depth):
    """
    Every value in a real subtree must render identically on both paths.

    Compared over the intersection of keys: the registry is live, so a key can
    appear or vanish between the two walks. Values are *not* given that
    latitude -- a value present in both must be identical, because the rendered
    form is what a saved snapshot diffs against later.
    """
    native = registry.snapshot_tree(root, sub, max_depth=depth)
    monkeypatch.setattr(win, "reg_snapshot", lambda *a, **k: None)
    fallback = registry.snapshot_tree(root, sub, max_depth=depth)

    common = set(native) & set(fallback)
    divergent = []
    compared = 0
    for key in common:
        for name in set(native[key]) & set(fallback[key]):
            compared += 1
            if native[key][name] != fallback[key][name]:
                divergent.append((key, name, native[key][name], fallback[key][name]))

    if compared < MIN_VALUES:
        pytest.skip(f"{root}\\{sub} holds only {compared} values on this machine "
                    f"— too sparse to conclude anything")
    assert not divergent, (
        f"{len(divergent)} of {compared} values differ between the native and "
        f"winreg paths. First few:\n" + "\n".join(
            f"  {k}::{n}\n    native={a!r}\n    winreg={b!r}"
            for k, n, a, b in divergent[:5]
        )
    )


# --- Authenticode -----------------------------------------------------------


def _system_binaries(limit):
    root = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    out = []
    try:
        for name in sorted(os.listdir(root)):
            if name.lower().endswith((".exe", ".dll")):
                p = os.path.join(root, name)
                if os.path.isfile(p):
                    out.append(p)
            if len(out) >= limit:
                break
    except OSError:
        pass
    return out


def test_signature_sweep_agrees(monkeypatch):
    """Both paths must reach the same verdict for every binary swept."""
    paths = _system_binaries(120)
    if len(paths) < 20:
        pytest.skip("too few system binaries readable")

    verdicts = {}
    for p in paths:
        signing._cache.clear()
        verdicts[p] = signing._verify(p)

    monkeypatch.setattr(win, "verify_signature", lambda _p: None)
    divergent = []
    for p in paths:
        signing._cache.clear()
        if signing._verify(p) != verdicts[p]:
            divergent.append(p)
    signing._cache.clear()

    assert not divergent, f"{len(divergent)}/{len(paths)} verdicts differ: {divergent[:5]}"


# --- services and drivers ---------------------------------------------------


def test_driver_sweep_agrees(monkeypatch):
    """
    Drivers come from a registry walk, so unlike services they are not subject
    to live state churn — every field must match exactly.
    """
    native = {d.name.lower(): d for d in services.enumerate_drivers(check_signature=False)}
    monkeypatch.setattr(win, "enum_driver_services", lambda *a, **k: None)
    fallback = {d.name.lower(): d for d in services.enumerate_drivers(check_signature=False)}

    assert len(native) > 50
    assert set(native) == set(fallback)
    divergent = [
        k for k in native
        if (native[k].image_path, native[k].start_type, native[k].state,
            native[k].display_name, native[k].account)
        != (fallback[k].image_path, fallback[k].start_type, fallback[k].state,
            fallback[k].display_name, fallback[k].account)
    ]
    assert not divergent, f"{len(divergent)} drivers differ: {divergent[:5]}"


def test_service_sweep_agrees(monkeypatch):
    """
    Services carry live state, so a handful may legitimately change between the
    two enumerations. Everything else must match.
    """
    native = {s.name.lower(): s for s in services.enumerate_services(check_signature=False)}
    monkeypatch.setattr(win, "enum_services", lambda *a, **k: None)
    fallback = {s.name.lower(): s for s in services.enumerate_services(check_signature=False)}

    common = set(native) & set(fallback)
    assert len(common) > 50
    divergent = [
        k for k in common
        if (native[k].start_type, native[k].state) != (fallback[k].start_type, fallback[k].state)
    ]
    assert len(divergent) <= 2, f"{len(divergent)} services differ: {divergent[:5]}"


# --- MFT --------------------------------------------------------------------


def test_mft_sweep_on_real_records():
    """
    Parse real on-disk FILE records through both paths.

    The same bytes are read once and fed to both, so this is deterministic --
    unlike comparing two volume walks, where a file being written between them
    changes its recorded size. Needs a raw volume handle, so it skips without
    elevation.
    """
    if not core.available():
        pytest.skip("aetheris_core.dll not built")
    from aetheris.storage import mft

    volume = r"\\.\C:"
    try:
        boot = mft.read_boot_info(volume)
        with open(volume, "rb", buffering=0) as fh:
            extents = mft._mft_extents(fh, boot)
            assert extents, "no $MFT extents"
            offset, length = extents[0]
            block = min(512 * boot.record_size, length - (length % boot.record_size))
            fh.seek(offset)
            data = fh.read(block)
    except (PermissionError, OSError) as exc:
        pytest.skip(f"raw volume unavailable (needs elevation): {exc}")

    rec_size, bps = boot.record_size, boot.bytes_per_sector
    native = core.mft_parse_block(data, rec_size, bps, 0)
    assert native is not None

    fallback = []
    for i, off in enumerate(range(0, len(data) - rec_size + 1, rec_size)):
        chunk = data[off:off + rec_size]
        if chunk[0:4] != mft.FILE_SIGNATURE:
            continue
        buf = bytearray(chunk)
        if not mft._apply_fixups(buf, bps):
            continue
        rec = mft._parse_record(bytes(buf), i)
        if rec and rec.name:
            fallback.append(rec)

    assert len(native) == len(fallback), (
        f"{len(native)} native records vs {len(fallback)} python over the same bytes"
    )
    assert len(native) > 10, "expected a meaningful number of records in the first block"
    for n, p in zip(native, fallback, strict=True):
        assert (n.index, n.name, n.size, n.parent_index) == \
               (p.index, p.name, p.size, p.parent_index), f"record {n.index} differs"
        assert (n.in_use, n.is_directory) == (p.in_use, p.is_directory)
