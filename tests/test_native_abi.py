"""
The ABI contract between the built engines and the host.

This exists because of a failure mode that is worse than a broken test: when
an engine's ABI version is bumped and ``loader.SUPPORTED_ABI`` is not, the
loader correctly refuses the library and every native test **skips**. A green
run with silent skips looks identical to a green run with the engines working.
That happened twice during the native migration — 21 MFT tests vanished from
the suite without a single failure.

So these tests *fail* rather than skip when a DLL is present but unusable, and
they are the one place in the suite that treats "the engine did not load" as an
error rather than a supported configuration.
"""
import ctypes

import pytest

from aetheris.native import core, loader, win

ENGINES = [
    ("aetheris_core", "aetheris_abi_version", core),
    ("aetheris_win", "aw_abi_version", win),
]


def _built(name: str) -> bool:
    return loader.library_path(name) is not None


@pytest.mark.parametrize("name,symbol,binding", ENGINES)
def test_built_engine_reports_a_supported_abi(name, symbol, binding):
    """
    A DLL that exists must be one this host can talk to.

    If this fails, the engine was rebuilt with a new ABI and
    ``loader.SUPPORTED_ABI`` was not updated to match — the exact mistake that
    silently disables the native path.
    """
    path = loader.library_path(name)
    if path is None:
        pytest.skip(f"{name}.dll not built")

    raw = ctypes.CDLL(str(path))
    fn = getattr(raw, symbol)
    fn.restype = ctypes.c_uint32
    fn.argtypes = []
    reported = int(fn())

    supported = loader.SUPPORTED_ABI[name]
    assert reported in supported, (
        f"{name}.dll reports ABI {reported}, but this host supports {supported}. "
        f"Update SUPPORTED_ABI in aetheris/native/loader.py — until you do, every "
        f"native test for this engine silently skips."
    )


@pytest.mark.parametrize("name,symbol,binding", ENGINES)
def test_a_built_engine_actually_loads(name, symbol, binding):
    """A present DLL must be live, not merely present. Catches an ABI
    mismatch, a missing export, and a load failure in one assertion."""
    if not _built(name):
        pytest.skip(f"{name}.dll not built")
    assert binding.available(), (
        f"{name}.dll is on disk but the binding refused it — check the warning "
        f"logged by aetheris.native.loader (ABI mismatch or missing export)."
    )


@pytest.mark.parametrize("name,symbol,binding", ENGINES)
def test_every_declared_symbol_resolves(name, symbol, binding):
    """
    Every signature the binding declares must exist in the DLL.

    ``win._load`` refuses a library missing an export rather than half-binding
    it, which is right at runtime but would show up here only as a skip. This
    resolves them directly so a removed or renamed export is a failure.
    """
    path = loader.library_path(name)
    if path is None:
        pytest.skip(f"{name}.dll not built")
    raw = ctypes.CDLL(str(path))
    missing = [sym for sym in binding._SIGNATURES if not hasattr(raw, sym)]
    assert not missing, f"{name}.dll is missing declared exports: {missing}"


def test_supported_abi_covers_every_engine():
    """A binding with no SUPPORTED_ABI entry would be refused unconditionally,
    because loader.load() treats an unknown name as 'no supported versions'."""
    for name, _symbol, _binding in ENGINES:
        assert name in loader.SUPPORTED_ABI
        assert loader.SUPPORTED_ABI[name], f"{name} has an empty version tuple"


def test_unknown_library_is_refused_not_guessed():
    assert loader.SUPPORTED_ABI.get("not_a_real_engine") is None
    assert loader.load("not_a_real_engine", "whatever_abi_version") is None
