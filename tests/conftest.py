"""
Shared pytest fixtures.

The native Win32 engine keeps process-global state that outlives a single test:
cached process handles, a catalog admin context, and a record of which handles
timed out inside NtQueryObject. That last one is what makes test order matter.

`test_object_name_resolution_never_hangs` deliberately sweeps with a 50 ms
timeout. Under load an ordinary handle can exceed that, get recorded as hung,
and then be skipped by every later test — so a test that passes alone fails in
the suite, and *which* test fails changes run to run. That is a genuinely
confusing failure to debug, so it is removed at the source rather than worked
around in the affected tests.
"""
import pytest

from aetheris.native import win


@pytest.fixture(autouse=True)
def _reset_native_engine_state():
    """
    Clear the engine's learned state around every test.

    Autouse and cheap (a couple of map clears plus closing cached handles), so
    each test sees the engine as a fresh process would. Note this does *not*
    clear the record of duplicates abandoned into this process — those are
    provably wedged and re-querying them really would hang.
    """
    if win.available():
        win.reset_cache()
    yield
    if win.available():
        win.reset_cache()
