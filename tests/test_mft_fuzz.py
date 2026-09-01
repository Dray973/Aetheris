"""Property/fuzz tests for the raw $MFT binary parser (hypothesis).

The MFT reader consumes on-disk bytes that a hostile or simply corrupt volume
fully controls, so it must never crash or hang on malformed run-lists or FILE
records -- it must degrade to a safe, well-formed result. These properties
assert exactly that across thousands of adversarial inputs.
"""
from hypothesis import given, settings
from hypothesis import strategies as st

from aetheris.storage import mft


@settings(max_examples=500, deadline=None)
@given(buf=st.binary(min_size=0, max_size=128),
       cluster=st.sampled_from([512, 1024, 4096, 65536]))
def test_parse_run_list_never_crashes_and_is_well_formed(buf, cluster):
    extents = mft._parse_run_list(buf, 0, cluster)
    assert isinstance(extents, list)
    for e in extents:
        assert isinstance(e, tuple) and len(e) == 2
        off, length = e
        assert isinstance(off, int) and isinstance(length, int)
        assert off >= 0 and length > 0


@settings(max_examples=500, deadline=None)
@given(pos=st.integers(min_value=0, max_value=200),
       buf=st.binary(min_size=0, max_size=128),
       cluster=st.integers(min_value=1, max_value=1 << 20))
def test_parse_run_list_tolerates_arbitrary_start_and_cluster(pos, buf, cluster):
    assert isinstance(mft._parse_run_list(buf, pos, cluster), list)


@settings(max_examples=500, deadline=None)
@given(data=st.binary(min_size=0, max_size=96))
def test_apply_fixups_never_crashes(data):
    result = mft._apply_fixups(bytearray(data), 512)
    assert isinstance(result, bool)


@settings(max_examples=800, deadline=None)
@given(data=st.binary(min_size=0, max_size=300))
def test_parse_record_never_crashes_on_arbitrary_bytes(data):
    out = mft._parse_record(bytes(data), 0)
    assert out is None or isinstance(out, mft.MftRecord)


@settings(max_examples=800, deadline=None)
@given(tail=st.binary(min_size=0, max_size=300))
def test_parse_record_never_crashes_with_valid_signature(tail):
    out = mft._parse_record(b"FILE" + bytes(tail), 0)
    assert out is None or isinstance(out, mft.MftRecord)
