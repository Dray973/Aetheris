"""YARA scanning: rule compile + byte matching (skips without yara-python).

Uses only benign strings (injection API names, PowerShell tokens, a canary) so
nothing here trips antivirus on the test file itself."""
import pytest

from aetheris.forensics import yarascan

pytestmark = pytest.mark.skipif(not yarascan.available(),
                                reason="yara-python not installed")


def test_load_builtin_rules():
    assert yarascan.load_rules() is not None


def test_injection_api_rule_matches():
    rules = yarascan.load_rules()
    data = b"...VirtualAllocEx...WriteProcessMemory...CreateRemoteThread..."
    ms = yarascan.scan_bytes(rules, data, pid=1234, name="evil.exe", address=0x4000)
    hit = next((m for m in ms if m.rule == "Aetheris_Injection_APIs"), None)
    assert hit is not None
    assert hit.technique == "T1055" and hit.pid == 1234 and hit.address == 0x4000


def test_encoded_powershell_rule_matches():
    rules = yarascan.load_rules()
    data = b"powershell FromBase64String IEX DownloadString http://x"
    ms = yarascan.scan_bytes(rules, data)
    assert any(m.rule == "Aetheris_Encoded_PowerShell" and m.technique == "T1059.001"
               for m in ms)


def test_custom_rule_via_extra_source():
    src = ('rule Canary { meta: mitre_attack = "T1105" '
           'strings: $s = "aetheris-canary-xyz" condition: $s }')
    rules = yarascan.load_rules(extra_source=src)
    ms = yarascan.scan_bytes(rules, b"prefix aetheris-canary-xyz suffix")
    assert any(m.rule == "Canary" and m.technique == "T1105" for m in ms)


def test_clean_data_and_none_rules_are_safe():
    rules = yarascan.load_rules()
    assert yarascan.scan_bytes(rules, b"nothing interesting here at all") == []
    assert yarascan.scan_bytes(None, b"data") == []
