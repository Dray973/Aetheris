"""Threat-hunting findings: detectors, ATT&CK tags, and correlation merge."""
from types import SimpleNamespace as NS

from aetheris.analysis import findings as F

TEMP_EXE = r"C:\Users\u\AppData\Local\Temp\helper.exe"


def _p(pid, name, exe, signature="signed"):
    return NS(pid=pid, name=name, exe=exe, signature=signature)


def test_process_detector_flags_unsigned_temp():
    procs = [_p(9002, "helper.exe", TEMP_EXE, "unsigned"),
             _p(512, "svchost.exe", r"C:\Windows\System32\svchost.exe", "signed")]
    fs = F.detect_processes(procs)
    assert len(fs) == 1
    assert fs[0].technique == "T1036"
    assert fs[0].severity in ("medium", "high")


def test_network_detector_public_from_unsigned():
    procs = [_p(9002, "helper.exe", TEMP_EXE, "unsigned")]
    conns = [NS(pid=9002, proc_name="helper.exe", raddr="1.2.3.4", rport=443,
                remote_class="public", geo="RU · Moscow", rdns="")]
    fs = F.detect_network(conns, procs)
    assert len(fs) == 1 and fs[0].technique == "T1071" and fs[0].score >= 40


def test_services_and_tasks_detectors():
    svcs = [NS(name="AppUpd", binary=r"C:\Program Files\App\u.exe",
               image_path=r"C:\Program Files\App\u.exe", start_type="auto",
               account="LocalSystem", unquoted_path=True)]
    assert F.detect_services(svcs)[0].technique == "T1574.009"
    tasks = [NS(name="Evil", path=r"\Evil", triggers=["logon"],
                actions=["powershell -enc AAAA"], action_binaries=["powershell.exe"],
                flags=["obfuscated/encoded shell command", "runs at logon/boot"])]
    assert F.detect_tasks(tasks)[0].technique == "T1053.005"


def test_injection_detector_scores():
    injs = [NS(pid=1, name="a.exe", base=0x1000, size=0x2000, kind="private-pe",
               protect="r-x", region_type="private")]
    fs = F.detect_injection(injs, {1: r"C:\x\a.exe"})
    assert fs[0].technique == "T1055" and fs[0].score == 75


def test_correlation_merges_same_binary_into_critical():
    procs = [_p(9002, "helper.exe", TEMP_EXE, "unsigned")]
    conns = [NS(pid=9002, proc_name="helper.exe", raddr="1.2.3.4", rport=443,
                remote_class="public", geo="RU", rdns="")]
    pmap = [NS(source="Run", name="Helper", detail="", location=r"HKCU\...\Run",
               binary=TEMP_EXE, signed="unsigned", enabled=True)]
    fs = F.analyze(processes=procs, connections=conns, persistence=pmap)
    top = fs[0]
    assert top.category == "correlated"
    assert top.severity == "critical"          # three signals boost past 80
    assert "helper.exe" in top.key
    joined = "\n".join(top.evidence)
    assert "T1036" in joined and "T1071" in joined and "T1547" in joined


def test_yara_detector_maps_match_to_finding():
    matches = [NS(rule="Susp_PS", pid=1234, name="evil.exe", address=0x1000,
                  technique="T1059.001", description="encoded powershell")]
    fs = F.detect_yara(matches, {1234: r"C:\x\evil.exe"})
    assert len(fs) == 1
    assert fs[0].category == "yara" and fs[0].technique == "T1059.001" and fs[0].score == 70
    assert "Susp_PS" in fs[0].title


def test_clean_system_yields_nothing():
    procs = [_p(512, "svchost.exe", r"C:\Windows\System32\svchost.exe", "signed")]
    assert F.analyze(processes=procs) == []
