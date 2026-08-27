"""Auto-Shell intent router — deterministic compile + safety guards."""
from aetheris.automation import nlshell


def test_find_and_move_captures_drive_and_ext():
    c = nlshell.compile(
        "Find every zip archive created this morning on drive E and move them to my desktop.")
    assert c.matched and c.intent == "find_and_move_files"
    assert "E:\\" in c.script and "*.zip" in c.script and "Move-Item" in c.script


def test_kill_by_memory_threshold_bytes():
    c = nlshell.compile(
        "Terminate all background processes utilizing more than 350MB of system memory right now.")
    assert c.intent == "terminate_by_memory"
    assert str(350 * 1024 * 1024) in c.script      # 367001600
    assert c.risk == "high"


def test_set_affinity_mask():
    c = nlshell.compile(
        "Isolate my web browser execution context exclusively to CPU cores 4, 5, and 6.")
    assert c.intent == "set_cpu_affinity"
    assert "112" in c.script                        # (1<<4)|(1<<5)|(1<<6)


def test_kill_by_name():
    c = nlshell.compile("kill all chrome")
    assert c.intent == "terminate_by_name" and "chrome" in c.script


def test_kill_all_processes_is_refused():
    # Must NOT compile to a "kill everything" script.
    c = nlshell.compile("kill all processes")
    assert not c.matched


def test_flush_dns():
    assert nlshell.compile("flush the dns cache").script == "ipconfig /flushdns"


def test_empty_recycle_bin():
    c = nlshell.compile("empty my recycle bin")
    assert c.intent == "empty_recycle_bin" and "Clear-RecycleBin" in c.script


def test_clear_temp():
    c = nlshell.compile("clear my temp files")
    assert c.intent == "clear_temp_files" and "$env:TEMP" in c.script


def test_restart_service_alias():
    c = nlshell.compile("restart the print spooler service")
    assert c.intent == "restart_service" and "Spooler" in c.script


def test_largest_files_count_and_location():
    c = nlshell.compile("show the top 10 largest files in downloads")
    assert c.intent == "largest_files" and "-First 10" in c.script


def test_unmatched_returns_safe_noop():
    c = nlshell.compile("make me a sandwich")
    assert not c.matched and c.script == ""
