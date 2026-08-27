"""Cascading-menu spec parser (pure; cross-platform)."""
from aetheris.core.registry import parse_menu_spec, MenuItem


def test_flat_leaves():
    items = parse_menu_spec("A | cmd-a\nB | cmd-b")
    assert [i.label for i in items] == ["A", "B"]
    assert all(not i.is_branch and i.command for i in items)
    assert items[0].command == "cmd-a"


def test_nested_branches_two_levels():
    spec = (
        "Tools\n"
        "  Open here | run.exe\n"
        "  Hashing\n"
        "    SHA-256 | hash.exe --sha256\n"
    )
    roots = parse_menu_spec(spec)
    assert len(roots) == 1
    tools = roots[0]
    assert tools.is_branch and tools.label == "Tools"
    labels = [c.label for c in tools.children]
    assert labels == ["Open here", "Hashing"]
    hashing = tools.children[1]
    assert hashing.is_branch
    assert hashing.children[0].label == "SHA-256"
    assert hashing.children[0].command == "hash.exe --sha256"


def test_command_may_contain_pipes():
    # Only the first '|' separates label from command.
    item = parse_menu_spec("Grep | findstr x | more")[0]
    assert item.label == "Grep"
    assert item.command == "findstr x | more"


def test_branch_has_no_command():
    roots = parse_menu_spec("Menu\n  Item | c")
    assert roots[0].is_branch and roots[0].command is None


def test_blank_lines_ignored():
    roots = parse_menu_spec("\nA | c\n\n  B | d\n")
    assert roots[0].label == "A"
    assert roots[0].children[0].label == "B"


def test_menuitem_defaults():
    m = MenuItem("x")
    assert m.children == [] and m.command is None and not m.is_branch
