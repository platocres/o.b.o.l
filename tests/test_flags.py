from obol.flags import extract_flag_value, parse_flag_output
from obol.pack import load_packs
from obol.report import _fact_category, build_report_context
from obol.workspace import Workspace


def _action(action_id):
    return next(a for a in load_packs() if a.id == action_id)


def _workspace(tmp_path, host="10.10.10.5"):
    ws = Workspace(tmp_path)
    ws.add_target(host)
    ws.target = host
    return ws


# ── the flag-hunt actions load and gate on a proven foothold ─────────────────
def test_flag_hunt_actions_load_and_gate_on_foothold():
    linux = _action("flag-hunt-linux")
    windows = _action("flag-hunt-windows")
    assert linux.os == ["linux"]
    assert set(linux.requires_all) == {"credential.available", "foothold.linux"}
    assert windows.os == ["windows"]
    assert set(windows.requires_all) == {"credential.available", "winrm.authenticated"}


def test_flag_hunt_command_has_no_banned_shell_metacharacters():
    # The runner rejects | ; & < > ` on the raw command string; the hunt must run
    # through the ordinary fixed-argv runner, not a guided-handoff path.
    for action_id in ("flag-hunt-linux", "flag-hunt-windows"):
        run = _action(action_id).commands[0]["run"]
        assert not any(ch in run for ch in "|;&<>`")


# ── the parser is action-id scoped and proof-bound ──────────────────────────
def test_linux_grep_output_captures_local_and_root_flags(tmp_path):
    ws = _workspace(tmp_path)
    action = _action("flag-hunt-linux")
    output = (
        "/home/bob/user.txt:ffeeddccbbaa99887766554433221100\n"
        "/root/root.txt:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6\n"
    )
    facts = parse_flag_output(action, ws, action.command, output, source="find / ... grep")
    by_kind = {f.kind: f for f in facts}

    assert set(by_kind) == {"objective.local_flag", "objective.root_flag"}
    local = by_kind["objective.local_flag"]
    assert local.scope == "host:10.10.10.5"
    assert local.value["flag"] == "ffeeddccbbaa99887766554433221100"
    assert local.value["name"] == "user.txt"
    assert local.value["slot"] == "local"
    assert local.value["path"] == "/home/bob/user.txt"
    assert by_kind["objective.root_flag"].value["slot"] == "root"


def test_windows_marker_output_captures_flags(tmp_path):
    ws = _workspace(tmp_path)
    action = _action("flag-hunt-windows")
    output = (
        "WINRM       10.10.10.5      5985   DC01             "
        "===FLAG:C:\\Users\\bob\\Desktop\\user.txt::0011223344556677889900aabbccddee\n"
        "WINRM       10.10.10.5      5985   DC01             "
        "===FLAG:C:\\Users\\Administrator\\Desktop\\root.txt::THM{captured_the_root}\n"
    )
    facts = parse_flag_output(action, ws, action.command, output, source="nxc winrm -X ...")
    by_kind = {f.kind: f for f in facts}

    assert by_kind["objective.local_flag"].value["flag"] == "0011223344556677889900aabbccddee"
    assert by_kind["objective.local_flag"].value["path"].endswith("user.txt")
    assert by_kind["objective.root_flag"].value["flag"] == "THM{captured_the_root}"


def test_parser_is_action_id_scoped(tmp_path):
    # Identical output through a non-flag action must never mint an objective fact.
    ws = _workspace(tmp_path)
    other = _action("local-linux-interfaces")
    output = "/root/root.txt:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6\n"
    assert parse_flag_output(other, ws, other.command, output) == []


def test_empty_or_unreadable_output_records_nothing(tmp_path):
    ws = _workspace(tmp_path)
    action = _action("flag-hunt-linux")
    # File matched but not readable / empty content — a lead, never a captured flag.
    assert parse_flag_output(action, ws, action.command, "") == []
    assert parse_flag_output(action, ws, action.command, "/root/root.txt:\n") == []
    # cat error text on the line is not a flag value.
    noise = "/root/root.txt:cat: /root/root.txt: Permission denied\n"
    assert parse_flag_output(action, ws, action.command, noise) == []


def test_non_flag_filename_is_ignored(tmp_path):
    ws = _workspace(tmp_path)
    action = _action("flag-hunt-linux")
    output = "/etc/passwd:root:x:0:0:root:/root:/bin/bash\n"
    assert parse_flag_output(action, ws, action.command, output) == []


def test_duplicate_capture_is_deduped(tmp_path):
    ws = _workspace(tmp_path)
    action = _action("flag-hunt-linux")
    val = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
    output = f"/root/root.txt:{val}\n/root/root.txt:{val}\n"
    facts = parse_flag_output(action, ws, action.command, output)
    assert len(facts) == 1


# ── value extraction boundaries ──────────────────────────────────────────────
def test_extract_flag_value_shapes():
    assert extract_flag_value("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6") == "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
    assert extract_flag_value("HTB{some_flag_here}") == "HTB{some_flag_here}"
    assert extract_flag_value("  flag{spaces_trimmed}  ") == "flag{spaces_trimmed}"
    assert extract_flag_value("shortcustomtoken") == "shortcustomtoken"
    assert extract_flag_value("") == ""
    assert extract_flag_value("this is clearly not a flag but prose") == ""
    assert extract_flag_value("cat: file: Permission denied") == ""


# ── the objective category and per-target rollup surface the flags ───────────
def test_objective_facts_categorized_and_rolled_up_per_target(tmp_path):
    ws = _workspace(tmp_path)
    action = _action("flag-hunt-linux")
    facts = parse_flag_output(
        action, ws, action.command,
        "/home/bob/user.txt:ffeeddccbbaa99887766554433221100\n",
        source="find / ...",
    )
    for f in facts:
        ws.facts.add(f)
    ws.save()

    assert _fact_category("objective.local_flag") == "objective"
    ctx = build_report_context(ws, include_secrets=True)
    target = next(t for t in ctx["targets"] if t["host"] == "10.10.10.5")
    assert len(target["flags"]) == 1
    assert target["flags"][0]["flag"] == "ffeeddccbbaa99887766554433221100"
    assert target["flags"][0]["slot"] == "local"
    assert ctx["category_counts"].get("objective") == 1
