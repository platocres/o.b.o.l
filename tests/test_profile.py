"""Engagement profile — platform/exam awareness and profile-driven flag capture
(ROADMAP §7).

The profile decides *which* flag file names and value formats the post-foothold
flag hunt looks for. It is operator configuration (one per engagement), never a
fact and never a relaxed proof boundary: a captured flag is still recorded only
when a file was actually read and its content matches a *configured* format.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from obol import board, profile
from obol.flags import extract_flag_value, parse_flag_output
from obol.pack import Action, load_pack
from obol.workspace import Workspace


def _ws(platform=""):
    ws = Workspace(Path(tempfile.mkdtemp()))
    ws.target = "10.10.10.10"
    ws.add_scope("10.10.10.10")
    if platform:
        ws.set_profile({"platform": platform})
    return ws


def _kinds(facts):
    return {f.kind for f in facts}


# --------------------------------------------------------------------------- #
# preset resolution
# --------------------------------------------------------------------------- #
def test_presets_resolve_names_and_slots():
    htb = profile.resolve_flag_config({"platform": "htb"})
    assert htb["names"] == ["user.txt", "root.txt"]
    assert htb["slots"]["user.txt"] == "local" and htb["slots"]["root.txt"] == "root"

    oscp = profile.resolve_flag_config({"platform": "oscp"})
    assert oscp["names"] == ["local.txt", "proof.txt"]
    assert oscp["slots"]["proof.txt"] == "root"


def test_platform_aliases_and_unknown_fallback():
    assert profile.normalize_platform("Hack The Box") == "htb"
    assert profile.normalize_platform("offsec") == "oscp"
    assert profile.normalize_platform("nope") == ""
    # an unknown platform in a stored profile resolves to the safe custom default
    assert profile.resolve_flag_config({"platform": "nope"})["platform"] == "custom"


def test_no_profile_keeps_full_defaults():
    cfg = profile.resolve_flag_config(None)
    assert set(cfg["names"]) == set(profile.DEFAULT_FLAG_NAMES)
    assert cfg["formats"] == profile.DEFAULT_FORMATS


def test_custom_override_names_and_formats():
    cfg = profile.resolve_flag_config(
        {"platform": "custom", "flag_names": ["secret.txt", "FLAG"], "flag_formats": ["brace"]}
    )
    assert cfg["names"] == ["secret.txt", "flag"]
    assert cfg["formats"] == ["brace"]


# --------------------------------------------------------------------------- #
# value-format gating
# --------------------------------------------------------------------------- #
def test_extract_respects_configured_formats():
    # A THM-style brace flag is accepted by a brace profile, rejected by a hash-only one.
    assert extract_flag_value("THM{some_flag_here}", ["brace"]) == "THM{some_flag_here}"
    assert extract_flag_value("THM{some_flag_here}", ["hex32", "hex64"]) == ""
    # A 32-hex flag is accepted by hex32 but not by a brace-only profile.
    h = "0123456789abcdef0123456789abcdef"
    assert extract_flag_value(h, ["hex32"]) == h
    assert extract_flag_value(h, ["brace"]) == ""


def test_extract_default_matches_prior_behavior():
    # Backward compatibility: no formats given == obol's original order.
    assert extract_flag_value("HTB{x}") == "HTB{x}"
    assert extract_flag_value("a" * 32) == "a" * 32


# --------------------------------------------------------------------------- #
# profile-driven flag hunt
# --------------------------------------------------------------------------- #
def _linux_action():
    return next(a for a in load_pack("obol_flag_hunt_2026_09") if a.id == "flag-hunt-linux")


def test_flag_hunt_honors_profile_names():
    # An OSCP engagement records proof.txt as the root flag ...
    ws = _ws("oscp")
    out = "/root/proof.txt:0123456789abcdef0123456789abcdef\n"
    facts = parse_flag_output(_linux_action(), ws, "hunt", out)
    assert "objective.root_flag" in _kinds(facts)

    # ... but a user.txt (not in the OSCP name set) is ignored on that profile.
    out2 = "/home/user/user.txt:0123456789abcdef0123456789abcdef\n"
    assert parse_flag_output(_linux_action(), ws, "hunt", out2) == []


def test_flag_hunt_htb_maps_user_and_root_slots():
    ws = _ws("htb")
    out = ("/home/bob/user.txt:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
           "/root/root.txt:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n")
    facts = parse_flag_output(_linux_action(), ws, "hunt", out)
    assert _kinds(facts) == {"objective.local_flag", "objective.root_flag"}


def test_flag_hunt_format_gate_blocks_wrong_shape():
    # HTB accepts a hash; a prose line at proof path is not a flag value.
    ws = _ws("htb")
    out = "/home/bob/user.txt:this is clearly not a flag value at all\n"
    assert parse_flag_output(_linux_action(), ws, "hunt", out) == []


def test_no_profile_hunt_unchanged():
    ws = _ws()  # no profile -> full default names/formats
    out = "/root/flag.txt:HTB{captured}\n"
    facts = parse_flag_output(_linux_action(), ws, "hunt", out)
    assert "objective.flag" in _kinds(facts)


# --------------------------------------------------------------------------- #
# command templating
# --------------------------------------------------------------------------- #
def test_flag_hunt_command_uses_configured_names():
    ws = _ws("oscp")
    cmd = board.fill_command(_linux_action(), ws)
    assert "-iname local.txt" in cmd and "-iname proof.txt" in cmd
    assert "-iname user.txt" not in cmd
    win = next(a for a in load_pack("obol_flag_hunt_2026_09") if a.id == "flag-hunt-windows")
    assert "-Include local.txt,proof.txt" in board.fill_command(win, ws)


def test_command_tokens_are_filename_safe():
    # Even a malicious override can't inject shell/find syntax into the fragment.
    expr = profile.linux_iname_expr(["user.txt", "; rm -rf /", "a b"])
    assert expr == "-iname user.txt"  # only the safe name survives
    assert profile.windows_name_list(["proof.txt", "$(evil)"]) == "proof.txt"


# --------------------------------------------------------------------------- #
# persistence
# --------------------------------------------------------------------------- #
def test_profile_persists_across_reload():
    ws = _ws("thm")
    ws.save()
    reloaded = Workspace(ws.root).load()
    assert reloaded.profile == {"platform": "thm"}
    assert reloaded.flag_config()["names"][0] == "user.txt"
