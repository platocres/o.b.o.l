"""Tests for web recon parsers (content discovery, vhosts, nikto).

Anti-overfit: fixtures use generic paths/hosts, so tests prove shape recognition,
not memorized walkthrough output. Every parser must map to the narrowest fact and
never claim a confirmed vuln, foothold, or access from recon output.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from obol.pack import load_pack
from obol.parsers import parse_action_output
from obol.workspace import Workspace


def _ws():
    ws = Workspace(Path("/tmp/obol-web-parse"))
    ws.target = "10.10.10.10"
    return ws


def _web_action(action_id: str):
    return next(a for a in load_pack("orange_web_2025_03") if a.id == action_id)


def _kinds(facts):
    return {f.kind for f in facts}


def test_gobuster_content_discovery_maps_paths_and_skips_404():
    out = (
        "===============================================================\n"
        "/admin                (Status: 301) [Size: 0]\n"
        "/backup               (Status: 200) [Size: 12]\n"
        "/missing              (Status: 404) [Size: 0]\n"
    )
    facts = parse_action_output(
        _web_action("content-discovery"), _ws(),
        "gobuster dir -u http://10.10.10.10 -w list.txt", out, "", source="gobuster",
    )
    cm = next(f for f in facts if f.kind == "web.content_map")
    assert set(cm.value["paths"]) == {"/admin", "/backup"}
    assert "/missing" not in cm.value["paths"]
    assert "/admin" in cm.value.get("interesting", [])
    # recon proves surface only — never a confirmed vuln or foothold
    assert not any(k.endswith("_confirmed") or k.startswith("foothold.") for k in _kinds(facts))


def test_feroxbuster_and_ffuf_content_shapes():
    ferox = "200      GET       10l       30w      500c http://10.10.10.10/api\n"
    facts = parse_action_output(
        _web_action("content-discovery"), _ws(),
        "feroxbuster -u http://10.10.10.10 -w list.txt", ferox, "", source="ferox",
    )
    assert "/api" in next(f for f in facts if f.kind == "web.content_map").value["paths"]

    ffuf = "config                  [Status: 200, Size: 12, Words: 3, Lines: 1]\n"
    facts = parse_action_output(
        _web_action("content-discovery"), _ws(),
        "ffuf -u http://10.10.10.10/FUZZ -w list.txt", ffuf, "", source="ffuf",
    )
    assert "/config" in next(f for f in facts if f.kind == "web.content_map").value["paths"]


def test_vhost_discovery_produces_vhosts_not_content_map():
    ffuf = "dev                     [Status: 200, Size: 12]\nstaging                 [Status: 200, Size: 20]\n"
    facts = parse_action_output(
        _web_action("vhost-discovery"), _ws(),
        'ffuf -u http://10.10.10.10 -H "Host: FUZZ.example.com" -w list.txt', ffuf, "", source="ffuf",
    )
    vhost = next(f for f in facts if f.kind == "web.vhost")
    assert set(vhost.value["vhosts"]) == {"dev", "staging"}
    assert "web.content_map" not in _kinds(facts)  # vhost mode must not double-parse as content


def test_nikto_findings_are_candidates_not_confirmed():
    out = (
        "- Nikto v2.5.0\n"
        "+ Server: Apache/2.4.29\n"
        "+ /admin/: Admin login page/section found.\n"
        "+ OSVDB-3268: /config/: Directory indexing found.\n"
    )
    facts = parse_action_output(
        _web_action("nikto-scan"), _ws(),
        "nikto -h http://10.10.10.10", out, "", source="nikto",
    )
    kinds = _kinds(facts)
    assert "exploit.candidate" in kinds
    cand = next(f for f in facts if f.kind == "exploit.candidate")
    # the plain "Server:" banner line is noise, not a finding
    assert all("server:" not in f.lower() for f in cand.value["findings"])
    # nikto reveals paths too, but never a confirmed vuln/foothold/access
    assert "web.content_map" in kinds
    assert not any(k.endswith("_confirmed") or k.startswith(("foothold.", "access.")) for k in kinds)


def test_empty_web_output_yields_no_facts():
    facts = parse_action_output(
        _web_action("content-discovery"), _ws(),
        "gobuster dir -u http://10.10.10.10 -w list.txt", "no matches\n", "", source="gobuster",
    )
    assert facts == []
