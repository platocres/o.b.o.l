"""Tests for the Orange AD pack and the proof-gated planner.

These lock in the two properties that make obol obol: the pack loads as real
data, and actions are gated on facts with conservative proof boundaries (a run
never proves more than the facts it produces).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from obol.facts import Fact, FactSet, ProofState
from obol.pack import load_pack, next_actions, blocked_actions, apply_action
from obol.seed import seed_forest
from obol.workspace import Workspace


def test_pack_loads_all_ad_actions():
    pack = load_pack()
    assert len(pack) == 33
    ids = {a.id for a in pack}
    assert {
        "nmap-fast-open-ports",
        "nmap-version-scripts",
        "ad-anon-ldap-enum",
        "asrep-roast",
        "kerberoast",
        "dcsync",
        "bloodhound-collect",
    } <= ids


def test_every_action_has_a_proof_boundary():
    for a in load_pack():
        assert a.proves, f"{a.id} missing proves"
        assert a.does_not_prove, f"{a.id} missing does_not_prove"


def test_asrep_needs_a_user_list_not_a_kerbrute_step():
    """The correction we grounded: AS-REP unlocks from any user list, not a tool."""
    a = next(x for x in load_pack() if x.id == "asrep-roast")
    assert "ad.user_list" in a.requires_all
    # candidate material only — never a validated credential or access
    assert "credential.candidate" in a.produces
    assert "credential.available" not in a.produces


def test_dcsync_is_blocked_until_privilege():
    facts = FactSet([Fact("ad.domain_known", "domain:htb.local")])
    blocked_ids = {a.id for a in blocked_actions(facts)}
    next_ids = {a.id for a in next_actions(facts)}
    assert "dcsync" in blocked_ids
    assert "dcsync" not in next_ids


def test_forest_seed_unlocks_anonymous_ldap():
    ws = Workspace(Path("/tmp/obol-test-ws"))
    seed_forest(ws)
    next_ids = {a.id for a in next_actions(ws.facts)}
    assert "ad-anon-ldap-enum" in next_ids
    # no credential path is unlocked from bare recon
    assert "bloodhound-collect" not in next_ids


def test_running_ldap_enum_unlocks_asrep():
    ws = Workspace(Path("/tmp/obol-test-ws2"))
    seed_forest(ws)
    ldap = next(a for a in next_actions(ws.facts) if a.id == "ad-anon-ldap-enum")
    new = apply_action(ldap, ws.facts, source="test")
    assert any(f.kind == "ad.user_list" for f in new)
    assert ws.facts.has("ad.user_list")
    assert "asrep-roast" in {a.id for a in next_actions(ws.facts)}


def test_produced_facts_are_supported_and_sourced():
    ws = Workspace(Path("/tmp/obol-test-ws3"))
    seed_forest(ws)
    ldap = next(a for a in next_actions(ws.facts) if a.id == "ad-anon-ldap-enum")
    new = apply_action(ldap, ws.facts, source="ldapsearch ...")
    for f in new:
        assert f.state is ProofState.SUPPORTED
        assert f.source == "ldapsearch ..."
