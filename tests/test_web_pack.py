"""Tests for the Orange web pack and multi-pack loading.

These lock in what makes the web pack a good sibling: it loads as data, its proof
boundaries hold, it reuses obol's shared fact-kind namespace (so an HTTP port
unlocks it and it never silently widens an AD claim), and merging packs keeps
action ids unique and gating correct.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from obol.facts import Fact, FactSet
from obol.pack import load_pack, load_packs, next_actions
from obol.playbook import load_playbook, resolve_steps


def test_web_pack_loads():
    pack = load_pack("orange_web_2025_03")
    assert len(pack) == 23
    ids = {a.id for a in pack}
    assert {"content-discovery", "vhost-discovery", "nikto-scan", "sqli-basics", "wordpress"} <= ids


def test_every_web_action_has_a_proof_boundary():
    for a in load_pack("orange_web_2025_03"):
        assert a.proves, f"{a.id} missing proves"
        assert a.does_not_prove, f"{a.id} missing does_not_prove"


def test_web_pack_uses_shared_fact_namespace_not_old_lane_kinds():
    """The old lane's web.reachable/shell.reverse must be remapped so cross-domain
    gating works — nothing in the pack should still use the pre-remap kinds."""
    for a in load_pack("orange_web_2025_03"):
        kinds = set(a.produces) | set(a.requires_all) | set(a.requires_any)
        assert "web.reachable" not in kinds, f"{a.id} still uses web.reachable"
        assert "shell.reverse" not in kinds, f"{a.id} still uses shell.reverse"


def test_content_discovery_unlocks_from_http_reachable():
    a = next(x for x in load_pack("orange_web_2025_03") if x.id == "content-discovery")
    assert "http.reachable" in a.requires_any
    assert "web.content_map" in a.produces


def test_wordpress_enum_does_not_widen_into_ad_user_list():
    """A WordPress user enum is application users, not the AD domain user list —
    producing ad.user_list would falsely unlock the AS-REP / Kerberos chain."""
    a = next(x for x in load_pack("orange_web_2025_03") if x.id == "wordpress")
    assert "ad.user_list" not in a.produces
    assert "web.users" in a.produces


def test_confirmed_injections_are_not_produced_by_bare_reachability():
    """sqlmap-style follow-ups must stay gated behind a confirmed finding, never
    surfaced from raw HTTP reachability."""
    sqlmap = next(x for x in load_pack("orange_web_2025_03") if x.id == "sqlmap-automation")
    assert "web.sqli_confirmed" in sqlmap.requires_all


def test_load_packs_merges_ad_and_web_with_unique_ids():
    merged = load_packs()
    ad = load_pack("orange_ad_2025_03")
    web = load_pack("orange_web_2025_03")
    assert len(merged) == len(ad) + len(web)
    ids = [a.id for a in merged]
    assert len(ids) == len(set(ids)), "merged packs must have unique action ids"


def test_http_port_unlocks_web_spine_ranked_before_deep_web():
    facts = FactSet([Fact("http.reachable", "host:target", {"port": 80})])
    ranked = [a.id for a in next_actions(facts)]
    assert "content-discovery" in ranked and "nikto-scan" in ranked
    # recon ranks ahead of a deep exploitation branch
    assert ranked.index("content-discovery") < ranked.index("jwt-attacks")


def test_bare_recon_does_not_unlock_web_actions():
    """No HTTP evidence yet -> no web actions live (only the nmap prelude)."""
    facts = FactSet([Fact("target.configured", "host:target", {"target": "t"})])
    live = {a.id for a in next_actions(facts)}
    assert "content-discovery" not in live
    assert "nikto-scan" not in live


def test_web_recon_playbook_resolves_across_packs():
    pb = load_playbook("web-recon")
    steps = resolve_steps(pb)  # uses load_packs(); web actions live in a sibling pack
    assert [s.action_id for s, _ in steps] == ["content-discovery", "nikto-scan", "vhost-discovery"]
    vhost = next(s for s, _ in steps if s.action_id == "vhost-discovery")
    assert vhost.require_approval is True
