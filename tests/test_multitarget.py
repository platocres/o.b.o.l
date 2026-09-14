"""Multi-target engagements: the library, per-target facts/planning, the engagement
graph, and BloodHound ingestion."""
from pathlib import Path

import pytest

from obol import bloodhound, graph, library, service
from obol.facts import Fact, FactSet
from obol.seed import seed_forest
from obol.workspace import Workspace


def test_identical_facts_on_different_hosts_are_both_kept():
    # the same (kind, value) on two hosts is two distinct facts — deduping without
    # scope would silently drop one host's finding (regression: multi-host sweep)
    fs = FactSet()
    assert fs.add(Fact("port:445", "host:10.10.10.5", {"port": 445})) is True
    assert fs.add(Fact("port:445", "host:10.10.10.7", {"port": 445})) is True
    # but re-adding the exact same (kind, scope, value) is still a no-op
    assert fs.add(Fact("port:445", "host:10.10.10.5", {"port": 445})) is False
    assert {f.scope for f in fs.facts} == {"host:10.10.10.5", "host:10.10.10.7"}

FIXTURES = Path("/home/user/kaldox/pentos/tests/fixtures/sharphound")


@pytest.fixture(autouse=True)
def temp_library(tmp_path):
    library.set_base(tmp_path)
    yield
    library.set_base(None)


def test_library_create_list_active():
    ws = library.create_engagement("Op Nightfall")
    assert ws.root.name == "op-nightfall"
    assert library.active_slug() == "op-nightfall"
    library.create_engagement("Op Nightfall")           # dup name -> unique slug
    slugs = {e["slug"] for e in library.list_engagements()}
    assert "op-nightfall" in slugs and "op-nightfall-2" in slugs
    library.set_active("op-nightfall")
    assert library.resolve_active().root.name == "op-nightfall"


def test_add_target_seeds_configured_fact_and_scope():
    ws = library.create_engagement("E")
    rec = ws.add_target("10.10.10.5", "WEB")
    assert rec["host"] == "10.10.10.5" and "10.10.10.5" in ws.scope
    # a bare target can immediately run the nmap prelude
    nxt = service.next_actions(ws.facts_for_target("10.10.10.5"))
    assert any(a.id == "nmap-fast-open-ports" for a in nxt)


def test_target_identity_enrichment_keeps_custom_labels():
    ws = library.create_engagement("E")
    ws.add_target("10.10.10.5")
    assert ws.enrich_target_identity(
        "10.10.10.5",
        hostname="DC01",
        fqdn="dc01.corp.local",
        domain="corp.local",
    )
    rec = ws.get_target("10.10.10.5")
    assert rec["label"] == "DC01"
    assert rec["hostname"] == "DC01"
    assert rec["fqdn"] == "dc01.corp.local"
    assert rec["domain"] == "corp.local"

    ws.add_target("10.10.10.7", "MANUAL")
    ws.enrich_target_identity("10.10.10.7", hostname="WEB01", domain="corp.local")
    assert ws.get_target("10.10.10.7")["label"] == "MANUAL"


def test_facts_are_scoped_per_target_but_share_domain():
    ws = library.create_engagement("E")
    seed_forest(ws)                          # host-scoped facts on 10.10.10.161 + domain
    ws.add_target("10.10.10.99", "OTHER")
    dc = ws.facts_for_target("10.10.10.161")
    other = ws.facts_for_target("10.10.10.99")
    assert dc.has("ldap.reachable")          # host-scoped fact visible to its host
    assert not other.has("ldap.reachable")   # ...not to a different host
    assert dc.has("ad.domain_known") and other.has("ad.domain_known")  # domain shared


def test_active_target_run_scopes_and_persists(tmp_path):
    ws = library.create_engagement("E")
    ws.add_target("10.10.10.161", "DC")
    action = service.find_action("nmap-fast-open-ports")
    outcome = service.run_action(ws, action, dry_run=True, target="10.10.10.161")
    assert ws.target == "10.10.10.161"
    assert "10.10.10.161" in outcome.command
    assert ws.runs[-1]["target"] == "10.10.10.161"


def test_engagement_graph_uses_evidence_backed_domain_and_service_edges():
    ws = library.create_engagement("E")
    ws.add_scope("10.10.10.0/24")
    seed_forest(ws)
    ws.add_target("10.10.10.99", "OTHER")
    g = graph.build_engagement_graph(ws)
    types = [n["type"] for n in g["nodes"]]
    assert "scope" in types and "domain" in types and "service" in types
    assert types.count("target") == 2

    dom = next(n["id"] for n in g["nodes"] if n["type"] == "domain")
    targets = {n["meta"]["host"]: n for n in g["nodes"] if n["type"] == "target"}
    dc_id = targets["10.10.10.161"]["id"]
    other_id = targets["10.10.10.99"]["id"]
    domain_linked = {e["to"] for e in g["edges"] if e["from"] == dom}
    assert dc_id in domain_linked
    assert other_id not in domain_linked

    service_edges = [e for e in g["edges"] if e["from"] == dc_id and e["kind"] == "exposes"]
    service_labels = {
        n["label"]
        for n in g["nodes"]
        if n["type"] == "service" and n["id"] in {e["to"] for e in service_edges}
    }
    assert {"Kerberos 88", "LDAP 389", "SMB 445"} <= service_labels


def test_engagement_graph_does_not_turn_smb_domain_banner_into_dc():
    ws = library.create_engagement("E")
    ws.add_target("10.10.10.25", "WIN10")
    ws.facts.add(Fact("host.hostname", "host:10.10.10.25", {"name": "WIN10"}))
    ws.facts.add(Fact("host.domain", "host:10.10.10.25", {"domain": "corp.local"}))
    ws.facts.add(Fact("ad.dc_candidate", "host:10.10.10.25", {"name": "WIN10", "domain": "corp.local"}))
    ws.facts.add(Fact("smb.reachable", "host:10.10.10.25", {"tool": "nxc"}))

    g = graph.build_engagement_graph(ws)
    target = next(n for n in g["nodes"] if n["type"] == "target")
    domain = next(n for n in g["nodes"] if n["type"] == "domain")
    edge = next(e for e in g["edges"] if e["from"] == domain["id"] and e["to"] == target["id"])
    assert target["meta"]["dc"] is False
    assert edge["kind"] == "domain-service"


@pytest.mark.skipif(not FIXTURES.exists(), reason="bloodhound fixtures not present")
def test_bloodhound_ingest_parses_and_records():
    ws = library.create_engagement("E")
    uploads = [(f.name, f.read_bytes()) for f in FIXTURES.glob("*.json")]
    summary = bloodhound.ingest(ws, uploads)
    assert summary["domain"] and summary["users"] > 0
    assert summary["kerberoastable"] and summary["asrep_roastable"]
    assert ws.facts.has("ad.graph.collected")
    # the overlay reaches the engagement graph
    g = graph.build_engagement_graph(ws)
    assert any(n["type"] in ("highvalue", "roastable") for n in g["nodes"])


def test_evidence_attach_and_scope():
    ws = library.create_engagement("E")
    ws.add_target("10.10.10.161", "DC")
    rec = ws.add_evidence(filename="s.png", data=b"\x89PNG", target="10.10.10.161",
                          phase="access", caption="shell")
    assert (ws.evidence_dir / rec["stored"]).exists()
    assert ws.evidence_for("10.10.10.161") and not ws.evidence_for("10.10.10.99")
    assert ws.remove_evidence(rec["id"])
    assert not (ws.evidence_dir / rec["stored"]).exists()
