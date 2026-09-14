"""Multi-target engagements: the library, per-target facts/planning, the engagement
graph, and BloodHound ingestion."""
from pathlib import Path

import pytest

from obol import bloodhound, graph, library, service
from obol.seed import seed_forest
from obol.workspace import Workspace

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


def test_engagement_graph_stitches_targets_to_domain():
    ws = library.create_engagement("E")
    seed_forest(ws)
    ws.add_target("10.10.10.99", "OTHER")
    g = graph.build_engagement_graph(ws)
    types = [n["type"] for n in g["nodes"]]
    assert "domain" in types and types.count("target") == 2
    # every target links up to the domain
    dom = next(n["id"] for n in g["nodes"] if n["type"] == "domain")
    tgts = [n["id"] for n in g["nodes"] if n["type"] == "target"]
    linked = {e["to"] for e in g["edges"] if e["from"] == dom}
    assert set(tgts).issubset(linked)


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
