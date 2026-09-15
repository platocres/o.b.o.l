"""External-action ingestion (cruise pillar III): paste-and-parse + operator-attested.

The way back into cruise after the operator does something by hand. Facts earned this way
go through the same proof-bound parser pipeline (paste-and-parse) or are recorded as a
clearly-marked operator assertion — either way with honest operator lineage, never mistaken
for something obol proved.
"""
from obol import ingest, library
from obol.facts import ProofState


def _ws(tmp_path, host="10.10.10.50"):
    library.set_base(tmp_path)
    library.engagements_dir().mkdir(parents=True, exist_ok=True)
    ws = library.create_engagement("E")
    ws.add_target(host)
    ws.target = host
    return ws


# ── paste-and-parse ───────────────────────────────────────────────────────────
NMAP = "PORT     STATE SERVICE\n22/tcp   open  ssh\n445/tcp  open  microsoft-ds\n"


def test_ingest_parses_output_into_facts_with_operator_lineage(tmp_path):
    ws = _ws(tmp_path)
    res = ingest.ingest_output(ws, NMAP, note="manual nmap -sV", target="10.10.10.50")
    assert res["ok"] and res["added"], "recognizable nmap output should yield facts"
    # every fact obol earned from the paste is stamped operator-sourced
    ingested = [f for f in ws.facts.facts if f.source.startswith("operator:")]
    assert ingested, "ingested facts must carry operator lineage"
    assert all("manual nmap" in f.source for f in ingested)
    # and it is a real, proof-bound fact — a port it actually saw
    assert ws.facts.has("port:22")


def test_ingest_is_proof_bound_and_invents_nothing(tmp_path):
    ws = _ws(tmp_path)
    res = ingest.ingest_output(ws, "i definitely got root trust me", note="claim")
    assert res["added"] == []  # ambiguous prose proves nothing
    assert not ws.facts.has("access.admin")


def test_ingest_records_an_external_run_in_the_ledger(tmp_path):
    ws = _ws(tmp_path)
    ingest.ingest_output(ws, NMAP, note="manual nmap", target="10.10.10.50")
    ext = [r for r in ws.runs if r.get("external")]
    assert ext and ext[-1].get("origin") == "operator"


# ── operator-attested assertion ───────────────────────────────────────────────
def test_assert_records_a_marked_operator_fact(tmp_path):
    ws = _ws(tmp_path)
    res = ingest.assert_fact(ws, "access.shell", target="10.10.10.50",
                             value={"user": "www-data"}, note="manual RCE chain")
    assert res["ok"] and res["added"]
    fact = next(f for f in ws.facts.facts if f.kind == "access.shell")
    assert fact.scope == "host:10.10.10.50"
    assert fact.value == {"user": "www-data"}
    assert fact.source.startswith("operator-attested:") and "manual RCE" in fact.source
    assert fact.state is ProofState.SUPPORTED  # the operator attests it as proven


def test_assert_requires_a_kind(tmp_path):
    ws = _ws(tmp_path)
    import pytest
    with pytest.raises(ValueError):
        ingest.assert_fact(ws, "", target="10.10.10.50")


def test_fact_origin_classifies_lineage(tmp_path):
    ws = _ws(tmp_path)
    ingest.ingest_output(ws, NMAP, note="nmap -sV 10.10.10.50", target="10.10.10.50")
    ingest.assert_fact(ws, "access.shell", target="10.10.10.50", note="by hand")
    by_kind = {f.kind: f for f in ws.facts.facts}
    assert ingest.fact_origin(by_kind["access.shell"]) == "operator-attested"
    assert ingest.fact_origin(by_kind["port:22"]) == "operator-executed"
    # a seeded/plain fact is obol-origin
    from obol.facts import Fact
    assert ingest.fact_origin(Fact("x", "host:1", {}, source="nmap ...")) == "obol"


def test_report_visibly_distinguishes_operator_facts(tmp_path):
    from obol import report
    ws = _ws(tmp_path)
    ingest.assert_fact(ws, "access.shell", target="10.10.10.50",
                       value={"user": "www-data"}, note="manual RCE")
    ctx = report.build_report_context(ws, include_secrets=True)
    shell = next(f for f in ctx["facts"] if f["kind"] == "access.shell")
    assert shell["origin"] == "operator-attested"
    md = report.build_report(ws, include_secrets=True)
    assert "operator-attested" in md  # the markdown tags it visibly


def test_assert_honors_an_explicit_state_and_scope(tmp_path):
    ws = _ws(tmp_path)
    res = ingest.assert_fact(ws, "ad.anonymous_bind", scope="domain:htb.local",
                             note="confirmed by hand", state="refuted")
    assert res["scope"] == "domain:htb.local" and res["state"] == "refuted"
    # a refuted fact is not a supported one — the planner does not treat it as proven
    assert not ws.facts.has("ad.anonymous_bind")
