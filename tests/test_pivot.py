"""§6c pivot-candidate surfacing: the projection that lifts the parsed
multi-homed / adjacent-subnet lead facts onto the target and engagement screens,
and its report-context wiring."""
from obol.facts import Fact
from obol.pivot import engagement_pivots, pivot_summary
from obol.report import _fact_category, build_report_context
from obol.workspace import Workspace


def _ws(tmp_path, host="10.10.10.5"):
    ws = Workspace(tmp_path)
    ws.add_target(host)
    ws.target = host
    return ws


def _seed_multihomed(ws, host="10.10.10.5"):
    scope = f"host:{host}"
    ws.facts.add(Fact("foothold.linux", scope, {}, source="ssh id"))
    ws.facts.add(Fact("host.interface", scope,
                      {"name": "eth1", "address": "172.16.20.10", "cidr": "172.16.20.10/24",
                       "network": "172.16.20.0/24"}, source="ip -o addr show"))
    ws.facts.add(Fact("host.multihomed", scope,
                      {"interfaces": 2, "subnets": ["10.10.10.0/24", "172.16.20.0/24"]},
                      source="ip -o addr show"))
    ws.facts.add(Fact("network.subnet_candidate", scope, {"cidr": "172.16.20.0/24"},
                      source="ip -o addr show"))
    ws.facts.add(Fact("pivot.candidate", scope,
                      {"reasons": ["multiple interface networks"],
                       "subnets": ["10.10.10.0/24", "172.16.20.0/24"]},
                      source="ip -o addr show"))


def test_pivot_summary_reports_multihomed_and_scope_tagging(tmp_path):
    ws = _ws(tmp_path)
    _seed_multihomed(ws)
    piv = pivot_summary(ws, "10.10.10.5")

    assert piv["empty"] is False
    assert piv["multihomed"] is True
    assert piv["interface_count"] == 2
    assert "multiple interface networks" in piv["reasons"]

    by_cidr = {s["cidr"]: s["in_scope"] for s in piv["subnets"]}
    # scope holds only the bare host 10.10.10.5, which authorizes that host but NOT
    # either /24 as a sweep range — so both candidate subnets read as not-in-scope,
    # exactly what a proven tunnel (§6d) would need to auto-extend.
    assert by_cidr["10.10.10.0/24"] is False
    assert by_cidr["172.16.20.0/24"] is False
    assert piv["unscoped_subnets"] == ["10.10.10.0/24", "172.16.20.0/24"]


def test_candidate_subnet_reads_in_scope_when_covered_by_scope_cidr(tmp_path):
    ws = _ws(tmp_path)
    _seed_multihomed(ws)
    ws.add_scope("172.16.20.0/24")
    piv = pivot_summary(ws, "10.10.10.5")
    by_cidr = {s["cidr"]: s["in_scope"] for s in piv["subnets"]}
    assert by_cidr["172.16.20.0/24"] is True
    # the foothold's own /24 is still not authorized as a range
    assert piv["unscoped_subnets"] == ["10.10.10.0/24"]


def test_pivot_summary_empty_without_leads(tmp_path):
    ws = _ws(tmp_path)
    ws.facts.add(Fact("foothold.linux", "host:10.10.10.5", {}, source="ssh id"))
    assert pivot_summary(ws, "10.10.10.5")["empty"] is True


def test_engagement_pivots_only_lists_hosts_with_leads(tmp_path):
    ws = _ws(tmp_path)
    ws.add_target("10.10.10.9")   # no lead
    _seed_multihomed(ws)          # lead on 10.10.10.5
    rows = engagement_pivots(ws)
    assert [r["host"] for r in rows] == ["10.10.10.5"]
    assert rows[0]["label"]


def test_pivot_lead_facts_group_under_pivot_category(tmp_path):
    assert _fact_category("pivot.candidate") == "pivot"
    assert _fact_category("network.subnet_candidate") == "pivot"
    assert _fact_category("host.multihomed") == "pivot"
    # a plain host identity/enum fact stays in the target bucket
    assert _fact_category("host.interface") == "target"


def test_report_context_carries_per_target_pivots_and_counts(tmp_path):
    ws = _ws(tmp_path)
    _seed_multihomed(ws)
    ctx = build_report_context(ws)
    target = next(t for t in ctx["targets"] if t["host"] == "10.10.10.5")
    assert target["pivots"]["multihomed"] is True
    assert "172.16.20.0/24" in target["pivots"]["unscoped_subnets"]
    assert ctx["category_counts"].get("pivot", 0) >= 1
