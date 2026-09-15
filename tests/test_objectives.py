"""Per-target objective ladder (§7): the OSCP progress spine cruise and the report read.

A projection over facts — a rung is reached only when a proof-bound fact records it, and
the ladder feeds cruise's goal function (stop at the root objective) and the report.
"""
from obol import cruise, ingest, library, objectives, report, service
from obol.facts import Fact
from obol.runner import RunResult
from obol.seed import seed_forest


def _ws(tmp_path, host="10.10.10.60"):
    library.set_base(tmp_path)
    library.engagements_dir().mkdir(parents=True, exist_ok=True)
    ws = library.create_engagement("E")
    ws.add_target(host)
    ws.target = host
    return ws


def test_rungs_are_reached_only_by_proving_facts(tmp_path):
    ws = _ws(tmp_path)
    p0 = objectives.progress(ws, "10.10.10.60")
    assert p0["reached"] == 0 and not p0["complete"]
    assert p0["next"]["id"] == "initial-access"

    ws.facts.add(Fact("foothold.linux", "host:10.10.10.60", {"user": "www"}, source="shell"))
    ws.facts.add(Fact("access.root", "host:10.10.10.60", {}, source="x"))  # unrelated kind, no rung
    p1 = objectives.progress(ws, "10.10.10.60")
    reached = {r["id"] for r in p1["rungs"] if r["reached"]}
    assert reached == {"initial-access"}
    assert p1["next"]["id"] == "privesc"


def test_root_flag_completes_the_objective(tmp_path):
    ws = _ws(tmp_path)
    ws.facts.add(Fact("objective.root_flag", "host:10.10.10.60",
                      {"flag": "abc", "slot": "root"}, source="cat /root/proof.txt"))
    p = objectives.progress(ws, "10.10.10.60")
    assert p["complete"] and objectives.is_complete(ws, "10.10.10.60")
    assert p["next"] is None
    # reached rungs carry their evidence lineage for the report to cite
    root = next(r for r in p["rungs"] if r["id"] == "root-flag")
    assert root["reached"] and "proof.txt" in root["evidence"]


def test_single_flag_plus_privilege_counts_as_complete(tmp_path):
    ws = _ws(tmp_path)
    ws.facts.add(Fact("objective.flag", "host:10.10.10.60", {"flag": "x"}, source="cat flag.txt"))
    assert not objectives.is_complete(ws, "10.10.10.60")  # a flag alone is not the root objective
    ws.facts.add(Fact("access.system", "host:10.10.10.60", {}, source="whoami"))
    assert objectives.is_complete(ws, "10.10.10.60")


def test_cruise_stops_when_the_objective_is_complete(tmp_path, monkeypatch):
    ws = _ws(tmp_path, "10.10.10.161")
    seed_forest(ws)
    ws.facts.add(Fact("objective.root_flag", "host:10.10.10.161", {"flag": "y"}, source="type proof.txt"))
    ws.save()
    monkeypatch.setattr(service, "run_command",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("cruise ran past the objective")))
    res = cruise.cruise(ws, "10.10.10.161")
    assert res.stop_reason == "objective-complete" and not res.ran
    assert res.briefing["objectives"]["complete"]


def test_operator_asserted_flag_completes_the_objective(tmp_path):
    """The resumable-handoff path closes the loop: an operator-attested root flag counts,
    with honest lineage."""
    ws = _ws(tmp_path)
    ingest.assert_fact(ws, "objective.root_flag", target="10.10.10.60",
                       value={"flag": "z"}, note="read by hand over my shell")
    assert objectives.is_complete(ws, "10.10.10.60")


def test_report_context_and_markdown_carry_objectives(tmp_path):
    ws = _ws(tmp_path)
    ws.facts.add(Fact("foothold.linux", "host:10.10.10.60", {"user": "www"}, source="shell"))
    ctx = report.build_report_context(ws, include_secrets=True)
    tgt = next(t for t in ctx["targets"] if t["host"] == "10.10.10.60")
    assert tgt["objectives"]["reached"] == 1 and tgt["objectives"]["total"] == 4
    assert "Objectives" in report.build_report(ws, include_secrets=True)
