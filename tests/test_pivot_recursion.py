"""The pivot recursion (§6e/f) in the cruise loop: the through-tunnel sweep as a move,
autonomy-elevated auto-sweep, and engagement cruise walking across segments.

Pivoting itself (opening a tunnel) stays a per-host checkpoint; once a tunnel is up, the
sweep of the pivoted segment becomes a move, and engagement cruise carries the operator
into the newly-discovered segment.
"""
from obol import cruise as cruise_mod
from obol import dispatch, discovery, library, moves
from obol.facts import Fact


def _ws(tmp_path, host="10.10.10.70"):
    library.set_base(tmp_path)
    library.engagements_dir().mkdir(parents=True, exist_ok=True)
    ws = library.create_engagement("E")
    ws.add_target(host)
    ws.target = host
    return ws


def _pivoted(ws, host="10.10.10.70", subnet="10.10.20.0/24"):
    """A host with a proven foothold and a live tunnel exposing a subnet."""
    ws.facts.add(Fact("foothold.linux", f"host:{host}", {"user": "www"}, source="shell"))
    t = ws.add_tunnel(host=host, kind="chisel", transport="socks", status="up",
                      exposed_subnet=subnet)
    ws.save()
    return t


# ── the sweep move ────────────────────────────────────────────────────────────
def test_sweep_move_is_offered_for_an_up_tunnel_and_settles_after_a_sweep(tmp_path):
    ws = _ws(tmp_path)
    t = _pivoted(ws)
    sweep = [m for m in moves.frontier_moves(ws, "10.10.10.70") if m.kind == "sweep"]
    assert sweep and sweep[0].id == f"sweep:{t['id']}"
    assert sweep[0].autonomy == "approve" and sweep[0].detail["subnet"] == "10.10.20.0/24"

    # a down tunnel is not swept
    ws.update_tunnel(t["id"], status="down"); ws.save()
    assert not [m for m in moves.frontier_moves(ws, "10.10.10.70") if m.kind == "sweep"]

    # and once a sweep has run for it, it settles out (re-sweep stays manual)
    ws.update_tunnel(t["id"], status="up")
    ws.record_run("nmap", "sweep", [], sweep=True, tunnel=t["id"])
    ws.save()
    assert not [m for m in moves.frontier_moves(ws, "10.10.10.70") if m.kind == "sweep"]


def test_dispatch_runs_a_through_tunnel_sweep(tmp_path, monkeypatch):
    ws = _ws(tmp_path)
    t = _pivoted(ws)
    monkeypatch.setattr(discovery, "run_tunnel_sweep",
                        lambda ws, tid, **kw: {"status": "up", "subnet": "10.10.20.0/24",
                                               "created": ["10.10.20.5"], "tunnel": tid})
    res = dispatch.run_move(ws, f"sweep:{t['id']}", host="10.10.10.70", approve=True)
    assert res["ok"] and res["kind"] == "sweep"
    assert any("10.10.20.5" in a for a in res["added"])


# ── autonomy: sweep is a checkpoint, elevated by auto_kinds ────────────────────
def test_cruise_stops_at_a_sweep_unless_auto_kinds_elevates_it(tmp_path, monkeypatch):
    ws = _ws(tmp_path)
    only_sweep = moves.Move(kind="sweep", id="sweep:t1", label="Sweep 10.10.20.0/24",
                            phase="escalate", ready=True, autonomy="approve",
                            detail={"tunnel": "t1", "subnet": "10.10.20.0/24"})
    monkeypatch.setattr(cruise_mod.moves_layer, "frontier_moves", lambda ws, h: [only_sweep])
    calls = []
    monkeypatch.setattr(cruise_mod.dispatch, "run_move",
                        lambda ws, mid, **kw: (calls.append((mid, kw.get("approve"))) or
                                               {"ok": True, "posture": "ran", "added": []}))

    # by default a sweep is a checkpoint — cruise stops and never fires it
    r = cruise_mod.cruise(ws, "10.10.10.70", auto_kinds=frozenset())
    assert r.stop_reason == "checkpoint" and r.stop_move["kind"] == "sweep" and not calls

    # auto_kinds={"sweep"} elevates it: cruise runs it (with approval) and carries on
    r2 = cruise_mod.cruise(ws, "10.10.10.70", auto_kinds=frozenset({"sweep"}))
    assert calls and calls[0] == ("sweep:t1", True)
    assert r2.stop_reason == "done"


# ── engagement cruise: walk all targets, pick up new segments ─────────────────
def test_engagement_cruise_walks_all_targets_and_recurses_into_new_ones(tmp_path, monkeypatch):
    ws = _ws(tmp_path, "10.10.10.70")

    def fake_cruise(ws, host, **kw):
        # cruising the first host "discovers" a host in the pivoted segment
        if host == "10.10.10.70":
            ws.add_target("10.10.20.5"); ws.save()
        return cruise_mod.CruiseResult(target=host, stop_reason="done",
                                       message="", briefing={"checkpoint": None})

    monkeypatch.setattr(cruise_mod, "cruise", fake_cruise)
    eng = cruise_mod.cruise_engagement(ws)
    hosts = [h["host"] for h in eng.hosts]
    assert "10.10.10.70" in hosts and "10.10.20.5" in hosts  # the recursion picked up the new segment
    assert eng.to_dict()["summary"]["cruised"] == 2
