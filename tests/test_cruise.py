"""obol cruise — the supervised cruise-control loop (pillar II).

Cruise must: run only auto (recon/enum) moves unattended, stop at the first move that
needs approval and hand it back as a checkpoint (never firing it), run each move at most
once so it always terminates, and go through the same scope-enforced runner/parser/store
as everything else (no second engine).
"""
import pytest

from obol import cruise, library, service
from obol.facts import Fact
from obol.runner import RunResult
from obol.seed import seed_forest


def _ws(tmp_path, host):
    library.set_base(tmp_path)
    library.engagements_dir().mkdir(parents=True, exist_ok=True)
    ws = library.create_engagement("E")
    ws.add_target(host)
    ws.target = host
    return ws


def _fake_runner(stdout, rc=0):
    def run(ws, command, tool, **kw):
        return RunResult(command, command.split(), rc, stdout, "",
                         ws.runs_dir / "o.txt", ws.runs_dir / "e.txt", 5.0, 1)
    return run


def test_no_target_stops_cleanly(tmp_path):
    ws = _ws(tmp_path, "10.10.10.40")
    ws.target = ""
    ws.save()
    res = cruise.cruise(ws, "")
    assert res.stop_reason == "no-target" and not res.ran


def test_cruise_runs_only_auto_moves_and_terminates(tmp_path, monkeypatch):
    ws = _ws(tmp_path, "10.10.10.161")
    seed_forest(ws)
    ws.save()
    monkeypatch.setattr(service, "run_command", _fake_runner("SMB 10.10.10.161 445 [+] ok"))
    res = cruise.cruise(ws, "10.10.10.161", max_steps=50)
    assert res.ran, "cruise should have run at least one auto move"
    # every move cruise ran unattended is an auto pack action — never a primitive
    # (login/enum/tunnel/exploit are approve/manual and must be checkpoints)
    assert all(s.kind == "action" for s in res.ran)
    assert res.stop_reason in {"checkpoint", "done", "max-steps"}


def test_cruise_stops_at_a_checkpoint_without_firing_it(tmp_path, monkeypatch):
    """Once the auto (recon/enum) moves are exhausted, the highest-ranked next move is a
    login (approve-tier). Cruise stops and hands it back as a checkpoint — it never fires
    the primitive itself (every move it ran was an auto pack action)."""
    ws = _ws(tmp_path, "10.10.10.161")
    seed_forest(ws)
    ws.facts.add(Fact("winrm.reachable", "host:10.10.10.161", {"tool": "nxc"}, source="x"))
    ws.facts.add(Fact("credential.available", "host:10.10.10.161",
                      {"user": "svc", "password": "s3rvice"}, source="crack"))
    ws.save()
    # a benign runner so auto actions "run" but nothing settles; the login proof would
    # be recognizable, but cruise must stop before ever calling it.
    monkeypatch.setattr(service, "run_command", _fake_runner(""))
    res = cruise.cruise(ws, "10.10.10.161", max_steps=100)
    assert res.stop_reason == "checkpoint"
    assert res.stop_move is not None and res.stop_move["autonomy"] in ("approve", "manual")
    # crucially: cruise never auto-ran a primitive — only auto pack actions
    assert all(s.kind == "action" for s in res.ran)
    assert not ws.facts.has("foothold.windows")  # the login was not fired


def test_cruise_terminates_when_actions_yield_no_facts(tmp_path, monkeypatch):
    """Even if every command yields no parseable facts (nothing settles), cruise runs
    each auto move at most once and then stops — it never spins."""
    ws = _ws(tmp_path, "10.10.10.161")
    seed_forest(ws)
    ws.save()
    monkeypatch.setattr(service, "run_command", _fake_runner(""))  # no parseable output
    res = cruise.cruise(ws, "10.10.10.161", max_steps=100)
    # ran each attempted move once; a bounded, terminating run
    ran_ids = [s.id for s in res.ran]
    assert len(ran_ids) == len(set(ran_ids)), "a move ran more than once"
    assert res.stop_reason in {"checkpoint", "done", "max-steps"}
