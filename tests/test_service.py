"""The shared run service is the one runner/parser/store path for both surfaces."""
from pathlib import Path

import pytest

from obol import service
from obol.pack import Action
from obol.runner import RunnerError
from obol.service import ActionError
from obol.workspace import Workspace


def _ws(tmp_path: Path) -> Workspace:
    ws = Workspace(tmp_path)
    ws.target = "10.10.10.5"
    ws.add_scope(ws.target)
    return ws


def test_find_action_by_id_and_unknown():
    action = service.find_action("ad-dc-identify")
    assert action.id == "ad-dc-identify"
    with pytest.raises(ActionError):
        service.find_action("does-not-exist")


def test_build_command_bad_variant(tmp_path):
    ws = _ws(tmp_path)
    action = Action(id="x", title="x", commands=[{"run": "nmap {{target}}"}])
    cmd, tool = service.build_command(action, ws, command_index=0)
    assert "10.10.10.5" in cmd
    with pytest.raises(ActionError):
        service.build_command(action, ws, command_index=5)


def test_dry_run_records_ledger_but_ingests_nothing(tmp_path):
    ws = _ws(tmp_path)
    action = Action(id="scan", title="scan", tool="nmap",
                    commands=[{"tool": "nmap", "run": "nmap -Pn {{target}}"}],
                    produces=["ports.open"])
    outcome = service.run_action(ws, action, dry_run=True)
    assert outcome.dry_run and outcome.added == []
    assert not ws.facts.has("ports.open")           # never invents produces
    assert ws.runs and ws.runs[-1]["dry_run"] is True
    assert ws.runs[-1]["action_id"] == "scan"
    assert Workspace(tmp_path).load().runs, "state was persisted"


def test_scope_gate_refuses_out_of_scope_target(tmp_path):
    ws = Workspace(tmp_path)
    ws.target = "10.10.10.5"                          # target NOT added to scope
    action = Action(id="scan", title="scan", tool="nmap",
                    commands=[{"tool": "nmap", "run": "nmap -Pn {{target}}"}])
    with pytest.raises(RunnerError):
        service.run_action(ws, action, dry_run=True)


def test_unfilled_token_is_refused(tmp_path):
    ws = _ws(tmp_path)
    action = Action(id="a", title="a", commands=[{"run": "nxc smb {{target}} -u {{user}}"}])
    # {{user}} has no value -> the command still carries a placeholder -> refused.
    with pytest.raises(RunnerError):
        service.run_action(ws, action, dry_run=True)
