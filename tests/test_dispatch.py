"""Move dispatch (cruise-control pillars I->II): run any frontier move by id through
its existing shared primitive, fact-gated, with an honest posture. The dispatcher
invents nothing — it routes to `service.run_action` / `sessions` / `enumrun` /
`tunnels` / `exploits` — and it can only run a move the frontier currently offers.
"""
import pytest

from obol import dispatch, library, service
from obol.facts import Fact
from obol.runner import RunResult
from obol.seed import seed_forest


def _ws(tmp_path, host="10.10.10.30"):
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


# ── id parsing ────────────────────────────────────────────────────────────────
def test_parse_move_id_distinguishes_primitives_from_actions():
    assert dispatch.parse_move_id("login:winrm") == ("login", "winrm")
    assert dispatch.parse_move_id("enum:linpeas") == ("enum", "linpeas")
    # a pack action slug is an action even though it has hyphens (and never a colon)
    assert dispatch.parse_move_id("ad-dc-identify") == ("action", "ad-dc-identify")
    # an unknown prefix is treated as an action id, not a bogus primitive
    assert dispatch.parse_move_id("weird:thing") == ("action", "weird:thing")


# ── the fact-gate on execution ────────────────────────────────────────────────
def test_a_move_not_on_the_frontier_is_refused(tmp_path):
    ws = _ws(tmp_path, "10.10.10.161")
    seed_forest(ws)
    ws.save()
    with pytest.raises(dispatch.DispatchError):
        dispatch.run_move(ws, "login:winrm", host="10.10.10.161")  # no credential -> not offered


def test_a_not_ready_move_is_refused_with_its_reason(tmp_path):
    ws = _ws(tmp_path)
    ws.facts.add(Fact("winrm.reachable", f"host:{ws.target}", {"tool": "nxc"}, source="x"))
    ws.save()  # winrm offered but not ready (no credential)
    with pytest.raises(dispatch.DispatchError) as exc:
        dispatch.run_move(ws, "login:winrm", host=ws.target)
    assert "not ready" in str(exc.value)


# ── action dispatch ───────────────────────────────────────────────────────────
def test_action_dry_run_previews_without_executing(tmp_path):
    ws = _ws(tmp_path, "10.10.10.161")
    seed_forest(ws)
    ws.save()
    res = dispatch.run_move(ws, "ad-dc-identify", host="10.10.10.161", dry_run=True)
    assert res["ok"] and res["posture"] == "dry-run" and res["kind"] == "action"
    assert res["command"] and "{{" not in res["command"]


def test_action_run_executes_through_the_shared_runner(tmp_path, monkeypatch):
    ws = _ws(tmp_path, "10.10.10.161")
    seed_forest(ws)
    ws.save()
    monkeypatch.setattr(service, "run_command",
                        _fake_runner("SMB 10.10.10.161 445 FOREST [+] enumerated"))
    res = dispatch.run_move(ws, "ad-dc-identify", host="10.10.10.161")
    assert res["ok"] and res["posture"] == "ran" and res["kind"] == "action"


# ── login dispatch (handoff posture) ──────────────────────────────────────────
def test_login_move_runs_the_proof_and_hands_off(tmp_path, monkeypatch):
    ws = _ws(tmp_path)
    host = ws.target
    ws.facts.add(Fact("winrm.reachable", f"host:{host}", {"tool": "nxc"}, source="x"))
    ws.facts.add(Fact("credential.available", f"host:{host}",
                      {"user": "svc", "password": "s3rvice"}, source="crack"))
    ws.save()
    monkeypatch.setattr(service, "run_command",
                        _fake_runner(f"WINRM {host} 5985 HOST [+] d\\svc\nd\\svc\n"))
    # a login is approve-tier (it touches the box), so it needs approval to run
    res = dispatch.run_move(ws, "login:winrm", host=host, approve=True)
    assert res["ok"] and res["posture"] == "handoff"
    assert "evil-winrm" in res["command"] and "s3rvice" in res["command"]  # secrets shown
    assert "foothold.windows" in res["added"]
    assert ws.facts.has("foothold.windows")


# ── the autonomy gate (cruise stop-contract) ──────────────────────────────────
def test_approve_tier_move_pauses_without_approval(tmp_path, monkeypatch):
    """An approve-tier move (a login) does not run unattended: without approval it
    returns a needs-approval checkpoint and touches nothing."""
    ws = _ws(tmp_path)
    host = ws.target
    ws.facts.add(Fact("winrm.reachable", f"host:{host}", {"tool": "nxc"}, source="x"))
    ws.facts.add(Fact("credential.available", f"host:{host}",
                      {"user": "svc", "password": "s3rvice"}, source="crack"))
    ws.save()
    # a runner that would explode if called — proves nothing executed
    monkeypatch.setattr(service, "run_command",
                        lambda *a, **k: pytest.fail("approve-tier move ran without approval"))
    res = dispatch.run_move(ws, "login:winrm", host=host)  # approve defaults False
    assert not res["ok"] and res["posture"] == "needs-approval"
    assert not ws.facts.has("foothold.windows")


def test_auto_tier_action_runs_without_approval(tmp_path, monkeypatch):
    """An auto-tier recon/enum action runs unattended (cruise auto-advances it)."""
    ws = _ws(tmp_path, "10.10.10.161")
    seed_forest(ws)
    ws.save()
    monkeypatch.setattr(service, "run_command", _fake_runner("SMB 10.10.10.161 445 [+] ok"))
    res = dispatch.run_move(ws, "ad-dc-identify", host="10.10.10.161")  # no approve
    assert res["ok"] and res["posture"] == "ran"


# ── exploit dispatch is craft-only (never fires) ──────────────────────────────
def test_exploit_move_is_crafted_not_fired(tmp_path):
    ws = _ws(tmp_path)
    host = ws.target
    ws.facts.add(Fact("foothold.linux", f"host:{host}", {"user": "www-data"}, source="shell"))
    ws.facts.add(Fact("privesc.sudo_rights", f"host:{host}",
                      {"nopasswd": True, "binary": "find"}, source="sudo -l"))
    ws.save()
    before = len(ws.facts.facts)
    res = dispatch.run_move(ws, "exploit:sudo-gtfo", host=host)
    assert res["ok"] and res["posture"] == "craft"
    # crafting touches nothing: no facts recorded, no session/tunnel state
    assert len(ws.facts.facts) == before
    assert not ws.sessions and not ws.tunnels
