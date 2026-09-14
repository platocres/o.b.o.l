"""Sessions layer (§6a): one-click login paired with a non-interactive proof, and
the ssh/rdp proof parsers. Proof-bound like the rest — a login is only recorded
once a captured, parsed command establishes the access fact."""
import pytest

from obol import library, service, sessions
from obol.facts import Fact
from obol.pack import Action
from obol.parsers import parse_action_output
from obol.runner import RunResult


def _ws(tmp_path, host="10.10.10.161"):
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


def _parse(ws, command, out):
    action = Action(id="probe", title="probe", commands=[{"run": command}])
    return parse_action_output(action, ws, command, out, "", source=command)


# ── the login flow ───────────────────────────────────────────────────────────
def test_winrm_login_proves_foothold_and_records_live_session(tmp_path, monkeypatch):
    ws = _ws(tmp_path)
    ws.facts.add(Fact("winrm.reachable", "host:10.10.10.161", {"tool": "nxc"}, source="x"))
    ws.facts.add(Fact("credential.available", "host:10.10.10.161",
                      {"user": "svc-alfresco", "password": "s3rvice"}, source="crack"))
    ws.save()
    monkeypatch.setattr(service, "run_command",
                        _fake_runner("WINRM 10.10.10.161 5985 FOREST [+] htb\\svc-alfresco\nhtb\\svc-alfresco\n"))

    offers = {o["kind"]: o for o in sessions.eligible_sessions(ws, "10.10.10.161")}
    assert offers["winrm"]["ready"] is True

    res = sessions.open_session(ws, "10.10.10.161", "winrm")
    assert res["ok"] and res["session"]["status"] == "active"
    assert res["session"]["proof_fact"] == "foothold.windows"
    assert ws.facts.has("foothold.windows")
    # the interactive command is handed back in full (secrets shown — operator box)
    assert "evil-winrm" in res["login_command"] and "s3rvice" in res["login_command"]
    # a normal user is NOT admin, despite any nxc banner
    assert not ws.facts.has("access.admin")

    # persisted as live state and reloads
    ws2 = library.get_engagement(ws.root.name)
    assert [(s["kind"], s["status"]) for s in ws2.sessions] == [("winrm", "active")]
    assert "s3rvice" in ws2.sessions[0]["login_command"]  # not redacted


def test_proven_badge_is_per_kind_not_a_shared_foothold(tmp_path, monkeypatch):
    """A WinRM login yields the shared foothold.windows; RDP (a sibling that also
    produces it) must NOT be marked proven or offered off that — it is not reachable."""
    ws = _ws(tmp_path)
    ws.facts.add(Fact("winrm.reachable", "host:10.10.10.161", {"tool": "nxc"}, source="x"))
    ws.facts.add(Fact("credential.available", "host:10.10.10.161",
                      {"user": "svc", "password": "pw"}, source="x"))
    ws.save()
    monkeypatch.setattr(service, "run_command", _fake_runner("[+] htb\\svc\nhtb\\svc\n"))
    sessions.open_session(ws, "10.10.10.161", "winrm")
    assert ws.facts.has("foothold.windows")
    offers = {o["kind"]: o for o in sessions.eligible_sessions(ws, "10.10.10.161")}
    assert offers["winrm"]["proven"] is True          # active winrm session
    assert "rdp" not in offers                          # 3389 not open, no rdp session


def test_login_needs_a_reachable_service_and_a_password(tmp_path):
    ws = _ws(tmp_path)
    # reachable but no credential → offered but not ready, and open_session refuses
    ws.facts.add(Fact("winrm.reachable", "host:10.10.10.161", {"tool": "nxc"}, source="x"))
    ws.save()
    offers = {o["kind"]: o for o in sessions.eligible_sessions(ws, "10.10.10.161")}
    assert offers["winrm"]["ready"] is False
    with pytest.raises(sessions.SessionError):
        sessions.open_session(ws, "10.10.10.161", "winrm")


def test_login_not_confirmed_records_no_session(tmp_path, monkeypatch):
    ws = _ws(tmp_path)
    ws.facts.add(Fact("port:5985", "host:10.10.10.161", {"port": 5985, "service": "wsman"}, source="nmap"))
    ws.facts.add(Fact("credential.available", "host:10.10.10.161",
                      {"user": "bob", "password": "wrong"}, source="guess"))
    ws.save()
    # a failed auth prints no shell/whoami line → no access fact → no session
    monkeypatch.setattr(service, "run_command",
                        _fake_runner("WINRM 10.10.10.161 5985 FOREST [-] htb\\bob:wrong\n", rc=1))
    res = sessions.open_session(ws, "10.10.10.161", "winrm")
    assert res["ok"] is False and res["session"] is None
    assert not ws.facts.has("foothold.windows")
    assert ws.sessions == []


def test_probe_flips_a_session_to_dead_when_reproof_fails(tmp_path, monkeypatch):
    ws = _ws(tmp_path)
    ws.facts.add(Fact("winrm.reachable", "host:10.10.10.161", {"tool": "nxc"}, source="x"))
    ws.facts.add(Fact("credential.available", "host:10.10.10.161",
                      {"user": "svc", "password": "pw"}, source="x"))
    ws.save()
    monkeypatch.setattr(service, "run_command", _fake_runner("[+] htb\\svc\nhtb\\svc\n"))
    sid = sessions.open_session(ws, "10.10.10.161", "winrm")["session"]["id"]
    # the box goes down: re-proof returns nothing and a non-zero code
    monkeypatch.setattr(service, "run_command", _fake_runner("connection refused\n", rc=1))
    res = sessions.probe_session(ws, sid)
    assert res["alive"] is False and ws.get_session(sid)["status"] == "dead"


# ── ssh / rdp proof parsers (anti-overfit: proof only on real success markers) ──
def test_ssh_id_proves_linux_shell_only(tmp_path):
    ws = _ws(tmp_path, "10.10.10.5")
    facts = {f.kind for f in _parse(
        ws, "sshpass -p pw ssh bob@10.10.10.5 id",
        "uid=1000(bob) gid=1000(bob) groups=1000(bob),4(adm)\n")}
    assert "foothold.linux" in facts and "access.shell" in facts
    assert "access.admin" not in facts and "foothold.windows" not in facts


def test_ssh_root_is_privileged(tmp_path):
    ws = _ws(tmp_path, "10.10.10.5")
    facts = {f.kind for f in _parse(
        ws, "sshpass -p pw ssh root@10.10.10.5 id", "uid=0(root) gid=0(root) groups=0(root)\n")}
    assert {"foothold.linux", "access.shell", "access.admin"} <= facts


def test_ssh_failed_login_proves_nothing(tmp_path):
    ws = _ws(tmp_path, "10.10.10.5")
    facts = _parse(ws, "sshpass -p wrong ssh bob@10.10.10.5 id",
                   "Permission denied (publickey,password).\n")
    assert not [f for f in facts if f.kind.startswith(("foothold", "access"))]


def test_nxc_rdp_success_proves_foothold_and_pwn3d_is_admin(tmp_path):
    ws = _ws(tmp_path)
    facts = {f.kind for f in _parse(
        ws, "nxc rdp 10.10.10.161 -u administrator -p pw",
        "RDP 10.10.10.161 3389 HOST [+] htb\\administrator:pw (Pwn3d!)\n")}
    assert {"rdp.authenticated", "foothold.windows", "access.admin"} <= facts


def test_nxc_rdp_failed_proves_nothing(tmp_path):
    ws = _ws(tmp_path)
    facts = {f.kind for f in _parse(
        ws, "nxc rdp 10.10.10.161 -u bob -p wrong",
        "RDP 10.10.10.161 3389 HOST [-] htb\\bob:wrong\n")}
    assert "rdp.authenticated" not in facts and "foothold.windows" not in facts
