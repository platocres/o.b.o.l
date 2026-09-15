"""The web surface over the engagement library: engagements, targets, the per-target
bundle, run-from-site, evidence, and BloodHound ingestion — all token-gated and over
one shared store."""
import io
import time
import zipfile
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("multipart")  # python-multipart, for file uploads
from fastapi.testclient import TestClient  # noqa: E402

from obol.facts import Fact  # noqa: E402
from obol.runner import RunResult  # noqa: E402
from obol.service import RunOutcome  # noqa: E402
from obol.webapp.server import create_app  # noqa: E402

TOKEN = "test-token"
H = {"X-Obol-Token": TOKEN}
FIXTURES = Path("/home/user/kaldox/pentos/tests/fixtures/sharphound")


@pytest.fixture
def cx(tmp_path):
    """A client on a fresh library with one engagement and one target."""
    client = TestClient(create_app(tmp_path, token=TOKEN))
    client.post("/api/engagements", json={"name": "Test Eng"}, headers=H)
    client.post("/api/targets", json={"host": "10.10.10.161", "label": "DC01"}, headers=H)
    return client


def test_token_required(cx):
    assert cx.get("/api/engagements").status_code == 401
    assert cx.get("/api/engagements", headers={"X-Obol-Token": "x"}).status_code == 401
    assert cx.get("/api/engagements", headers=H).status_code == 200
    assert cx.get(f"/api/engagements?token={TOKEN}").status_code == 200


def test_engagement_lifecycle(tmp_path):
    client = TestClient(create_app(tmp_path, token=TOKEN))
    assert client.get("/api/overview", headers=H).status_code == 404  # no active engagement yet
    r = client.post("/api/engagements", json={"name": "Alpha"}, headers=H).json()
    assert r["ok"] and r["slug"] == "alpha"
    engs = client.get("/api/engagements", headers=H).json()
    assert engs["active"] == "alpha" and len(engs["engagements"]) == 1
    # second engagement, switch active
    client.post("/api/engagements", json={"name": "Beta"}, headers=H)
    client.post("/api/engagements/activate", json={"slug": "alpha"}, headers=H)
    assert client.get("/api/engagements", headers=H).json()["active"] == "alpha"


def test_targets_and_bundle(cx):
    cx.post("/api/targets", json={"host": "10.10.10.5", "label": "WEB"}, headers=H)
    meta = cx.get("/api/meta", headers=H).json()
    assert {t["label"] for t in meta["targets"]} == {"DC01", "WEB"}
    b = cx.get("/api/target", params={"target": "10.10.10.161"}, headers=H).json()
    assert set(b) >= {"meta", "access", "phase", "chain", "next", "tools", "checklist",
                      "findings", "commands", "evidence", "graph", "facts_summary",
                      "facts_total", "quickstart"}
    # a bare target unlocks the nmap prelude (so you can start from the UI)
    assert any(a["id"] == "nmap-fast-open-ports" for a in b["next"])
    # the target bundle carries accumulated useful facts and a Quick Start plan
    assert b["facts_total"] >= 1
    assert b["quickstart"]["steps"][0]["action_id"] == "nmap-fast-open-ports"
    assert any(
        f["kind"] == "target.configured"
        for section in b["facts_summary"]
        for f in section["facts"]
    )
    # the static checklist covers every phase regardless of proof state
    assert [c["phase"] for c in b["checklist"]] == ["recon", "enum", "creds", "access", "escalate", "loot"]
    assert cx.get("/api/target", params={"target": "9.9.9.9"}, headers=H).status_code == 404


def test_scope_add_list_remove(cx):
    # adding a target already put its host in scope
    assert cx.get("/api/scope", headers=H).json()["scope"] == ["10.10.10.161"]
    # a CIDR range is kept verbatim; a host is normalized
    r = cx.post("/api/scope", json={"value": "10.10.10.0/24"}, headers=H).json()
    assert "10.10.10.0/24" in r["scope"] and r["added"] == "10.10.10.0/24"
    r = cx.post("/api/scope", json={"value": "http://10.10.10.9:8080/x"}, headers=H).json()
    assert r["added"] == "10.10.10.9" and "10.10.10.9" in r["scope"]
    # the overview and meta payloads both expose the authorization boundary
    assert "10.10.10.0/24" in cx.get("/api/overview", headers=H).json()["scope"]
    assert "10.10.10.0/24" in cx.get("/api/meta", headers=H).json()["scope"]
    # remove the range and the unused host, leaving the target's own entry
    assert cx.request("DELETE", "/api/scope", params={"value": "10.10.10.0/24"}, headers=H).status_code == 200
    cx.request("DELETE", "/api/scope", params={"value": "10.10.10.9"}, headers=H)
    assert cx.get("/api/scope", headers=H).json()["scope"] == ["10.10.10.161"]


def test_scope_add_rejects_garbage(cx):
    assert cx.post("/api/scope", json={"value": ""}, headers=H).status_code == 422
    assert cx.post("/api/scope", json={"value": "not a host!!"}, headers=H).status_code == 422


def test_scope_remove_guards_active_target_and_missing(cx):
    # a live target's authorization can't be pulled out from under it
    r = cx.request("DELETE", "/api/scope", params={"value": "10.10.10.161"}, headers=H)
    assert r.status_code == 409 and "target" in r.json()["detail"].lower()
    assert cx.get("/api/scope", headers=H).json()["scope"] == ["10.10.10.161"]
    # removing something not in scope is a 404
    assert cx.request("DELETE", "/api/scope", params={"value": "10.10.10.99"}, headers=H).status_code == 404


def test_run_from_site_scoped_to_target(cx):
    b = cx.get("/api/target", params={"target": "10.10.10.161"}, headers=H).json()
    action = next(a for a in b["next"] if a["id"] == "nmap-fast-open-ports")
    preflight = action["variants"][0]["preflight"]
    assert preflight["command"].endswith("10.10.10.161")
    assert preflight["missing_inputs"] == []
    assert preflight["parser"]["state"] == "supported"
    out = cx.post("/api/run/action",
                  json={"action_id": action["id"], "target": "10.10.10.161", "dry_run": True},
                  headers=H).json()
    assert out["dry_run"] is True and "10.10.10.161" in out["command"]
    assert out["success"] is True and out["status"] == "dry-run"
    assert out["message"] and out["facts"] == [] and out["added_count"] == 0


def test_run_unknown_and_missing(cx):
    assert cx.post("/api/run/action", json={"action_id": "nope"}, headers=H).status_code == 404
    assert cx.post("/api/run/action", json={}, headers=H).status_code == 422


def test_preflight_reports_missing_fact_prerequisite(cx):
    r = cx.get("/api/action/preflight",
               params={"action_id": "nmap-version-scripts", "target": "10.10.10.161"},
               headers=H)
    assert r.status_code == 200
    data = r.json()
    assert data["can_run"] is False
    assert "nmap_ports" in {i["name"] for i in data["missing_inputs"]}
    assert any(i["kind"] == "missing_input" for i in data["issues"])


def test_inputs_fill_command_tokens(cx):
    before = cx.get("/api/action/preflight",
                    params={"action_id": "asrep-roast", "target": "10.10.10.161"},
                    headers=H).json()
    assert {"userlist", "hashfile"}.issubset({i["name"] for i in before["missing_inputs"]})
    r = cx.post("/api/inputs",
                json={"target": "10.10.10.161",
                      "inputs": {"userlist": "users.txt", "hashfile": "hashes.asrep"}},
                headers=H)
    assert r.status_code == 200 and set(r.json()["saved"]) == {"userlist", "hashfile"}
    after = cx.get("/api/action/preflight",
                   params={"action_id": "asrep-roast", "target": "10.10.10.161"},
                   headers=H).json()
    assert "users.txt" in after["command"] and "hashes.asrep" in after["command"]
    assert not ({"userlist", "hashfile"} & {i["name"] for i in after["missing_inputs"]})


def test_playbook_steps_include_preflight(cx):
    pb = cx.get("/api/playbook/ad-recon", params={"target": "10.10.10.161"}, headers=H).json()
    assert pb["steps"]
    assert {"preflight", "command"}.issubset(pb["steps"][0])
    assert pb["steps"][0]["preflight"]["command"].endswith("10.10.10.161")


def test_quickstart_runs_nmap_then_nxc_when_unlocked(cx, monkeypatch):
    import obol.webapp.server as server

    calls = []

    def fake_which(binary):
        return f"/usr/bin/{binary}" if binary in {"nmap", "nxc"} else None

    def fake_run_action(ws, action, **kwargs):
        target = kwargs.get("target") or ws.target
        calls.append((action.id, kwargs.get("command_index", 0)))
        if action.id == "nmap-fast-open-ports":
            added = [
                Fact("host.up", f"host:{target}", {"target": target}, source="fake nmap"),
                Fact("scan.nmap.quick", f"host:{target}", {"ports": [445]}, source="fake nmap"),
                Fact("ports.open", f"host:{target}", {"ports": [445]}, source="fake nmap"),
                Fact("port:445", f"host:{target}", {"port": 445, "service": "microsoft-ds"}, source="fake nmap"),
            ]
        else:
            added = [Fact("smb.reachable", f"host:{target}", {"tool": "nxc"}, source="fake nxc")]
        for fact in added:
            ws.facts.add(fact)
        ws.record_run(action.tool, f"fake {action.id} {target}", [f.kind for f in added],
                      action_id=action.id, command_index=kwargs.get("command_index", 0) + 1,
                      returncode=0, timed_out=False, dry_run=False, target=target, quickstart=True)
        ws.save()
        result = RunResult(f"fake {action.id} {target}", ["fake", target], 0, "", "",
                           ws.runs_dir / "stdout.txt", ws.runs_dir / "stderr.txt", 0.0, 1)
        return RunOutcome(action.id, result.command, action.tool, result, added)

    monkeypatch.setattr(server.shutil, "which", fake_which)
    monkeypatch.setattr(server, "run_action", fake_run_action)

    started = cx.post("/api/run/quickstart", json={"target": "10.10.10.161"}, headers=H).json()

    assert started["quickstart"] is True
    assert started["pending"] is True
    assert started["job_id"]
    assert started["steps"][0]["status"] in {"queued", "running"}

    out = started
    for _ in range(50):
        out = cx.get(f"/api/quickstart/jobs/{started['job_id']}", headers=H).json()
        if not out["pending"]:
            break
        time.sleep(0.02)

    assert out["pending"] is False
    assert out["status"] == "success"
    assert calls[0] == ("nmap-fast-open-ports", 0)
    assert ("gpp-passwords", 0) in calls  # nxc smb --shares is the first SMB/GPP variant
    assert {f["kind"] for f in out["facts"]} >= {"port:445", "smb.reachable"}
    steps = {step["action_id"]: step for step in out["steps"]}
    assert steps["nmap-fast-open-ports"]["status"] == "success"
    assert steps["gpp-passwords"]["added_count"] >= 1


def test_sweep_discovers_hosts_and_creates_targets(cx, monkeypatch):
    import obol.webapp.server as server

    # authorize a range, then sweep it — the real nmap is faked out
    cx.post("/api/scope", json={"value": "10.10.10.0/24"}, headers=H)

    def fake_run_sweep(ws, range_, **kwargs):
        for host in ("10.10.10.5", "10.10.10.7"):
            ws.add_target(host)
        ws.save()
        return {"range": range_, "command": f"nmap -sn {range_}", "dry_run": False,
                "returncode": 0, "timed_out": False,
                "hosts": ["10.10.10.5", "10.10.10.7"],
                "created": ["10.10.10.5", "10.10.10.7"], "existing": []}

    monkeypatch.setattr(server.discovery, "run_sweep", fake_run_sweep)

    started = cx.post("/api/run/sweep",
                      json={"range": "10.10.10.0/24", "enumerate": False}, headers=H).json()
    assert started["kind"] == "sweep" and started["pending"] is True and started["job_id"]

    out = started
    for _ in range(100):
        out = cx.get(f"/api/sweep/jobs/{started['job_id']}", headers=H).json()
        if not out["pending"]:
            break
        time.sleep(0.02)
    assert out["pending"] is False and out["status"] == "success"
    assert set(out["created"]) == {"10.10.10.5", "10.10.10.7"}
    # the new hosts are now real targets in the engagement
    hosts = {t["host"] for t in cx.get("/api/meta", headers=H).json()["targets"]}
    assert {"10.10.10.5", "10.10.10.7"}.issubset(hosts)


def test_sweep_refuses_unauthorized_range(cx):
    # 192.168.0.0/24 was never added to scope
    r = cx.post("/api/run/sweep", json={"range": "192.168.0.0/24"}, headers=H)
    assert r.status_code == 400 and "scope" in r.json()["detail"].lower()
    assert cx.post("/api/run/sweep", json={"range": ""}, headers=H).status_code == 422


def test_sweep_chains_quickstart_enumeration_per_host(cx, monkeypatch):
    import obol.webapp.server as server

    cx.post("/api/scope", json={"value": "10.10.10.0/24"}, headers=H)

    def fake_run_sweep(ws, range_, **kwargs):
        for host in ("10.10.10.5", "10.10.10.7"):
            ws.add_target(host)
        ws.save()
        return {"range": range_, "command": f"nmap -sn {range_}", "dry_run": False,
                "returncode": 0, "timed_out": False,
                "hosts": ["10.10.10.5", "10.10.10.7"],
                "created": ["10.10.10.5", "10.10.10.7"], "existing": []}

    enum_hosts = []

    def fake_which(binary):
        return f"/usr/bin/{binary}" if binary in {"nmap", "nxc"} else None

    def fake_run_action(ws, action, **kwargs):
        # the sweep's enumeration fan-out drives Quick Start, which calls run_action
        target = kwargs.get("target") or ws.target
        enum_hosts.append((action.id, target))
        added = ([Fact("port:445", f"host:{target}", {"port": 445, "service": "microsoft-ds"}, source="fake")]
                 if action.id == "nmap-fast-open-ports" else
                 [Fact("smb.reachable", f"host:{target}", {"tool": "nxc"}, source="fake")])
        for fact in added:
            ws.facts.add(fact)
        ws.record_run(action.tool, f"fake {action.id} {target}", [f.kind for f in added],
                      action_id=action.id, command_index=kwargs.get("command_index", 0) + 1,
                      returncode=0, timed_out=False, dry_run=False, target=target)
        ws.save()
        result = RunResult(f"fake {action.id}", ["fake", target], 0, "", "",
                           ws.runs_dir / "o.txt", ws.runs_dir / "e.txt", 0.0, 1)
        return RunOutcome(action.id, result.command, action.tool, result, added)

    monkeypatch.setattr(server.discovery, "run_sweep", fake_run_sweep)
    monkeypatch.setattr(server.shutil, "which", fake_which)
    monkeypatch.setattr(server, "run_action", fake_run_action)

    started = cx.post("/api/run/sweep", json={"range": "10.10.10.0/24"}, headers=H).json()
    out = started
    for _ in range(200):
        out = cx.get(f"/api/sweep/jobs/{started['job_id']}", headers=H).json()
        if not out["pending"]:
            break
        time.sleep(0.02)

    assert out["status"] == "success"
    # both discovered hosts were enumerated, and enumeration actually ran per host
    assert set(out["enumerated"]) == {"10.10.10.5", "10.10.10.7"}
    assert out["enum_jobs"] and len(out["enum_jobs"]) == 2
    hosts_enumerated = {h for _, h in enum_hosts}
    assert hosts_enumerated == {"10.10.10.5", "10.10.10.7"}
    assert ("nmap-fast-open-ports", "10.10.10.5") in enum_hosts
    # the per-host baseline populated facts on each new target
    b = cx.get("/api/target", params={"target": "10.10.10.7"}, headers=H).json()
    assert any(f["kind"] == "port:445" for f in b["findings"])


def test_checklist_toggle_persists(cx):
    assert cx.post("/api/target/checklist",
                   json={"target": "10.10.10.161", "item": "ad-dc-identify", "checked": True},
                   headers=H).status_code == 200
    b = cx.get("/api/target", params={"target": "10.10.10.161"}, headers=H).json()
    items = {i["id"]: i["checked"] for c in b["checklist"] for i in c["items"]}
    assert items.get("ad-dc-identify") is True


def test_evidence_upload_fetch_delete(cx):
    r = cx.post("/api/target/evidence",
                data={"target": "10.10.10.161", "phase": "access", "caption": "winrm shell"},
                files={"file": ("shell.png", b"\x89PNG\r\n\x1a\n fake", "image/png")}, headers=H)
    assert r.status_code == 200
    eid = r.json()["evidence"]["id"]
    got = cx.get(f"/api/evidence/{eid}", headers=H)
    assert got.status_code == 200 and got.content.startswith(b"\x89PNG")
    b = cx.get("/api/target", params={"target": "10.10.10.161"}, headers=H).json()
    assert any(e["id"] == eid for e in b["evidence"])
    assert cx.delete(f"/api/evidence/{eid}", headers=H).status_code == 200
    assert cx.get(f"/api/evidence/{eid}", headers=H).status_code == 404


@pytest.mark.skipif(not FIXTURES.exists(), reason="bloodhound fixtures not present")
def test_bloodhound_ingest_and_engagement_graph(cx):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for f in FIXTURES.glob("*.json"):
            zf.write(f, f.name)
    r = cx.post("/api/bloodhound",
                files=[("files", ("bh.zip", buf.getvalue(), "application/zip"))], headers=H)
    assert r.status_code == 200
    data = r.json()
    assert data["domain"] and data["users"] > 0
    assert "ad.graph.collected" in data["added_facts"]
    g = cx.get("/api/engagement/graph", headers=H).json()
    assert any(n["type"] == "target" for n in g["nodes"])
    assert any(n["type"] in ("highvalue", "roastable") for n in g["nodes"])


def test_report_and_overview(cx):
    assert cx.get("/api/overview", headers=H).status_code == 200
    assert cx.get("/api/report", headers=H).status_code == 200
    assert cx.get("/api/report.md", headers=H).status_code == 200
    assert cx.get("/", ).status_code == 200
    assert cx.get("/static/style.css").status_code == 200


def test_events_route_is_wired_and_gated(cx):
    assert cx.get("/api/events").status_code == 401
    assert "/api/events" in {getattr(r, "path", None) for r in cx.app.routes}


def test_engagement_activity_rolls_up_findings_by_category_and_host(cx):
    """0e: the engagement-level findings roll-up groups proven facts by category and
    tags each with the host that produced it, across every target."""
    cx.post("/api/targets", json={"host": "10.10.10.5", "label": "WEB"}, headers=H)
    # facts must be attached through the store both surfaces share
    import obol.webapp.server as server
    from obol import library
    ws = library.resolve_active()
    ws.facts.add(Fact("port:445", "host:10.10.10.161", {"port": 445, "service": "microsoft-ds"}, source="nmap -p-"))
    ws.facts.add(Fact("smb.reachable", "host:10.10.10.161", {"tool": "nxc"}, source="nxc smb"))
    ws.facts.add(Fact("port:80", "host:10.10.10.5", {"port": 80, "service": "http"}, source="nmap -p-"))
    ws.facts.add(Fact("ad.domain_known", "domain:htb.local", {"name": "htb.local"}, source="nxc ldap"))
    ws.save()

    a = cx.get("/api/engagement/activity", headers=H).json()
    assert set(a) >= {"jobs", "active_count", "timeline", "findings", "findings_total", "hosts"}
    by_cat = {c["id"]: c for c in a["findings"]}
    # port:445 / smb.reachable land in target/service categories, tagged to their host
    tgt_hosts = {f["host"] for f in by_cat["target"]["findings"]}
    assert "10.10.10.161" in tgt_hosts and "10.10.10.5" in tgt_hosts
    assert any(f["kind"] == "smb.reachable" and f["host"] == "10.10.10.161"
               for f in by_cat["service"]["findings"])
    # a domain-scoped fact rolls up with no host, tagged as domain-scoped
    ad = [f for f in by_cat["ad"]["findings"] if f["kind"] == "ad.domain_known"][0]
    assert ad["host"] == "" and ad["origin"] == "htb.local" and ad["origin_kind"] == "domain"
    # per-host counts drive the filter chips
    counts = {h["host"]: h["count"] for h in a["hosts"]}
    assert counts["10.10.10.161"] >= 2 and counts["10.10.10.5"] >= 1


def test_privesc_facts_show_on_host_and_engagement_pages(cx):
    from obol import library

    ws = library.resolve_active()
    ws.facts.add(Fact("foothold.linux", "host:10.10.10.161", {"service": "ssh"}, source="ssh id"))
    ws.facts.add(Fact("privesc.sudo_rights", "host:10.10.10.161",
                      {"entries": ["(root) NOPASSWD: /usr/bin/find"]}, source="sudo -l"))
    ws.facts.add(Fact("privesc.leads", "host:10.10.10.161",
                      {"kinds": ["privesc.sudo_rights"], "count": 1}, source="sudo -l"))
    ws.save()

    target = cx.get("/api/target", params={"target": "10.10.10.161"}, headers=H).json()
    assert any(section["id"] == "privesc" for section in target["facts_summary"])
    privesc = next(section for section in target["facts_summary"] if section["id"] == "privesc")
    assert {fact["kind"] for fact in privesc["facts"]} >= {"privesc.sudo_rights", "privesc.leads"}
    assert any(f["kind"] == "privesc.sudo_rights" and f["category"] == "privesc" for f in target["findings"])
    assert any(action["id"] == "sudo-abuse" for action in target["next"])

    activity = cx.get("/api/engagement/activity", headers=H).json()
    by_cat = {category["id"]: category for category in activity["findings"]}
    assert "privesc" in by_cat
    assert any(f["kind"] == "privesc.sudo_rights" for f in by_cat["privesc"]["findings"])


def test_login_flow_opens_session_and_bundle_surfaces_it(cx, monkeypatch):
    """§6a over the web: a login validates access through the shared runner, records
    a live session, and the target bundle surfaces sessions + eligible logins. The
    full login command (with the password) is shown — this is the operator's box."""
    from obol import library, service
    from obol.runner import RunResult

    ws = library.resolve_active()
    ws.facts.add(Fact("winrm.reachable", "host:10.10.10.161", {"tool": "nxc"}, source="x"))
    ws.facts.add(Fact("credential.available", "host:10.10.10.161",
                      {"user": "svc-alfresco", "password": "s3rvice"}, source="crack"))
    ws.save()

    def fake_run_command(ws, command, tool, **kw):
        return RunResult(command, command.split(), 0,
                         "WINRM 10.10.10.161 5985 FOREST [+] htb\\svc-alfresco\nhtb\\svc-alfresco\n",
                         "", ws.runs_dir / "o.txt", ws.runs_dir / "e.txt", 5.0, 1)
    monkeypatch.setattr(service, "run_command", fake_run_command)

    # eligible logins appear in the bundle before we log in
    b = cx.get("/api/target", params={"target": "10.10.10.161"}, headers=H).json()
    assert any(o["kind"] == "winrm" and o["ready"] for o in b["logins"])

    r = cx.post("/api/run/login", json={"target": "10.10.10.161", "kind": "winrm"}, headers=H).json()
    assert r["ok"] and r["session"]["kind"] == "winrm" and r["session"]["status"] == "active"
    assert "evil-winrm" in r["session"]["login_command"] and "s3rvice" in r["session"]["login_command"]

    b = cx.get("/api/target", params={"target": "10.10.10.161"}, headers=H).json()
    assert [s["kind"] for s in b["sessions"]] == ["winrm"]
    # the login unlocked the Windows foothold on this host
    assert any(f["kind"] == "foothold.windows" for f in b["findings"])

    # close it
    sid = b["sessions"][0]["id"]
    assert cx.post("/api/session/close", json={"id": sid}, headers=H).status_code == 200
    b = cx.get("/api/target", params={"target": "10.10.10.161"}, headers=H).json()
    assert b["sessions"][0]["status"] == "closed"


def test_login_requires_target_and_kind(cx):
    assert cx.post("/api/run/login", json={"target": "10.10.10.161"}, headers=H).status_code == 422
    assert cx.post("/api/run/login", json={"kind": "winrm"}, headers=H).status_code == 422


def test_tunnel_flow_over_web_extends_scope_and_surfaces_in_bundle(cx):
    """§6d over the web: a foothold surfaces pivot candidates and tunnel offers; opening
    a tunnel auto-extends scope to its subnet and records live state the bundle shows."""
    from obol import library

    ws = library.resolve_active()
    s = "host:10.10.10.161"
    ws.facts.add(Fact("foothold.linux", s, {}, source="ssh id"))
    ws.facts.add(Fact("host.os_family", s, {"family": "linux"}, source="ssh id"))
    ws.facts.add(Fact("credential.available", s, {"user": "bob", "password": "pw123"}, source="crack"))
    ws.facts.add(Fact("host.multihomed", s, {"interfaces": 2, "subnets": ["172.16.20.0/24"]}, source="ip"))
    ws.facts.add(Fact("network.subnet_candidate", s, {"cidr": "172.16.20.0/24"}, source="ip"))
    ws.facts.add(Fact("pivot.candidate", s, {"reasons": ["multiple interface networks"],
                                             "subnets": ["172.16.20.0/24"]}, source="ip"))
    ws.save()

    b = cx.get("/api/target", params={"target": "10.10.10.161"}, headers=H).json()
    assert b["pivots"]["multihomed"] is True
    assert "172.16.20.0/24" in b["pivots"]["unscoped_subnets"]
    kinds = {k["kind"]: k for k in b["tunnel_kinds"]}
    assert kinds["chisel"]["proxychains"] is True and kinds["ligolo"]["proxychains"] is False

    r = cx.post("/api/run/tunnel", json={"target": "10.10.10.161", "kind": "chisel",
                                         "subnet": "172.16.20.0/24", "lhost": "10.10.14.7"}, headers=H).json()
    assert r["ok"] and r["proxychains"] is True and r["scope_added"] == "172.16.20.0/24"
    assert "chisel" in r["setup_command"]

    # scope auto-extended and the live tunnel surfaces in the bundle
    meta = cx.get("/api/meta", headers=H).json()
    assert "172.16.20.0/24" in meta["scope"]
    b = cx.get("/api/target", params={"target": "10.10.10.161"}, headers=H).json()
    assert [(t["kind"], t["status"], t["exposed_subnet"]) for t in b["tunnels"]] \
        == [("chisel", "up", "172.16.20.0/24")]

    # remove retracts the auto-added scope (no target discovered inside it yet)
    tid = b["tunnels"][0]["id"]
    rr = cx.request("DELETE", "/api/tunnel", params={"id": tid}, headers=H).json()
    assert rr["scope_retracted"] == "172.16.20.0/24"
    assert "172.16.20.0/24" not in cx.get("/api/meta", headers=H).json()["scope"]


def test_tunnel_requires_target_and_kind(cx):
    assert cx.post("/api/run/tunnel", json={"target": "10.10.10.161"}, headers=H).status_code == 422
    assert cx.post("/api/run/tunnel", json={"kind": "chisel"}, headers=H).status_code == 422


def test_engagement_wide_redact_switch(cx):
    """One switch the whole SPA respects: with include_secrets=0 every read surface —
    per-target findings, the engagement findings roll-up, and the command ledger —
    redacts secrets; by default (show-by-default product call) they are shown."""
    from obol import library

    ws = library.resolve_active()
    ws.facts.add(Fact("credential.available", "host:10.10.10.161",
                      {"user": "bob", "password": "S3cret!"}, source="crack"))
    ws.record_run("nxc", "nxc smb 10.10.10.161 -u bob -p S3cret!", ["credential.available"],
                  target="10.10.10.161", action_id="x")
    ws.save()

    # default: secrets shown across findings, roll-up, and the command ledger
    b = cx.get("/api/target", params={"target": "10.10.10.161"}, headers=H).json()
    assert any(f.get("value", {}).get("password") == "S3cret!" for f in b["findings"])
    act = cx.get("/api/engagement/activity", headers=H).json()
    rollup = [f for cat in act["findings"] for f in cat["findings"]]
    assert any(f.get("value", {}).get("password") == "S3cret!" for f in rollup)
    assert any("S3cret!" in r["command"] for r in act["timeline"])

    # redact switch on (include_secrets=0): the same three surfaces hide the secret
    b = cx.get("/api/target", params={"target": "10.10.10.161", "include_secrets": "0"}, headers=H).json()
    assert all(f.get("value", {}).get("password") != "S3cret!" for f in b["findings"])
    assert not any("S3cret!" in c["command"] for c in b["commands"])
    act = cx.get("/api/engagement/activity", params={"include_secrets": "0"}, headers=H).json()
    rollup = [f for cat in act["findings"] for f in cat["findings"]]
    assert all(f.get("value", {}).get("password") != "S3cret!" for f in rollup)
    assert all("S3cret!" not in r["command"] for r in act["timeline"])

    # a subsequent default request is not poisoned by the earlier redacted one
    b = cx.get("/api/target", params={"target": "10.10.10.161"}, headers=H).json()
    assert any(f.get("value", {}).get("password") == "S3cret!" for f in b["findings"])


def test_engagement_activity_surfaces_running_jobs_and_ledger(cx, monkeypatch):
    """0e: an in-flight Quick Start job shows up in the engagement run feed, and its
    committed command appears in the cross-host ledger once it finishes."""
    import obol.webapp.server as server

    monkeypatch.setattr(server.shutil, "which",
                        lambda b: f"/usr/bin/{b}" if b in {"nmap", "nxc"} else None)

    def fake_run_action(ws, action, **kwargs):
        target = kwargs.get("target") or ws.target
        added = [Fact("host.up", f"host:{target}", {"target": target}, source="fake nmap")]
        if action.id == "nmap-fast-open-ports":
            added.append(Fact("port:445", f"host:{target}", {"port": 445, "service": "microsoft-ds"}, source="fake nmap"))
        for f in added:
            ws.facts.add(f)
        ws.record_run(action.tool, f"fake {action.id} {target}", [f.kind for f in added],
                      action_id=action.id, target=target, returncode=0, timed_out=False,
                      dry_run=False, quickstart=True)
        ws.save()
        result = RunResult(f"fake {action.id} {target}", ["fake", target], 0, "", "",
                           ws.runs_dir / "o.txt", ws.runs_dir / "e.txt", 0.0, 1)
        return RunOutcome(action.id, result.command, action.tool, result, added)

    monkeypatch.setattr(server, "run_action", fake_run_action)

    started = cx.post("/api/run/quickstart", json={"target": "10.10.10.161"}, headers=H).json()
    jid = started["job_id"]

    # the running job is visible in the engagement feed while pending
    a = cx.get("/api/engagement/activity", headers=H).json()
    job = next((j for j in a["jobs"] if j["id"] == jid), None)
    assert job is not None and job["kind"] == "quickstart" and job["target"] == "10.10.10.161"

    for _ in range(100):
        if not cx.get(f"/api/quickstart/jobs/{jid}", headers=H).json()["pending"]:
            break
        time.sleep(0.02)

    a = cx.get("/api/engagement/activity", headers=H).json()
    assert a["active_count"] == 0
    # the finished command is now in the cross-host ledger, tagged with its host
    assert any(r["target"] == "10.10.10.161" and r["produced"] for r in a["timeline"])


def test_profile_endpoint_get_set_and_meta(cx):
    # default profile is the safe custom fallback, and the preset catalogue is served
    r = cx.get("/api/profile", headers=H).json()
    assert r["config"]["platform"] == "custom"
    assert {p["id"] for p in r["presets"]} >= {"htb", "oscp", "thm", "ctf", "custom"}

    # set a platform; the resolved flag config follows the preset
    r = cx.post("/api/profile", json={"platform": "htb"}, headers=H).json()
    assert r["ok"] and r["config"]["names"] == ["user.txt", "root.txt"]

    # it surfaces on meta and overview for the SPA to render
    assert cx.get("/api/meta", headers=H).json()["profile"]["platform"] == "htb"
    assert cx.get("/api/overview", headers=H).json()["profile"]["platform"] == "htb"

    # an unknown platform is rejected
    assert cx.post("/api/profile", json={"platform": "nope"}, headers=H).status_code == 422

    # custom override of names/formats
    r = cx.post("/api/profile", json={"platform": "custom", "flag_names": ["x.txt"], "flag_formats": ["brace"]}, headers=H).json()
    assert r["config"]["names"] == ["x.txt"] and r["config"]["formats"] == ["brace"]


def test_cruise_objectives_and_ingest_endpoints(cx):
    # objectives ladder for the seeded target — nothing reached yet
    r = cx.get("/api/objectives?host=10.10.10.161", headers=H).json()
    assert r["total"] == 4 and r["reached"] == 0 and not r["complete"]

    # paste-and-parse ingestion records operator-sourced facts
    nmap = "PORT     STATE SERVICE\n22/tcp   open  ssh\n"
    r = cx.post("/api/ingest", json={"text": nmap, "note": "nmap -sV 10.10.10.161",
                                     "target": "10.10.10.161"}, headers=H).json()
    assert r["ok"] and "port:22" in r["added"]
    # empty ingest is rejected
    assert cx.post("/api/ingest", json={"text": "  "}, headers=H).status_code == 422

    # operator-attested assertion completes the objective and cruise then stops on it
    cx.post("/api/assert", json={"kind": "objective.root_flag", "target": "10.10.10.161",
                                 "note": "read by hand"}, headers=H)
    r = cx.get("/api/objectives?host=10.10.10.161", headers=H).json()
    assert r["complete"]
    c = cx.post("/api/cruise", json={"host": "10.10.10.161"}, headers=H).json()
    assert c["stop_reason"] == "objective-complete"
    assert c["briefing"]["objectives"]["complete"]

    # a bad assert (no kind) is a 422
    assert cx.post("/api/assert", json={"note": "x"}, headers=H).status_code == 422
