"""The web surface over the engagement library: engagements, targets, the per-target
bundle, run-from-site, evidence, and BloodHound ingestion — all token-gated and over
one shared store."""
import io
import zipfile
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("multipart")  # python-multipart, for file uploads
from fastapi.testclient import TestClient  # noqa: E402

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
