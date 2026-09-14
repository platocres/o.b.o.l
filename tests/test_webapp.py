"""The web surface: token gate, read endpoints, and run-from-site through the same
scope-enforced runner/parser/store as the terminal."""
from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from obol.seed import seed_forest  # noqa: E402
from obol.webapp.server import create_app  # noqa: E402
from obol.workspace import Workspace  # noqa: E402

TOKEN = "test-token"
H = {"X-Obol-Token": TOKEN}


@pytest.fixture
def client(tmp_path):
    ws = Workspace(tmp_path)
    seed_forest(ws)
    ws.save()
    return TestClient(create_app(tmp_path, token=TOKEN)), tmp_path


def test_token_required(client):
    cx, _ = client
    assert cx.get("/api/overview").status_code == 401
    assert cx.get("/api/overview", headers={"X-Obol-Token": "nope"}).status_code == 401
    assert cx.get("/api/overview", headers=H).status_code == 200
    # query-param token also accepted (used by the SSE stream)
    assert cx.get(f"/api/overview?token={TOKEN}").status_code == 200


def test_read_endpoints(client):
    cx, _ = client
    for ep in ("/api/meta", "/api/overview", "/api/findings", "/api/graph",
               "/api/next", "/api/playbooks", "/api/report", "/api/report.md"):
        assert cx.get(ep, headers=H).status_code == 200, ep
    ov = cx.get("/api/overview", headers=H).json()
    assert ov["tiles"]["facts"] > 0
    assert any(seg["reached"] for seg in ov["access_ladder"])
    assert cx.get("/").status_code == 200
    assert cx.get("/static/style.css").status_code == 200


def test_next_actions_carry_command_preview(client):
    cx, _ = client
    actions = cx.get("/api/next", headers=H).json()["actions"]
    assert actions
    a = actions[0]
    assert a["id"] and a["phase"] and a["variants"]
    assert a["variants"][0]["command"]


def test_run_from_site_dry_run_ingests_nothing(client):
    cx, root = client
    a = cx.get("/api/next", headers=H).json()["actions"][0]
    before = len(cx.get("/api/findings", headers=H).json()["findings"])
    out = cx.post("/api/run/action", json={"action_id": a["id"], "dry_run": True}, headers=H).json()
    assert out["dry_run"] is True and out["added_count"] == 0
    after = len(cx.get("/api/findings", headers=H).json()["findings"])
    assert after == before
    # but the dry run IS recorded in the shared ledger, tagged as web-launched
    assert Workspace(root).load().runs[-1]["surface"] == "web"


def test_run_unknown_action_404(client):
    cx, _ = client
    assert cx.post("/api/run/action", json={"action_id": "nope"}, headers=H).status_code == 404


def test_run_missing_action_id_422(client):
    cx, _ = client
    assert cx.post("/api/run/action", json={}, headers=H).status_code == 422


def test_run_real_missing_binary_is_400_not_500(client):
    """A runner refusal (here: the tool binary isn't installed) surfaces as a clean
    400, never an unhandled 500."""
    cx, _ = client
    a = cx.get("/api/next", headers=H).json()["actions"][0]
    r = cx.post("/api/run/action", json={"action_id": a["id"], "dry_run": False}, headers=H)
    assert r.status_code == 400
    assert "not found" in r.json()["detail"].lower() or "scope" in r.json()["detail"].lower()


def test_playbook_endpoints_and_approval_gate(client):
    cx, _ = client
    pbs = cx.get("/api/playbooks", headers=H).json()["playbooks"]
    if not pbs:
        pytest.skip("no playbooks shipped")
    name = pbs[0]["name"]
    pb = cx.get(f"/api/playbook/{name}", headers=H).json()
    assert pb["steps"]
    approval_steps = [s for s in pb["steps"] if s["require_approval"]]
    if approval_steps:
        step = approval_steps[0]["step"]
        # without approve and not dry_run -> 409 require_approval
        r = cx.post("/api/run/playbook", json={"name": name, "step": step}, headers=H)
        assert r.status_code == 409


def test_events_route_is_wired_and_gated(client):
    # The SSE stream is intentionally infinite, so we don't consume it here (that
    # would hang the sync TestClient at teardown). Assert instead that the route
    # exists and enforces the token — the streaming behavior is smoke-tested by
    # running the server for real.
    cx, _ = client
    assert cx.get("/api/events").status_code == 401
    paths = {getattr(r, "path", None) for r in cx.app.routes}
    assert "/api/events" in paths
