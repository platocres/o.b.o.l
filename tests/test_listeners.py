"""Listener layer (§8/§6a): reverse-shell payloads, listener live state, and the
proof-bound catch that records the access fact only from captured shell output."""
import pytest

from obol import library, listeners


def _ws(tmp_path, host="10.10.10.5"):
    library.set_base(tmp_path)
    library.engagements_dir().mkdir(parents=True, exist_ok=True)
    ws = library.create_engagement("E")
    ws.add_target(host)
    ws.target = host
    ws.save()
    return ws, host


def test_reverse_payloads_fill_lhost_lport():
    lin = listeners.reverse_payloads("linux", "10.8.0.5", 4444)
    names = {p["name"] for p in lin}
    assert {"bash-devtcp", "nc-mkfifo", "python3"} <= names
    devtcp = next(p for p in lin if p["name"] == "bash-devtcp")
    assert "10.8.0.5" in devtcp["command"] and "4444" in devtcp["command"]
    win = listeners.reverse_payloads("windows", "10.8.0.5", 4444)
    assert any("New-Object Net.Sockets.TCPClient" in p["command"] for p in win)


def test_start_listener_records_live_state_and_returns_command(tmp_path):
    ws, host = _ws(tmp_path)
    res = listeners.start_listener(ws, 9001, kind="nc", lhost="10.8.0.5", host=host, os_name="linux")
    assert res["ok"] and "nc -lvnp 9001" in res["listen_command"]
    assert res["payloads"] and res["listener"]["status"] == "listening"
    # persisted as live state
    ws2 = library.get_engagement(ws.root.name)
    assert [(l["kind"], l["port"], l["status"]) for l in ws2.listeners] == [("nc", 9001, "listening")]


def test_start_listener_rejects_bad_kind_and_port(tmp_path):
    ws, host = _ws(tmp_path)
    with pytest.raises(listeners.ListenerError):
        listeners.start_listener(ws, 9001, kind="not-a-kind")
    with pytest.raises(listeners.ListenerError):
        listeners.start_listener(ws, 99999, kind="nc")


def test_catch_without_proof_flips_status_but_records_no_fact(tmp_path):
    ws, host = _ws(tmp_path)
    ln = listeners.start_listener(ws, 9001, kind="nc", host=host)["listener"]
    res = listeners.record_catch(ws, ln["id"], host=host)
    assert res["ok"] and res["proof_fact"] == "" and res["session"] is None
    assert ws.get_listener(ln["id"])["status"] == "caught"
    # no access/foothold fact invented (only the auto target.configured marker exists)
    tf = ws.facts_for_target(host)
    assert not any(f.kind.startswith(("access.", "foothold.")) for f in tf.facts)


def test_catch_with_root_proof_records_access_and_session(tmp_path):
    ws, host = _ws(tmp_path)
    ln = listeners.start_listener(ws, 9001, kind="nc", host=host)["listener"]
    res = listeners.record_catch(ws, ln["id"], host=host,
                                 proof_output="uid=0(root) gid=0(root) groups=0(root)")
    assert res["proof_fact"] == "access.admin"
    assert ws.facts_for_target(host).has("access.admin")
    assert res["session"] and res["session"]["kind"] == "revshell"
    assert ws.get_listener(ln["id"])["status"] == "caught"


def test_close_and_remove(tmp_path):
    ws, host = _ws(tmp_path)
    ln = listeners.start_listener(ws, 9001, kind="nc", host=host)["listener"]
    assert listeners.close_listener(ws, ln["id"])
    assert ws.get_listener(ln["id"])["status"] == "closed"
    assert listeners.remove_listener(ws, ln["id"])
    assert ws.get_listener(ln["id"]) is None


# ── web endpoints ──────────────────────────────────────────────────────────────
fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402
from obol.webapp.server import create_app  # noqa: E402

H = {"X-Obol-Token": "t"}


def test_listener_endpoints(tmp_path):
    ws, host = _ws(tmp_path)
    library.set_active(ws.root.name)
    cx = TestClient(create_app(tmp_path, token="t"))
    r = cx.post("/api/listener/start", json={"port": 9001, "kind": "nc", "host": host}, headers=H)
    assert r.status_code == 200 and r.json()["listener"]["status"] == "listening"
    lid = r.json()["listener"]["id"]
    lst = cx.get("/api/listeners", headers=H).json()["listeners"]
    assert lst and lst[0]["id"] == lid
    c = cx.post("/api/listener/catch",
                json={"id": lid, "host": host, "proof": "uid=0(root) gid=0(root) groups=0(root)"}, headers=H)
    assert c.status_code == 200 and c.json()["proof_fact"] == "access.admin"
    assert cx.request("DELETE", "/api/listener", params={"id": lid}, headers=H).status_code == 200
