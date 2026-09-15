"""Transfer layer (§8): the channel registry, the fallback cascade, verify, and
staged-material live state. No network and no live target — `service.run_command`
is faked (which also bypasses the scope gate, like the sessions tests)."""
import hashlib

import pytest

from obol import library, provision, service, staging
from obol.facts import Fact
from obol.runner import RunResult


LINPEAS = b"#!/bin/sh\necho enum\n"
LINPEAS_SHA = hashlib.sha256(LINPEAS).hexdigest()


def _fake_fetcher(content):
    def fetch(url, dest, timeout=0):
        from pathlib import Path
        Path(dest).write_bytes(content)
        return len(content)
    return fetch


def _linux_foothold(tmp_path, host="10.10.10.5"):
    library.set_base(tmp_path)
    library.engagements_dir().mkdir(parents=True, exist_ok=True)
    ws = library.create_engagement("E")
    ws.add_target(host)
    ws.target = host
    ws.facts.add(Fact("foothold.linux", f"host:{host}", {"tool": "ssh"}, source="login"))
    ws.facts.add(Fact("credential.available", f"host:{host}",
                      {"user": "bob", "password": "hunter2"}, source="crack"))
    ws.save()
    # cache the material so a push has a local file
    provision.download("linpeas", fetcher=_fake_fetcher(LINPEAS))
    return ws, host


def _seq_runner(results):
    """A fake runner returning (rc, stdout) per call, in order, writing stdout to the
    outcome's stdout_path so the verify step can read it back."""
    calls = {"i": 0}

    def run(ws, command, tool, **kw):
        i = calls["i"]
        calls["i"] += 1
        rc, out = results[i] if i < len(results) else (0, "")
        ws.runs_dir.mkdir(parents=True, exist_ok=True)
        op = ws.runs_dir / f"o{i}.txt"
        op.write_text(out)
        ep = ws.runs_dir / f"e{i}.txt"
        ep.write_text("")
        return RunResult(command, command.split(), rc, out, "", op, ep, 5.0, 1)
    return run


def test_eligible_channels_for_linux_foothold(tmp_path):
    ws, host = _linux_foothold(tmp_path)
    rows = {r["key"]: r for r in staging.eligible_channels(ws, host)}
    assert "scp" in rows and rows["scp"]["os"] == "linux"
    assert rows["scp"]["ready"] is True         # password cred present
    # no windows channels offered for a linux foothold
    assert all(r["os"] == "linux" for r in rows.values())


def test_plan_is_dry_and_fills_commands(tmp_path):
    ws, host = _linux_foothold(tmp_path)
    p = staging.plan(ws, host, "linpeas", channels=["scp"])
    assert p["steps"] and p["steps"][0]["channel"] == "scp"
    cmd = p["steps"][0]["command"]
    assert "scp" in cmd and "bob@10.10.10.5" in cmd and "hunter2" in cmd
    assert "/tmp/linpeas.sh" in cmd


def test_cascade_falls_back_to_next_channel(tmp_path, monkeypatch):
    ws, host = _linux_foothold(tmp_path)
    # scp push fails (rc 1); b64 push succeeds (rc 0); b64 verify returns no match
    monkeypatch.setattr(service, "run_command",
                        _seq_runner([(1, ""), (0, ""), (0, "nomatch")]))
    res = staging.stage(ws, host, "linpeas", channels=["scp", "b64-ssh"])
    assert res["ok"] and res["channel"] == "b64-ssh"
    assert [a["channel"] for a in res["attempts"]] == ["scp", "b64-ssh"]
    assert res["attempts"][0]["ok"] is False and res["attempts"][1]["ok"] is True
    # recorded as live staged state, unverified (hash didn't match)
    assert ws.staged and ws.staged[0]["status"] == "staged"
    assert ws.staged[0]["material"] == "linpeas" and ws.staged[0]["channel"] == "b64-ssh"


def test_verify_marks_staged_verified(tmp_path, monkeypatch):
    ws, host = _linux_foothold(tmp_path)
    # scp push ok; verify returns the cached sha256 -> verified
    monkeypatch.setattr(service, "run_command",
                        _seq_runner([(0, ""), (0, f"{LINPEAS_SHA}  /tmp/linpeas.sh")]))
    res = staging.stage(ws, host, "linpeas", channels=["scp"])
    assert res["ok"] and res["staged"]["status"] == "verified"
    assert res["staged"]["verified"] is True


def test_all_channels_fail_returns_not_ok(tmp_path, monkeypatch):
    ws, host = _linux_foothold(tmp_path)
    monkeypatch.setattr(service, "run_command", _seq_runner([(1, ""), (1, "")]))
    res = staging.stage(ws, host, "linpeas", channels=["scp", "b64-ssh"])
    assert res["ok"] is False and res["staged"] is None
    assert not ws.staged


def test_stage_without_foothold_raises(tmp_path):
    library.set_base(tmp_path)
    library.engagements_dir().mkdir(parents=True, exist_ok=True)
    ws = library.create_engagement("E")
    ws.add_target("10.10.10.9")
    ws.target = "10.10.10.9"
    ws.save()
    with pytest.raises(staging.StagingError):
        staging.stage(ws, "10.10.10.9", "linpeas")


def test_staged_state_persists_and_reloads(tmp_path, monkeypatch):
    ws, host = _linux_foothold(tmp_path)
    monkeypatch.setattr(service, "run_command", _seq_runner([(0, "")]))
    staging.stage(ws, host, "linpeas", channels=["scp"])
    ws2 = library.get_engagement(ws.root.name)
    assert [(s["material"], s["channel"]) for s in ws2.staged] == [("linpeas", "scp")]
    # removal is de-registration of live state
    assert ws2.remove_staged(ws2.staged[0]["id"])
    ws2.save()
    ws3 = library.get_engagement(ws.root.name)
    assert ws3.staged == []


# ── web endpoints ──────────────────────────────────────────────────────────────
fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402
from obol.webapp.server import create_app  # noqa: E402

H = {"X-Obol-Token": "t"}


def test_staging_endpoints(tmp_path, monkeypatch):
    ws, host = _linux_foothold(tmp_path)
    library.set_active(ws.root.name)
    cx = TestClient(create_app(tmp_path, token="t"))
    chans = cx.get("/api/stage/channels", params={"host": host}, headers=H).json()
    assert any(c["key"] == "scp" for c in chans["channels"])
    monkeypatch.setattr(service, "run_command", _seq_runner([(0, "")]))
    r = cx.post("/api/run/stage", json={"host": host, "material": "linpeas", "channel": "scp"}, headers=H)
    assert r.status_code == 200 and r.json()["ok"] is True
    staged = cx.get("/api/staged", headers=H).json()["staged"]
    assert staged and staged[0]["material"] == "linpeas"
    fid = staged[0]["id"]
    assert cx.request("DELETE", "/api/staged", params={"id": fid}, headers=H).status_code == 200
