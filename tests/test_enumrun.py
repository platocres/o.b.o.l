"""Enum run-and-rank (§8): the highlight ranker, and staging + running a read-only
enum tool so the shared privesc.* lead parsers fire on its output. `run_command` is
faked, so no network/target and the scope gate is bypassed like the sessions tests."""
import hashlib

import pytest

from obol import enumrun, library, provision, service
from obol.facts import Fact
from obol.runner import RunResult


LINPEAS = b"#!/bin/sh\necho enum\n"


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
    provision.download("linpeas", fetcher=_fake_fetcher(LINPEAS))
    return ws, host


def _seq_runner(results):
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


PEAS_OUTPUT = """
\x1b[1;31m[+] Checking sudo -l\x1b[0m
User bob may run the following commands on victim:
    (ALL) NOPASSWD: /usr/bin/vim
\x1b[1;33m[+] Capabilities\x1b[0m
/usr/bin/python3.8 = cap_setuid+ep
[+] Kernel exploits
[99%] CVE-2021-4034 PwnKit: Local Privilege Escalation (vulnerable)
Possible interesting file: /home/bob/.ssh/id_rsa
just some boring line with nothing interesting on it at all
"""


# ── highlight ranking ─────────────────────────────────────────────────────────
def test_extract_highlights_ranks_known_exploit_first():
    hi = enumrun.extract_highlights(PEAS_OUTPUT)
    assert hi and hi[0]["signal"] == "known-exploit"          # CVE/PwnKit line wins
    lines = " ".join(h["line"] for h in hi)
    assert "CVE-2021-4034" in lines and "id_rsa" in lines and "NOPASSWD" in lines
    # ANSI stripped, boring line dropped
    assert all("\x1b" not in h["line"] for h in hi)
    assert not any("boring line" in h["line"] for h in hi)
    # ranks are 1..n in order
    assert [h["rank"] for h in hi] == list(range(1, len(hi) + 1))


# ── run orchestration ─────────────────────────────────────────────────────────
def test_run_enum_stages_runs_and_extracts_leads_and_highlights(tmp_path, monkeypatch):
    ws, host = _linux_foothold(tmp_path)
    # calls: scp push, scp verify, then the enum run returns peas output
    monkeypatch.setattr(service, "run_command",
                        _seq_runner([(0, ""), (0, ""), (0, PEAS_OUTPUT)]))
    res = enumrun.run_enum(ws, host, "linpeas")
    assert res["ok"] and res["guided"] is False
    # shared privesc parser fired on the peas output (reuse, not a new parser)
    assert "privesc.sudo_rights" in res["privesc_leads"]
    assert "privesc.capability" in res["privesc_leads"]
    # ranked highlights recorded as a proof-bound candidate lead fact
    assert res["highlights"] and res["highlights"][0]["signal"] == "known-exploit"
    tf = ws.facts_for_target(host)
    assert tf.has("enum.findings")
    finding = tf.values("enum.findings")[0]
    assert finding["tool"] == "linpeas" and finding["count"] == len(res["highlights"])


def test_run_enum_reuses_existing_staged_copy(tmp_path, monkeypatch):
    ws, host = _linux_foothold(tmp_path)
    ws.add_staged(host=host, material="linpeas", remote_path="/tmp/linpeas.sh",
                  channel="scp", status="verified")
    ws.save()
    # only ONE call now (the enum run) — no re-staging push/verify
    monkeypatch.setattr(service, "run_command", _seq_runner([(0, PEAS_OUTPUT)]))
    res = enumrun.run_enum(ws, host, "linpeas")
    assert res["ok"] and res["channel"] == "existing" and res["remote_path"] == "/tmp/linpeas.sh"


def test_run_enum_requires_credential(tmp_path):
    library.set_base(tmp_path)
    library.engagements_dir().mkdir(parents=True, exist_ok=True)
    ws = library.create_engagement("E")
    ws.add_target("10.10.10.5")
    ws.target = "10.10.10.5"
    ws.facts.add(Fact("foothold.linux", "host:10.10.10.5", {"tool": "ssh"}, source="x"))
    ws.save()
    with pytest.raises(enumrun.EnumError):
        enumrun.run_enum(ws, "10.10.10.5", "linpeas")


def test_eligible_enum_filters_by_foothold_os(tmp_path):
    ws, host = _linux_foothold(tmp_path)
    rows = {r["key"]: r for r in enumrun.eligible_enum(ws, host)}
    assert "linpeas" in rows and rows["linpeas"]["os"] == "linux"
    assert rows["linpeas"]["ready"] is True and rows["linpeas"]["cached"] is True
    assert "winpeas" not in rows           # windows tool not offered for a linux foothold


# ── web endpoints ──────────────────────────────────────────────────────────────
fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402
from obol.webapp.server import create_app  # noqa: E402

H = {"X-Obol-Token": "t"}


def test_enum_endpoints(tmp_path, monkeypatch):
    ws, host = _linux_foothold(tmp_path)
    library.set_active(ws.root.name)
    cx = TestClient(create_app(tmp_path, token="t"))
    tools = cx.get("/api/enum/tools", params={"host": host}, headers=H).json()["tools"]
    assert any(t["key"] == "linpeas" for t in tools)
    monkeypatch.setattr(service, "run_command", _seq_runner([(0, ""), (0, ""), (0, PEAS_OUTPUT)]))
    r = cx.post("/api/run/enum", json={"host": host, "tool": "linpeas"}, headers=H)
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] and body["highlights"]
