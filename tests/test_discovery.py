"""Engagement discovery sweep: parse live hosts and auto-create targets, gated on
an authorized scope range, through the one shared runner."""
from pathlib import Path

import pytest

from obol import discovery
from obol.runner import RunResult, RunnerError, run_command
from obol.workspace import Workspace

SN_OUTPUT = """Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 10.10.10.161
Host is up (0.021s latency).
Nmap scan report for dc02.htb.local (10.10.10.175)
Host is up (0.020s latency).
Nmap scan report for 10.10.10.200
Host is up.
Nmap done: 256 IP addresses (3 hosts up) scanned in 5.20 seconds
"""


def _result(stdout: str) -> RunResult:
    p = Path("/tmp/x")
    return RunResult("nmap -sn 10.10.10.0/24", ["nmap"], 0, stdout, "", p, p, 0.0, 12)


def test_parse_live_hosts_handles_rdns_and_bare_ips():
    # the IP is taken from the parens when reverse DNS resolved, else the bare token
    assert discovery.parse_live_hosts(SN_OUTPUT) == [
        "10.10.10.161", "10.10.10.175", "10.10.10.200"]


def test_parse_live_hosts_empty_when_nothing_up():
    assert discovery.parse_live_hosts("Nmap done: 256 IP addresses (0 hosts up)") == []


def test_default_command_is_ad_aware_not_bare_ping():
    cmd = discovery.discovery_command(Workspace(Path("/tmp")), "10.10.10.0/24")
    assert cmd.endswith("10.10.10.0/24") and "-sn" in cmd
    # ICMP-filtered AD hosts still found: TCP SYN to AD ports + a UDP NetBIOS probe
    assert "-PS" in cmd and "445" in cmd and "-PU137" in cmd


def test_run_sweep_creates_targets_for_live_hosts(tmp_path, monkeypatch):
    ws = Workspace(tmp_path)
    ws.add_scope("10.10.10.0/24")
    monkeypatch.setattr(discovery, "run_command", lambda *a, **k: _result(SN_OUTPUT))

    out = discovery.run_sweep(ws, "10.10.10.0/24")
    assert out["created"] == ["10.10.10.161", "10.10.10.175", "10.10.10.200"]
    assert {t["host"] for t in ws.targets} == set(out["created"])
    # a re-sweep is idempotent — the same hosts come back as existing, not created
    out2 = discovery.run_sweep(ws, "10.10.10.0/24")
    assert out2["created"] == [] and set(out2["existing"]) == set(out["created"])
    # the sweep is recorded in the ledger with its lineage, and persisted
    row = ws.runs[-1]
    assert row["sweep"] is True and row["range"] == "10.10.10.0/24"
    assert Workspace(tmp_path).load().targets, "targets persisted"


def test_run_sweep_refuses_unauthorized_range(tmp_path, monkeypatch):
    ws = Workspace(tmp_path)
    ws.add_scope("10.10.10.0/24")
    # asked to sweep a different range that was never authorized
    monkeypatch.setattr(discovery, "run_command", lambda *a, **k: _result(SN_OUTPUT))
    with pytest.raises(RunnerError):
        discovery.run_sweep(ws, "192.168.1.0/24")
    assert ws.targets == []


def test_runner_range_gate_requires_authorized_entry(tmp_path):
    # the runner's scope_target gate is the hard authorization boundary for a
    # range run (dry_run so nothing executes; the gate runs before dry_run)
    ws = Workspace(tmp_path)
    ws.add_scope("10.10.10.0/24")
    # not an authorized entry
    with pytest.raises(RunnerError):
        run_command(ws, command="nmap -sn 192.168.0.0/24", tool="nmap",
                    dry_run=True, scope_target="192.168.0.0/24")
    # authorized, but the command doesn't actually contain the range
    with pytest.raises(RunnerError):
        run_command(ws, command="nmap -sn 10.10.10.5", tool="nmap",
                    dry_run=True, scope_target="10.10.10.0/24")
    # authorized and present → allowed
    res = run_command(ws, command="nmap -sn 10.10.10.0/24", tool="nmap",
                      dry_run=True, scope_target="10.10.10.0/24")
    assert res.dry_run is True


def test_run_sweep_dry_run_touches_nothing(tmp_path, monkeypatch):
    ws = Workspace(tmp_path)
    ws.add_scope("10.10.10.0/24")
    called = {"n": 0}

    def fake(*a, **k):
        called["n"] += 1
        assert k.get("dry_run") is True
        return RunResult("nmap", ["nmap"], None, "", "", Path("/tmp/x"), Path("/tmp/x"), 0.0, 0, dry_run=True)

    monkeypatch.setattr(discovery, "run_command", fake)
    out = discovery.run_sweep(ws, "10.10.10.0/24", dry_run=True)
    assert called["n"] == 1 and out["created"] == [] and ws.targets == []
    assert ws.runs == []  # a dry run previews; it does not record or create targets
