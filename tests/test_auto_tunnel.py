"""§6d/e/f — the auto-tunnel cascade (feasibility + binary staging + confirmed path),
the through-tunnel sweep (health proof + recursion), and the topology map.
`service.run_command` is faked (no network/target; scope gate bypassed)."""
import pytest

from obol import discovery, library, provision, service, tunnels
from obol.facts import Fact
from obol.graph import build_topology
from obol.runner import RunResult


def _fake_fetcher(content=b"chiselbin"):
    def fetch(url, dest, timeout=0):
        from pathlib import Path
        Path(dest).write_bytes(content)
        return len(content)
    return fetch


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


def _win_admin_foothold(tmp_path, host="10.10.10.7"):
    library.set_base(tmp_path)
    library.engagements_dir().mkdir(parents=True, exist_ok=True)
    ws = library.create_engagement("E")
    ws.add_target(host)
    ws.target = host
    ws.facts.add(Fact("foothold.windows", f"host:{host}", {"tool": "winrm"}, source="login"))
    ws.facts.add(Fact("access.system", f"host:{host}", {"identity": "nt authority\\system"}, source="godpotato"))
    ws.facts.add(Fact("credential.available", f"host:{host}", {"user": "svc", "password": "pw"}, source="x"))
    ws.save()
    provision.download("chisel", fetcher=_fake_fetcher())
    return ws, host


# ── §6d feasibility cascade ───────────────────────────────────────────────────
def test_cascade_marks_feasibility_with_reasons(tmp_path):
    ws, host = _win_admin_foothold(tmp_path)
    rows = {r["kind"]: r for r in tunnels.feasible_cascade(ws, host)}
    # ligolo needs a binary obol can't fetch (ligolo-agent is manual, not cached)
    assert rows["ligolo"]["feasible"] is False and "ligolo-agent" in rows["ligolo"]["reason"]
    # sshuttle/ssh are linux-only → infeasible for a windows foothold
    assert rows["sshuttle"]["feasible"] is False
    # chisel's binary is cached (downloaded) and it fits any OS → feasible
    assert rows["chisel"]["feasible"] is True and rows["chisel"]["material"] == "chisel"


def test_auto_tunnel_stages_binary_and_records_confirmed_path(tmp_path, monkeypatch):
    ws, host = _win_admin_foothold(tmp_path)
    # one call: the SMB put-file push that stages chisel (no verify on smb-put)
    monkeypatch.setattr(service, "run_command", _seq_runner([(0, "")]))
    res = tunnels.auto_tunnel(ws, host, subnet="10.10.20.0/24", lhost="10.8.0.5")
    assert res["ok"] and res["kind"] == "chisel"
    # obol confirms it STAGED the binary and knows its on-target location
    assert res["staged"] and res["staged"]["material"] == "chisel"
    remote = res["staged"]["remote_path"]
    assert remote and res["tunnel"]["staged_path"] == remote
    assert res["tunnel"]["staged_material"] == "chisel"
    # and the setup command points at that staged path, not a bare binary name
    assert remote in res["setup_command"]
    # proxychains needed (SOCKS), scope auto-extended to the routed subnet
    assert res["proxychains"] is True and res["scope_added"] == "10.10.20.0/24"
    assert res["tunnel"]["status"] == "connecting"     # until §6e confirms


def test_auto_tunnel_no_foothold_raises(tmp_path):
    library.set_base(tmp_path)
    library.engagements_dir().mkdir(parents=True, exist_ok=True)
    ws = library.create_engagement("E")
    ws.add_target("10.10.10.9")
    ws.target = "10.10.10.9"
    ws.save()
    with pytest.raises(tunnels.TunnelError):
        tunnels.auto_tunnel(ws, "10.10.10.9", subnet="10.10.20.0/24")


# ── §6e through-tunnel sweep ──────────────────────────────────────────────────
def test_through_tunnel_command_is_transport_aware():
    socks = discovery.through_tunnel_discovery_command("socks", "10.10.20.0/24")
    assert socks.startswith("proxychains -q nmap -sT -Pn") and "10.10.20.0/24" in socks
    transparent = discovery.through_tunnel_discovery_command("transparent", "10.10.20.0/24")
    assert transparent.startswith("nmap -sT -Pn") and "proxychains" not in transparent


SWEEP_OUT = """
Nmap scan report for 10.10.20.5
Host is up (0.02s latency).
PORT    STATE SERVICE
445/tcp open  microsoft-ds

Nmap scan report for 10.10.20.9
Host is up (0.01s latency).
All 18 scanned ports are closed
"""


def test_parse_hosts_with_open_ports_needs_an_open_port():
    hosts = discovery.parse_hosts_with_open_ports(SWEEP_OUT)
    assert hosts == ["10.10.20.5"]        # the all-closed host is not "live"


def test_run_tunnel_sweep_confirms_health_and_finds_hosts(tmp_path, monkeypatch):
    ws, host = _win_admin_foothold(tmp_path)
    monkeypatch.setattr(service, "run_command", _seq_runner([(0, "")]))
    res = tunnels.auto_tunnel(ws, host, subnet="10.10.20.0/24", lhost="10.8.0.5")
    tid = res["tunnel"]["id"]
    # the sweep returns a live host → tunnel proven UP, host added as a target
    # (the sweep runs run_command directly from discovery, so patch it there)
    monkeypatch.setattr(discovery, "run_command", _seq_runner([(0, SWEEP_OUT)]))
    sweep = discovery.run_tunnel_sweep(ws, tid)
    assert sweep["status"] == "up" and sweep["hosts"] == ["10.10.20.5"]
    assert "10.10.20.5" in sweep["created"]
    assert ws.get_tunnel(tid)["status"] == "up"
    assert ws.get_target("10.10.20.5") is not None


def test_run_tunnel_sweep_empty_marks_down(tmp_path, monkeypatch):
    ws, host = _win_admin_foothold(tmp_path)
    monkeypatch.setattr(service, "run_command", _seq_runner([(0, "")]))
    res = tunnels.auto_tunnel(ws, host, subnet="10.10.20.0/24", lhost="10.8.0.5")
    tid = res["tunnel"]["id"]
    monkeypatch.setattr(discovery, "run_command", _seq_runner([(0, "no hosts up\n")]))
    sweep = discovery.run_tunnel_sweep(ws, tid)
    assert sweep["status"] == "down" and ws.get_tunnel(tid)["status"] == "down"


# ── §6f topology map ──────────────────────────────────────────────────────────
def test_topology_shows_segments_joined_by_tunnels(tmp_path, monkeypatch):
    ws, host = _win_admin_foothold(tmp_path)
    ws.add_scope("10.10.10.0/24")     # the pivot host's own segment
    ws.save()
    monkeypatch.setattr(service, "run_command", _seq_runner([(0, "")]))
    res = tunnels.auto_tunnel(ws, host, subnet="10.10.20.0/24", lhost="10.8.0.5")
    topo = build_topology(ws)
    cidrs = {s["cidr"]: s for s in topo["segments"]}
    assert "10.10.10.0/24" in cidrs and "10.10.20.0/24" in cidrs
    assert cidrs["10.10.10.0/24"]["source"] == "operator"
    assert cidrs["10.10.20.0/24"]["source"] == "pivot"   # authorized by the tunnel
    # the pivot host sits in its segment, flagged as a foothold
    hosts = {h["host"]: h for h in cidrs["10.10.10.0/24"]["hosts"]}
    assert host in hosts and hosts[host]["foothold"] is True
    # a hop from the pivot host to the exposed segment, carrying the staged binary path
    hop = next(h for h in topo["hops"] if h["tunnel_id"] == res["tunnel"]["id"])
    assert hop["from_segment"] == "10.10.10.0/24" and hop["to_segment"] == "10.10.20.0/24"
    assert hop["staged_material"] == "chisel" and hop["staged_path"]
