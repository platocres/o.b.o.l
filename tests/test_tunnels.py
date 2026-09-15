"""§6d tunnels layer + route-aware runner: the tunnel registry, tunnels as live
state (auto-extending scope from a proven foothold, never bypassing it), and the
runner auto-prefixing proxychains for hosts reached only through a SOCKS tunnel."""
import pytest

from obol import library, service, tunnels
from obol.facts import Fact
from obol.pack import Action
from obol.tunnels import TunnelError


def _ws(tmp_path, host="10.10.10.5"):
    library.set_base(tmp_path)
    library.engagements_dir().mkdir(parents=True, exist_ok=True)
    ws = library.create_engagement("E")
    ws.add_target(host)
    ws.target = host
    return ws


def _foothold(ws, host="10.10.10.5", os="linux"):
    s = f"host:{host}"
    ws.facts.add(Fact("foothold.linux" if os == "linux" else "foothold.windows", s, {}, source="x"))
    ws.facts.add(Fact("host.os_family", s, {"family": os}, source="x"))
    ws.facts.add(Fact("credential.available", s, {"user": "bob", "password": "pw123"}, source="x"))
    ws.save()


def _cmd(ws, target):
    a = Action(id="probe", title="probe", tool="nxc", commands=[{"tool": "nxc", "run": "nxc smb {{target}}"}])
    return service.build_command(a, ws, target=target)[0]


# ── registry / eligibility ───────────────────────────────────────────────────
def test_tunnels_offered_only_with_a_foothold(tmp_path):
    ws = _ws(tmp_path)
    assert tunnels.eligible_tunnels(ws, "10.10.10.5") == []   # no foothold yet
    _foothold(ws)
    offers = {o["kind"]: o for o in tunnels.eligible_tunnels(ws, "10.10.10.5")}
    # a Linux foothold offers the OS-agnostic and linux transports, not none
    assert offers["ligolo"]["transport"] == "transparent" and offers["ligolo"]["proxychains"] is False
    assert offers["chisel"]["transport"] == "socks" and offers["chisel"]["proxychains"] is True
    assert "sshuttle" in offers and "ssh-dynamic" in offers


def test_windows_foothold_hides_ssh_only_transports(tmp_path):
    ws = _ws(tmp_path, "10.10.10.20")
    _foothold(ws, "10.10.10.20", os="windows")
    kinds = {o["kind"] for o in tunnels.eligible_tunnels(ws, "10.10.10.20")}
    assert "ligolo" in kinds and "chisel" in kinds       # OS-agnostic
    assert "sshuttle" not in kinds and "ssh-dynamic" not in kinds  # linux-only


# ── open: live state + scope auto-extend (never bypass) ──────────────────────
def test_open_socks_tunnel_records_state_and_extends_scope(tmp_path):
    ws = _ws(tmp_path)
    _foothold(ws)
    res = tunnels.open_tunnel(ws, "10.10.10.5", "chisel", subnet="172.16.20.0/24", lhost="10.10.14.7")
    assert res["ok"] and res["proxychains"] is True
    assert res["scope_added"] == "172.16.20.0/24"
    assert "172.16.20.0/24" in ws.scope
    t = res["tunnel"]
    assert t["transport"] == "socks" and t["status"] == "up" and t["exposed_subnet"] == "172.16.20.0/24"
    # the setup command is filled from facts (secrets shown — operator box)
    assert "chisel" in res["setup_command"] and "10.10.14.7" in res["setup_command"]
    # tunnel-authorized scope is tagged distinctly from operator scope
    assert tunnels.tunnel_scope_entries(ws) == {"172.16.20.0/24": t["id"]}


def test_open_refused_without_foothold_or_subnet(tmp_path):
    ws = _ws(tmp_path)
    ws.facts.add(Fact("port:22", "host:10.10.10.5", {"port": 22}, source="nmap"))
    ws.save()
    with pytest.raises(TunnelError):
        tunnels.open_tunnel(ws, "10.10.10.5", "chisel", subnet="172.16.20.0/24")  # no foothold
    _foothold(ws)
    with pytest.raises(TunnelError):
        tunnels.open_tunnel(ws, "10.10.10.5", "ligolo")  # subnet-route transport needs a subnet


def test_open_persists_across_reload(tmp_path):
    ws = _ws(tmp_path)
    _foothold(ws)
    tunnels.open_tunnel(ws, "10.10.10.5", "ligolo", subnet="172.16.99.0/24", lhost="10.10.14.7")
    ws2 = library.get_engagement(ws.root.name)
    assert [(t["kind"], t["transport"], t["status"], t["exposed_subnet"]) for t in ws2.tunnels] \
        == [("ligolo", "transparent", "up", "172.16.99.0/24")]
    assert "172.16.99.0/24" in ws2.scope


# ── route-aware runner ───────────────────────────────────────────────────────
def test_socks_tunnel_auto_prefixes_proxychains(tmp_path):
    ws = _ws(tmp_path)
    _foothold(ws)
    tunnels.open_tunnel(ws, "10.10.10.5", "chisel", subnet="172.16.20.0/24", lhost="10.10.14.7")
    ws.add_target("172.16.20.9")
    ws.save()
    # a host behind the SOCKS tunnel is proxychained; the pivot host is not
    assert _cmd(ws, "172.16.20.9") == "proxychains -q nxc smb 172.16.20.9"
    assert _cmd(ws, "10.10.10.5") == "nxc smb 10.10.10.5"


def test_transparent_tunnel_does_not_proxychain(tmp_path):
    ws = _ws(tmp_path)
    _foothold(ws)
    tunnels.open_tunnel(ws, "10.10.10.5", "ligolo", subnet="172.16.99.0/24", lhost="10.10.14.7")
    ws.add_target("172.16.99.4")
    ws.save()
    assert _cmd(ws, "172.16.99.4") == "nxc smb 172.16.99.4"


def test_down_tunnel_stops_routing(tmp_path):
    ws = _ws(tmp_path)
    _foothold(ws)
    res = tunnels.open_tunnel(ws, "10.10.10.5", "chisel", subnet="172.16.20.0/24", lhost="10.10.14.7")
    ws.add_target("172.16.20.9")
    ws.save()
    assert tunnels.route_prefix(ws, "172.16.20.9") == "proxychains -q "
    tunnels.close_tunnel(ws, res["tunnel"]["id"])
    assert tunnels.route_prefix(ws, "172.16.20.9") == ""   # a down tunnel routes nothing


# ── remove + scope retract ───────────────────────────────────────────────────
def test_remove_tunnel_retracts_scope_unless_a_target_lives_there(tmp_path):
    ws = _ws(tmp_path)
    _foothold(ws)
    res = tunnels.open_tunnel(ws, "10.10.10.5", "chisel", subnet="172.16.20.0/24", lhost="10.10.14.7")
    tid = res["tunnel"]["id"]
    # no target discovered in the subnet yet → removing retracts the auto-added scope
    out = tunnels.remove_tunnel(ws, tid)
    assert out["scope_retracted"] == "172.16.20.0/24"
    assert "172.16.20.0/24" not in ws.scope

    # but once a target lives in the subnet, the scope stays even when the tunnel goes
    _foothold(ws)
    res2 = tunnels.open_tunnel(ws, "10.10.10.5", "chisel", subnet="172.16.20.0/24", lhost="10.10.14.7")
    ws.add_target("172.16.20.50")
    ws.save()
    out2 = tunnels.remove_tunnel(ws, res2["tunnel"]["id"])
    assert out2["scope_retracted"] == ""
    assert "172.16.20.0/24" in ws.scope
