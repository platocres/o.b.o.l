from obol.facts import Fact
from obol.localenum import parse_local_enum_output
from obol.pack import load_packs, next_actions
from obol.workspace import Workspace


def _action(action_id):
    return next(a for a in load_packs() if a.id == action_id)


def _workspace(tmp_path, host="10.10.10.5"):
    ws = Workspace(tmp_path)
    ws.add_target(host)
    ws.target = host
    return ws


def test_linux_local_enum_parses_interfaces_and_pivot_candidates(tmp_path):
    ws = _workspace(tmp_path)
    action = _action("local-linux-interfaces")
    output = """
1: lo    inet 127.0.0.1/8 scope host lo
2: eth0    inet 10.10.10.5/24 brd 10.10.10.255 scope global eth0
3: eth1    inet 172.16.20.10/24 brd 172.16.20.255 scope global eth1
"""

    facts = parse_local_enum_output(action, ws, action.command, output, source="ip -o addr show")
    kinds = {f.kind for f in facts}

    assert "scan.local.interfaces" in kinds
    assert "host.interface" in kinds
    assert "host.ip_address" in kinds
    assert "host.multihomed" in kinds
    assert "network.subnet_candidate" in kinds
    assert "pivot.candidate" in kinds
    assert "tunnel.up" not in kinds
    assert "access.admin" not in kinds

    pivot = next(f for f in facts if f.kind == "pivot.candidate")
    assert "multiple interface networks" in pivot.value["reasons"]
    assert set(pivot.value["subnets"]) == {"10.10.10.0/24", "172.16.20.0/24"}


def test_linux_route_to_extra_subnet_is_candidate_not_scope_or_tunnel(tmp_path):
    ws = _workspace(tmp_path)
    action = _action("local-linux-routes")
    output = """
default via 10.10.10.1 dev eth0
10.10.10.0/24 dev eth0 proto kernel scope link src 10.10.10.5
172.16.50.0/24 via 10.10.10.254 dev eth0
"""

    facts = parse_local_enum_output(action, ws, action.command, output, source="ip route")
    kinds = {f.kind for f in facts}

    assert "scan.local.routes" in kinds
    assert "host.route" in kinds
    assert "network.subnet_candidate" in kinds
    assert "pivot.candidate" in kinds
    assert "scope.authorized" not in kinds
    assert "tunnel.up" not in kinds


def test_single_route_table_subnet_does_not_become_pivot_candidate(tmp_path):
    ws = _workspace(tmp_path)
    action = _action("local-linux-routes")
    output = """
default via 10.10.10.1 dev eth0
10.10.10.0/24 dev eth0 proto kernel scope link src 10.10.10.5
"""

    facts = parse_local_enum_output(action, ws, action.command, output, source="ip route")
    kinds = {f.kind for f in facts}

    assert "scan.local.routes" in kinds
    assert "host.route" in kinds
    assert "network.subnet_candidate" in kinds
    assert "pivot.candidate" not in kinds
    assert "host.multihomed" not in kinds


def test_windows_ipconfig_parses_interfaces_dns_and_multihomed_candidate(tmp_path):
    ws = _workspace(tmp_path)
    action = _action("local-windows-interfaces")
    output = """
WINRM 10.10.10.20 5985 HOST Windows IP Configuration
WINRM 10.10.10.20 5985 HOST 
WINRM 10.10.10.20 5985 HOST Ethernet adapter Ethernet0:
WINRM 10.10.10.20 5985 HOST    Connection-specific DNS Suffix  . : htb.local
WINRM 10.10.10.20 5985 HOST    IPv4 Address. . . . . . . . . . . : 10.10.10.20(Preferred)
WINRM 10.10.10.20 5985 HOST    Subnet Mask . . . . . . . . . . . : 255.255.255.0
WINRM 10.10.10.20 5985 HOST    Default Gateway . . . . . . . . . : 10.10.10.1
WINRM 10.10.10.20 5985 HOST    DNS Servers . . . . . . . . . . . : 10.10.10.2
WINRM 10.10.10.20 5985 HOST                                        10.10.10.3
WINRM 10.10.10.20 5985 HOST 
WINRM 10.10.10.20 5985 HOST Ethernet adapter Ethernet1:
WINRM 10.10.10.20 5985 HOST    IPv4 Address. . . . . . . . . . . : 192.168.56.22(Preferred)
WINRM 10.10.10.20 5985 HOST    Subnet Mask . . . . . . . . . . . : 255.255.255.0
"""

    facts = parse_local_enum_output(action, ws, action.command, output, source="ipconfig /all")
    kinds = {f.kind for f in facts}

    assert "scan.local.interfaces" in kinds
    assert "scan.local.dns" in kinds
    assert "host.dns_server" in kinds
    assert "host.multihomed" in kinds
    assert "pivot.candidate" in kinds
    assert "access.system" not in kinds


def test_windows_route_print_parses_additional_subnet_candidate(tmp_path):
    ws = _workspace(tmp_path)
    action = _action("local-windows-routes")
    output = """
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0       10.10.10.1     10.10.10.20     25
       10.10.10.0    255.255.255.0         On-link      10.10.10.20    281
       172.16.80.0    255.255.255.0      10.10.10.254   10.10.10.20     26
"""

    facts = parse_local_enum_output(action, ws, action.command, output, source="route print")
    kinds = {f.kind for f in facts}

    assert "scan.local.routes" in kinds
    assert "host.route" in kinds
    assert "network.subnet_candidate" in kinds
    assert "pivot.candidate" in kinds
    assert "tunnel.up" not in kinds


def test_post_foothold_actions_unlock_from_access_facts(tmp_path):
    ws = _workspace(tmp_path)
    ws.facts.add(Fact("foothold.linux", "host:10.10.10.5", {}, source="ssh id"))
    ws.facts.add(Fact("host.os_family", "host:10.10.10.5", {"family": "linux"}, source="ssh id"))
    ws.facts.add(Fact(
        "credential.available",
        "host:10.10.10.5",
        {"user": "low", "password": "Password123!"},
        source="nxc ssh",
    ))

    action_ids = {a.id for a in next_actions(ws.facts_for_target("10.10.10.5"))}

    assert "local-linux-interfaces" in action_ids
    assert "local-linux-routes" in action_ids
    assert "local-windows-interfaces" not in action_ids


def test_windows_local_enum_requires_winrm_exec_channel_not_rdp_only(tmp_path):
    ws = _workspace(tmp_path)
    ws.facts.add(Fact("host.os_family", "host:10.10.10.5", {"family": "windows"}, source="nmap"))
    ws.facts.add(Fact("rdp.authenticated", "host:10.10.10.5", {}, source="nxc rdp"))
    ws.facts.add(Fact(
        "credential.available",
        "host:10.10.10.5",
        {"user": "low", "password": "Password123!"},
        source="nxc rdp",
    ))

    action_ids = {a.id for a in next_actions(ws.facts_for_target("10.10.10.5"))}
    assert "local-windows-interfaces" not in action_ids

    ws.facts.add(Fact("winrm.authenticated", "host:10.10.10.5", {}, source="nxc winrm"))
    action_ids = {a.id for a in next_actions(ws.facts_for_target("10.10.10.5"))}
    assert "local-windows-interfaces" in action_ids
