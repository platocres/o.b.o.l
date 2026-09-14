import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from obol.facts import Fact
from obol.pack import load_pack, next_actions
from obol.parsers import parse_action_output
from obol.workspace import Workspace


def _workspace() -> Workspace:
    ws = Workspace(Path("/tmp/obol-parser-test"))
    ws.target = "10.10.10.10"
    ws.add_scope(ws.target)
    ws.facts.add(Fact("target.configured", "host:10.10.10.10", {"target": ws.target}, source="test"))
    return ws


def test_configured_target_unlocks_nmap_first_not_direct_nxc():
    ws = _workspace()
    actions = next_actions(ws.facts)
    ids = {action.id for action in actions}
    assert actions[0].id == "nmap-fast-open-ports"
    assert "ad-dc-identify" not in ids


def test_nmap_quick_scan_produces_port_facts_for_followup():
    ws = _workspace()
    action = next(action for action in load_pack() if action.id == "nmap-fast-open-ports")
    out = """
Starting Nmap 7.95 ( https://nmap.org ) at 2026-09-14 00:00 UTC
Nmap scan report for 10.10.10.10
Host is up (0.042s latency).
Discovered open port 389/tcp on 10.10.10.10
Discovered open port 445/tcp on 10.10.10.10
Discovered open port 88/tcp on 10.10.10.10
Nmap done: 1 IP address (1 host up) scanned in 42.00 seconds
"""
    facts = parse_action_output(
        action,
        ws,
        "nmap -Pn -p- --min-rate 5000 --open -oN nmap-allports.txt 10.10.10.10",
        out,
        "",
        "test",
    )
    for fact in facts:
        ws.facts.add(fact)
    kinds = {fact.kind for fact in facts}
    assert {"host.up", "scan.nmap.quick", "ports.open", "port:389", "port:445", "port:88"} <= kinds
    next_ids = [action.id for action in next_actions(ws.facts)]
    assert next_ids[0] == "nmap-version-scripts"
    assert "ad-dc-identify" in next_ids


def test_nmap_version_scan_produces_service_reachability_without_access():
    ws = _workspace()
    ws.facts.add(Fact("host.up", "host:10.10.10.10", {"target": ws.target}, source="test"))
    ws.facts.add(Fact("scan.nmap.quick", "host:10.10.10.10", {"profile": "open-port-discovery"}, source="test"))
    ws.facts.add(Fact("ports.open", "host:10.10.10.10", {"ports": [88, 389, 445]}, source="test"))
    action = next(action for action in load_pack() if action.id == "nmap-version-scripts")
    out = """
Nmap scan report for 10.10.10.10
Host is up (0.041s latency).
PORT    STATE SERVICE       VERSION
88/tcp  open  kerberos-sec  Microsoft Windows Kerberos
389/tcp open  ldap          Microsoft Windows Active Directory LDAP
445/tcp open  microsoft-ds  Windows Server 2019 Standard
Service detection performed. Please report any incorrect results.
"""
    facts = parse_action_output(
        action,
        ws,
        "nmap -Pn -sC -sV -p 88,389,445 -oN nmap-version.txt 10.10.10.10",
        out,
        "",
        "test",
    )
    kinds = {fact.kind for fact in facts}
    assert {"scan.nmap.version", "kerberos.reachable", "ldap.reachable", "smb.reachable", "ad.dc_candidate"} <= kinds
    assert "credential.available" not in kinds
    assert "access.admin" not in kinds
    assert "foothold.windows" not in kinds


def test_nxc_ldap_smoke_produces_domain_and_reachability_not_access():
    ws = _workspace()
    action = next(action for action in load_pack() if action.id == "ad-dc-identify")
    out = """
LDAP        10.10.10.10     389    DC01         [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:corp.local)
"""
    facts = parse_action_output(action, ws, "nxc ldap 10.10.10.10 -u '' -p ''", out, "", "test")
    kinds = {fact.kind for fact in facts}
    assert {"ad.dc_candidate", "ad.domain_known", "ad.base_dn", "ldap.reachable"} <= kinds
    assert "credential.available" not in kinds
    assert "access.admin" not in kinds
    assert "foothold.windows" not in kinds


def test_nxc_ldap_users_parses_generic_users_without_walkthrough_names():
    ws = _workspace()
    ws.facts.add(Fact("ad.domain_known", "domain:corp.local", {"name": "corp.local"}, source="test"))
    action = next(action for action in load_pack() if action.id == "ad-anon-ldap-enum")
    out = """
LDAP        10.10.10.10     389    DC01         [*] Total of records returned 4
LDAP        10.10.10.10     389    DC01         Administrator
LDAP        10.10.10.10     389    DC01         alice.smith
LDAP        10.10.10.10     389    DC01         backup-svc
sAMAccountName: build.operator
description: ordinary lab hint text
"""
    facts = parse_action_output(
        action,
        ws,
        "nxc ldap 10.10.10.10 -u '' -p '' --users",
        out,
        "",
        "test",
    )
    user_fact = next(fact for fact in facts if fact.kind == "ad.user_list")
    assert user_fact.value["users"] == ["Administrator", "alice.smith", "backup-svc", "build.operator"]
    assert user_fact.value["count"] == 4
    kinds = {fact.kind for fact in facts}
    assert "ad.anonymous_bind" in kinds
    assert "credential.available" not in kinds
    assert "credential.admin" not in kinds
    assert "access.admin" not in kinds


def test_ldapsearch_naming_contexts_parse_base_dn():
    ws = _workspace()
    action = next(action for action in load_pack() if action.id == "ad-anon-ldap-enum")
    out = """
dn:
namingContexts: DC=example,DC=internal
"""
    facts = parse_action_output(
        action,
        ws,
        "ldapsearch -x -H ldap://10.10.10.10 -s base namingcontexts",
        out,
        "",
        "test",
    )
    values = {fact.kind: fact.value for fact in facts}
    assert values["ad.domain_known"]["name"] == "example.internal"
    assert values["ad.base_dn"]["base_dn"] == "DC=example,DC=internal"
    assert "ldap.reachable" in values


def test_asrep_hash_parser_produces_candidate_material_only():
    ws = _workspace()
    action = next(action for action in load_pack() if action.id == "asrep-roast")
    out = "$krb5asrep$23$user@CORP.LOCAL:abcdef1234567890"
    facts = parse_action_output(
        action,
        ws,
        "nxc ldap 10.10.10.10 -u users.txt -p '' --asreproast asrep.txt",
        out,
        "",
        "test",
    )
    kinds = {fact.kind for fact in facts}
    assert {"hash.asrep", "credential.candidate"} <= kinds
    assert "credential.available" not in kinds
    assert "access.admin" not in kinds
