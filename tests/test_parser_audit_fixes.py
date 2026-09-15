"""Regression tests for the parser-quality audit fixes.

Each test is a "misleading output" negative (or a previously-missing positive)
that would have caught the audited defect. Grouped by finding id.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from obol.pack import Action
from obol.parsers import parse_action_output
from obol.workspace import Workspace


def _ws(target="10.10.10.10", domain=""):
    ws = Workspace(Path("/tmp/obol-audit-parse"))
    ws.target = target
    if domain:
        from obol.facts import Fact
        ws.facts.add(Fact("ad.domain_known", f"domain:{domain}", {"name": domain}, source="t"))
    return ws


def _action(action_id, tool=""):
    return Action(id=action_id, title=action_id, tool=tool)


def _run(action_id, command, out, ws=None, tool=""):
    ws = ws or _ws()
    return parse_action_output(_action(action_id, tool), ws, command, out, "", command)


def _kinds(facts):
    return {f.kind for f in facts}


def _one(facts, kind):
    return next(f for f in facts if f.kind == kind)


# --------------------------------------------------------------------------- #
# H1 — AlwaysInstallElevated must reflect the real DWORDs, not stray "1"s
# --------------------------------------------------------------------------- #
def test_aie_both_keys_zero_is_not_flagged():
    out = (
        "OS Version: 10.0.17763 N/A Build 17763\n"  # contains a lone "1"
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\n"
        "    AlwaysInstallElevated    REG_DWORD    0x0\n"
        "HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\n"
        "    AlwaysInstallElevated    REG_DWORD    0x0\n"
    )
    facts = _run("windows-enum", "reg query ... /v AlwaysInstallElevated", out)
    assert "privesc.always_install_elevated" not in _kinds(facts)


def test_aie_only_one_key_set_is_not_flagged():
    out = (
        "HKEY_LOCAL_MACHINE\\...\\Installer\n    AlwaysInstallElevated    REG_DWORD    0x1\n"
        "HKEY_CURRENT_USER\\...\\Installer\n    AlwaysInstallElevated    REG_DWORD    0x0\n"
    )
    facts = _run("windows-enum", "reg query ...", out)
    assert "privesc.always_install_elevated" not in _kinds(facts)


def test_aie_both_keys_set_is_flagged():
    out = (
        "HKEY_LOCAL_MACHINE\\...\\Installer\n    AlwaysInstallElevated    REG_DWORD    0x1\n"
        "HKEY_CURRENT_USER\\...\\Installer\n    AlwaysInstallElevated    REG_DWORD    0x1\n"
    )
    facts = _run("windows-enum", "reg query ...", out)
    assert "privesc.always_install_elevated" in _kinds(facts)


# --------------------------------------------------------------------------- #
# H2 — a bare WinRM port is a hint, never a promoted os_family
# --------------------------------------------------------------------------- #
def test_winrm_port_alone_does_not_promote_os_family():
    out = "Nmap scan report for 10.10.10.10\nHost is up.\n5985/tcp open  wsman\n"
    facts = _run("nmap-version-scripts", "nmap -Pn -sV 10.10.10.10", out)
    kinds = _kinds(facts)
    assert "winrm.reachable" in kinds
    assert "host.os_hint" in kinds
    assert "host.os_family" not in kinds


def test_winrm_with_windows_banner_still_promotes():
    out = (
        "Nmap scan report for 10.10.10.10\nHost is up.\n"
        "5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)\n"
        "Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows\n"
    )
    facts = _run("nmap-version-scripts", "nmap -Pn -sV 10.10.10.10", out)
    assert _one(facts, "host.os_family").value["family"] == "windows"


# --------------------------------------------------------------------------- #
# M1 — a guest LDAP bind is not an anonymous bind
# --------------------------------------------------------------------------- #
def test_guest_ldap_bind_is_not_anonymous_bind():
    out = "LDAP        10.10.10.10   389    DC01   [+] corp.local\\guest: (Guest)\n"
    facts = _run("ad-anon-ldap-enum", "nxc ldap 10.10.10.10 -u guest -p ''", out, ws=_ws(domain="corp.local"))
    assert "ad.anonymous_bind" not in _kinds(facts)


def test_true_anonymous_ldap_bind_is_recorded():
    out = "LDAP        10.10.10.10   389    DC01   [+] corp.local\\: (anonymous)\n"
    facts = _run("ad-anon-ldap-enum", "nxc ldap 10.10.10.10 -u '' -p ''", out, ws=_ws(domain="corp.local"))
    assert "ad.anonymous_bind" in _kinds(facts)


# --------------------------------------------------------------------------- #
# M2 — nxc rdp coverage (previously untested)
# --------------------------------------------------------------------------- #
def test_nxc_rdp_success_records_auth_and_foothold():
    out = "RDP         10.10.10.10   3389   DC01   [+] corp.local\\svc-audit:Spring2026!\n"
    facts = _run("rdp-login", "nxc rdp 10.10.10.10 -u svc-audit -p 'Spring2026!'", out, ws=_ws(domain="corp.local"))
    kinds = _kinds(facts)
    assert {"rdp.authenticated", "foothold.windows"} <= kinds
    assert "access.admin" not in kinds


def test_nxc_rdp_pwned_records_admin():
    out = "RDP         10.10.10.10   3389   DC01   [+] corp.local\\administrator:P@ss (Pwn3d!)\n"
    facts = _run("rdp-login", "nxc rdp 10.10.10.10 -u administrator -p 'P@ss'", out, ws=_ws(domain="corp.local"))
    assert "access.admin" in _kinds(facts)


def test_nxc_rdp_failed_auth_records_nothing():
    out = "RDP         10.10.10.10   3389   DC01   [-] corp.local\\svc-audit:WrongPass\n"
    facts = _run("rdp-login", "nxc rdp 10.10.10.10 -u svc-audit -p WrongPass", out, ws=_ws(domain="corp.local"))
    kinds = _kinds(facts)
    assert not ({"rdp.authenticated", "foothold.windows", "access.admin"} & kinds)


# --------------------------------------------------------------------------- #
# M3 — SUID and local-secret heuristics must not fire on noise
# --------------------------------------------------------------------------- #
def test_suid_bare_paths_need_a_find_perm_command():
    # A linpeas-style dump that mentions "SUID" but whose bare paths are not from
    # a `find -perm` search must not flag every path as a SUID candidate.
    out = (
        "══════════╣ Interesting SUID files\n"
        "/usr/bin/curl\n/usr/bin/wget\n/etc/hosts\n"
    )
    facts = _run("linux-loot-hunt", "linpeas.sh", out)
    assert "privesc.suid_candidate" not in _kinds(facts)


def test_suid_from_find_perm_command_is_flagged():
    out = "/usr/bin/pkexec\n/usr/local/bin/backup\n"
    facts = _run("suid-gtfobins", "find / -perm -4000 2>/dev/null", out)
    assert "privesc.suid_candidate" in _kinds(facts)


def test_suid_setuid_mode_line_is_flagged_anywhere():
    out = "-rwsr-xr-x 1 root root 26696 /usr/bin/passwd\n"
    facts = _run("linux-enum", "ls -la /usr/bin", out)
    assert "privesc.suid_candidate" in _kinds(facts)


def test_local_secret_needs_a_value_not_a_bare_keyword():
    out = "══════════╣ Searching for passwords in memory\nChecking for secret files\n"
    facts = _run("linux-loot-hunt", "linpeas.sh", out)
    assert "credential.candidate" not in _kinds(facts)


def test_local_secret_with_assignment_is_recorded():
    out = "db_password = Sup3rS3cret!\n"
    facts = _run("linux-loot-hunt", "grep -ri password /var/www", out)
    assert "credential.candidate" in _kinds(facts)


# --------------------------------------------------------------------------- #
# M4 — weak-service-permission needs a service ACE or a low-priv writable ACE
# --------------------------------------------------------------------------- #
def test_admin_only_icacls_is_not_a_weak_service_permission():
    out = (
        "C:\\Program Files\\App\\svc.exe\n"
        "  NT AUTHORITY\\SYSTEM:(F)\n"
        "  BUILTIN\\Administrators:(F)\n"
    )
    facts = _run("weak-service-permissions", "icacls \"C:\\Program Files\\App\\svc.exe\"", out)
    assert "privesc.weak_service_permission" not in _kinds(facts)


def test_users_writable_ace_is_a_weak_service_permission():
    out = "C:\\Program Files\\App\\svc.exe\n  BUILTIN\\Users:(M)\n"
    facts = _run("weak-service-permissions", "icacls \"C:\\Program Files\\App\\svc.exe\"", out)
    assert "privesc.weak_service_permission" in _kinds(facts)


# --------------------------------------------------------------------------- #
# M7 — john rows only from real --show output
# --------------------------------------------------------------------------- #
def test_john_loaded_preamble_without_crack_is_not_a_credential():
    out = (
        "Loaded 3 password hashes with 3 different salts (sha512crypt)\n"
        "admin:something\n"  # a stray colon line, but nothing was cracked
        "0g 0:00:00:03 DONE\n"
    )
    facts = _run("crack-hashes", "john hashes.txt", out)
    assert "credential.plaintext" not in _kinds(facts)


def test_john_show_output_records_cracked_credentials():
    out = "svc-audit:Spring2026!\n\n1 password hash cracked, 0 left\n"
    facts = _run("crack-hashes", "john --show hashes.txt", out)
    assert "credential.plaintext" in _kinds(facts)


# --------------------------------------------------------------------------- #
# #40 AD-abuse parser boundary locks (audited on this branch)
# --------------------------------------------------------------------------- #
def test_addcomputer_failure_records_nothing():
    out = "[-] Cannot add computer: MachineAccountQuota exceeded or access denied\n"
    facts = _run(
        "delegation-abuse",
        "impacket-addcomputer corp.local/u:p -computer-name OBOL$ -computer-pass Pass123!",
        out, ws=_ws(domain="corp.local"),
    )
    kinds = _kinds(facts)
    assert not ({"ad.computer_added", "credential.candidate"} & kinds)


def test_gmsa_no_hash_present_records_no_ntlm_hash():
    out = "gMSADumper: no readable gMSA accounts for this principal\n"
    facts = _run("gmsa-read", "gMSADumper.py -u u -p p -d corp.local", out, ws=_ws(domain="corp.local"))
    assert "credential.ntlm_hash" not in _kinds(facts)
