import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from obol.facts import Fact
from obol.pack import load_pack, next_actions
from obol.parsers import parse_action_output
from obol.workspace import Workspace


def _workspace() -> Workspace:
    ws = Workspace(Path("/tmp/obol-privesc-parser-test"))
    ws.target = "10.10.10.20"
    ws.add_scope(ws.target)
    ws.facts.add(Fact("target.configured", "host:10.10.10.20", {"target": ws.target}, source="test"))
    return ws


def _action(pack: str, action_id: str):
    return next(action for action in load_pack(pack) if action.id == action_id)


def test_linux_privesc_enum_outputs_leads_without_claiming_root():
    ws = _workspace()
    action = _action("orange_linux_privesc_2025_03", "linux-enum")
    out = """
Linux web01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux
uid=1000(www-data) gid=33(www-data) groups=33(www-data),108(lxd),999(docker)
User www-data may run the following commands on web01:
    (root) NOPASSWD: /usr/bin/find
/usr/bin/find
/usr/local/bin/backup
/usr/bin/python3 = cap_setuid+ep
-rw-rw-rw- 1 root root 2234 Jan 1 00:00 /etc/passwd
/srv/share *(rw,sync,no_root_squash)
"""
    facts = parse_action_output(
        action,
        ws,
        "find / -perm -4000 2>/dev/null; getcap -r / 2>/dev/null; sudo -l; id; uname -a",
        out,
        "",
        "test",
    )
    kinds = {fact.kind for fact in facts}
    assert {
        "host.os_family", "host.kernel", "host.arch", "privesc.leads",
        "privesc.sudo_rights", "privesc.suid_candidate", "privesc.capability",
        "privesc.passwd_writable", "privesc.nfs_no_root_squash",
        "privesc.lxd_group", "privesc.docker_group",
    } <= kinds
    assert "access.admin" not in kinds
    assert "access.system" not in kinds

    for fact in facts:
        ws.facts.add(fact)
    unlocked = {action.id for action in next_actions(ws.facts)}
    assert {"sudo-abuse", "suid-gtfobins", "capabilities", "writable-passwd", "lxc-lxd-escape", "docker-socket"} <= unlocked


def test_linux_privesc_root_proof_is_required_for_admin_access():
    ws = _workspace()
    action = _action("orange_linux_privesc_2025_03", "sudo-abuse")
    facts = parse_action_output(action, ws, "sudo /usr/bin/find -exec id \\;", "uid=0(root) gid=0(root) groups=0(root)\n", "", "test")
    kinds = {fact.kind for fact in facts}
    assert "access.admin" in kinds
    assert next(f for f in facts if f.kind == "access.admin").value["identity"] == "root"


def test_windows_privesc_enum_outputs_leads_without_claiming_system():
    ws = _workspace()
    action = _action("orange_windows_privesc_2025_03", "windows-enum")
    out = r"""
Privilege Name                Description                               State
============================= ========================================= ========
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled

OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
System Type:               x64-based PC

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1
HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1

VulnSvc     C:\Program Files\Vuln App\service.exe     Auto
SERVICE_CHANGE_CONFIG
BUILTIN\Users:(F)
Currently stored credentials:
    Target: Domain:interactive=CORP\backup
DefaultPassword    REG_SZ    Summer2026!
"""
    facts = parse_action_output(
        action,
        ws,
        "whoami /priv && systeminfo && reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
        out,
        "",
        "test",
    )
    kinds = {fact.kind for fact in facts}
    assert {
        "host.os_family", "host.kernel", "host.arch", "privesc.leads",
        "privesc.windows_privilege", "privesc.always_install_elevated",
        "privesc.unquoted_service_path", "privesc.weak_service_permission",
        "privesc.stored_credentials", "credential.candidate",
    } <= kinds
    assert "access.system" not in kinds

    for fact in facts:
        ws.facts.add(fact)
    unlocked = {action.id for action in next_actions(ws.facts)}
    assert {"seimpersonate", "alwaysinstallelevated", "unquoted-service-path", "weak-service-permissions"} <= unlocked


def test_windows_privesc_system_proof_records_system_access():
    ws = _workspace()
    action = _action("orange_windows_privesc_2025_03", "seimpersonate")
    facts = parse_action_output(action, ws, "gp.exe -cmd whoami", "nt authority\\system\n", "", "test")
    assert "access.system" in {fact.kind for fact in facts}
