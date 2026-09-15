"""Evidence parsers for tool output.

Parsers map observed output to the narrowest supported facts. They should parse
stable tool signals, not walkthrough-specific names, passwords, hosts, or paths.
Unknown output is still preserved by the runner; it simply produces no facts.

The parser surface is deliberately one module: recon/enum parsing (nmap, LDAP,
SMB, GPP, AS-REP, cracking) and the post-credential AD path (auth validation,
TGS roast, evil-winrm footholds, BloodHound signals) share the same fact-scoping
helpers, so keeping them together prevents that discipline from drifting apart.
"""
from __future__ import annotations

import re
import shlex

from .facts import Fact, ProofState
from .pack import Action
from .workspace import Workspace

_DOMAIN_RE = re.compile(r"\(domain:([^)]+)\)", re.IGNORECASE)
_NAME_RE = re.compile(r"\(name:([^)]+)\)", re.IGNORECASE)
_NXC_PROTO_REACHABLE_RE = re.compile(r"^(?P<proto>LDAP|SMB|WINRM|RDP|SSH|FTP)\s+\S+\s+\d+\s+\S+", re.IGNORECASE | re.MULTILINE)
_SAM_RE = re.compile(r"\bsAMAccountName:\s*([^\s,;]+)", re.IGNORECASE)
_UPN_RE = re.compile(r"\buserPrincipalName:\s*([^\s,;@]+)(?:@[^\s,;]+)?", re.IGNORECASE)
_NXC_USER_ROW_RE = re.compile(
    r"^(?:LDAP|SMB)\s+\S+\s+\d+\s+\S+\s+(?!\[[^\]]+\])(?P<user>[A-Za-z0-9._$-]{2,})\b",
    re.IGNORECASE | re.MULTILINE,
)
_NXC_RID_USER_RE = re.compile(
    r"^(?:SMB|RPC)\s+\S+\s+\d+\s+\S+\s+(?:0x[0-9a-f]+|\d+):\s+"
    r"(?:[^\\\s]+\\)?(?P<user>[A-Za-z0-9._$-]{2,})\s+\(SidTypeUser\)",
    re.IGNORECASE | re.MULTILINE,
)
_RPC_USER_RE = re.compile(r"\buser:\[(?P<user>[^\]]+)\]\s+rid:\[[^\]]+\]", re.IGNORECASE)
_BASE_DN_RE = re.compile(
    r"\b(?:namingContexts|defaultNamingContext|rootDomainNamingContext):\s*([A-Za-z0-9_=,.-]+)",
    re.IGNORECASE,
)
_ASREP_RE = re.compile(r"(\$krb5asrep\$[^\s]+)", re.IGNORECASE)
_ASREP_USER_RE = re.compile(r"\$krb5asrep\$\d+\$([^:@$]+)(?:@([^:$]+))?:", re.IGNORECASE)
_TGS_RE = re.compile(r"(\$krb5tgs\$[^\s]+)", re.IGNORECASE)
_TGS_USER_RE = re.compile(r"\$krb5tgs\$\d+\$\*?([^$*:]+)", re.IGNORECASE)
# pwdump / secretsdump / nxc --sam|--lsa|--ntds tuple: [DOMAIN\]user:RID:LM:NT:::
_NTDS_HASH_RE = re.compile(
    r"(?:(?P<domain>[^\s\\:]+)\\)?(?P<user>[^\s\\:]+):(?P<rid>\d+):[0-9a-fA-F]{32}:(?P<nt>[0-9a-fA-F]{32}):::"
)
# whoami-style identity from command-execution output, tolerating an nxc row prefix.
_NXC_ROW_PREFIX = r"(?:(?:SMB|WINRM|WMI|RPC|SSH)\s+\S+\s+\d+\s+\S+\s+)?"
_SYSTEM_ID_RE = re.compile(r"\bnt authority\\system\b", re.IGNORECASE)
_WHOAMI_ID_RE = re.compile(
    rf"^{_NXC_ROW_PREFIX}(?P<id>nt authority\\system|[A-Za-z0-9][A-Za-z0-9.-]*\\[A-Za-z0-9._$-]{{2,}})\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_EXEC_SUCCESS_RE = re.compile(
    r"\bexecuted command\b|\[\+\]\s+executed|Microsoft Windows \[Version|^[A-Za-z]:\\.*>",
    re.IGNORECASE | re.MULTILINE,
)
# Linux `id` output — proof of an interactive shell as a specific uid over ssh.
_LINUX_ID_RE = re.compile(r"\buid=(?P<uid>\d+)\((?P<user>[^)]+)\)\s+gid=\d+", re.IGNORECASE)
# penelope (brightio) reverse-shell handler session signals.
_PENELOPE_GOT_RE = re.compile(r"got reverse shell from\s+(?P<info>.+)", re.IGNORECASE)
_PENELOPE_UPGRADE_RE = re.compile(r"shell upgraded|spawned a pty|upgrading shell to pty", re.IGNORECASE)
_PENELOPE_SID_RE = re.compile(r"session\s*id\s*[:=]?\s*(?P<sid>\w+)", re.IGNORECASE)
_PENELOPE_HOST_RE = re.compile(r"(?P<host>[A-Za-z0-9][\w.-]*)~(?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
# ADCS: certipy find vulnerabilities + certipy/pywhisker certificate material.
_ESC_RE = re.compile(r"\bESC(\d{1,2})\b")
_CERTIPY_TEMPLATE_RE = re.compile(r"Template Name\s*:\s*(?P<name>\S[^\n]*)", re.IGNORECASE)
_CERTIPY_UPN_RE = re.compile(r"certificate with UPN '(?P<upn>[^']+)'", re.IGNORECASE)
_PFX_SAVED_RE = re.compile(r"saved[^\n]*?(?P<pfx>[A-Za-z0-9_./\\-]+\.pfx)", re.IGNORECASE)
_JOHN_SHOW_RE = re.compile(r"^(?P<user>[A-Za-z0-9._$-]{2,}):(?P<password>[^:\s][^:\r\n]*)(?::.*)?$")
_CPASSWORD_RE = re.compile(r"\bcpassword\s*=\s*[\"']?([^\"'\s<>]+)", re.IGNORECASE)
_GPP_FILE_RE = re.compile(r"\b(?:Groups|ScheduledTasks|Services|DataSources|Printers|Drives)\.xml\b", re.IGNORECASE)
_NMAP_OPEN_RE = re.compile(
    r"^(?P<port>\d+)/(?:tcp|udp)\s+open(?:\|\w+)?\s+(?P<service>\S+)?(?:\s+(?P<version>.*?))?\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_NMAP_DISCOVERED_RE = re.compile(
    r"Discovered open port (?P<port>\d+)/(?P<proto>tcp|udp) on (?P<host>\S+)",
    re.IGNORECASE,
)
_NMAP_DOMAIN_NAME_RE = re.compile(
    r"^\|_?\s*(?:Domain name|DNS_Domain_Name|NetBIOS_Domain_Name):\s*"
    r"(?P<domain>[A-Za-z0-9][A-Za-z0-9_.-]*\.[A-Za-z0-9_.-]+)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_NMAP_FQDN_RE = re.compile(
    r"^\|_?\s*FQDN:\s*(?P<fqdn>[A-Za-z0-9][A-Za-z0-9_.-]*\.[A-Za-z0-9_.-]+)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_NMAP_COMPUTER_NAME_RE = re.compile(
    r"^\|_?\s*(?:Computer name|NetBIOS computer name):\s*(?P<name>[A-Za-z0-9_.-]+)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_NMAP_SMB_SIGNING_RE = re.compile(
    r"Message signing enabled(?: and (?P<required>required)| but not required)?",
    re.IGNORECASE,
)
_NMAP_HTTP_TITLE_RE = re.compile(r"^\|\s*_?http-title:\s*(?P<title>.+)$", re.IGNORECASE | re.MULTILINE)
_NMAP_HTTP_SERVER_RE = re.compile(r"^\|\s*_?http-server-header:\s*(?P<header>.+)$", re.IGNORECASE | re.MULTILINE)
_NMAP_HTTP_GENERATOR_RE = re.compile(r"^\|\s*_?http-generator:\s*(?P<generator>.+)$", re.IGNORECASE | re.MULTILINE)
_NMAP_HTTP_REDIRECT_RE = re.compile(r"^\|\s*_?http-title:\s*Did not follow redirect to (?P<location>\S+)", re.IGNORECASE | re.MULTILINE)
_NMAP_FTP_ANON_RE = re.compile(r"ftp-anon:\s*Anonymous FTP login allowed|Anonymous FTP login allowed", re.IGNORECASE)
_NMAP_SSH_HOSTKEY_RE = re.compile(
    r"^\|_?\s+(?P<bits>\d{3,5})\s+(?P<fingerprint>[0-9a-f:]{16,})\s+\((?P<kind>[^)]+)\)",
    re.IGNORECASE | re.MULTILINE,
)
_NMAP_SNMP_FIELD_RE = re.compile(r"^\|_?\s*(?P<key>enterprise|name|description|location|contact):\s*(?P<value>.+)$", re.IGNORECASE | re.MULTILINE)
_NXC_SIGNING_RE = re.compile(r"\(signing:(?P<enabled>True|False)\)", re.IGNORECASE)
_NXC_SMBV1_RE = re.compile(r"\(SMBv1:(?P<enabled>True|False)\)", re.IGNORECASE)

# Web content/vhost discovery + nikto output shapes (tool-stable signals only).
_WEB_GOBUSTER_RE = re.compile(r"^(?P<path>/\S*)\s+\(Status:\s*(?P<code>\d{3})\)", re.MULTILINE)
_WEB_FEROX_RE = re.compile(
    r"^\s*(?P<code>\d{3})\s+\w+\s+\d+l\s+\d+w\s+\d+c\s+(?P<url>https?://\S+)",
    re.IGNORECASE | re.MULTILINE,
)
_WEB_FFUF_RE = re.compile(r"^(?P<token>\S+)\s+\[Status:\s*(?P<code>\d{3})", re.MULTILINE)
_WEB_DIRB_RE = re.compile(r"^\+\s+(?P<url>https?://\S+)\s+\(CODE:(?P<code>\d{3})", re.IGNORECASE | re.MULTILINE)
_WEB_GOBUSTER_VHOST_RE = re.compile(r"Found:\s*(?P<name>\S+)\s+\(Status:\s*(?P<code>\d{3})\)", re.IGNORECASE)
_NIKTO_FINDING_RE = re.compile(r"^\+\s+(?P<text>\S.+)$", re.MULTILINE)
_WEB_PATH_IN_TEXT_RE = re.compile(r"/[A-Za-z0-9_][A-Za-z0-9_./-]{1,}")
_WEB_INTERESTING_RE = re.compile(
    r"/admin|/api|/upload|/backup|/login|/dashboard|/config|/phpmyadmin|/wp-admin"
    r"|\.git|\.svn|\.bak|\.old|\.zip|\.tar|\.sql|\.env|\.config",
    re.IGNORECASE,
)
_GIT_HEAD_RE = re.compile(r"\bref:\s+refs/heads/(?P<branch>[A-Za-z0-9_./-]+)", re.IGNORECASE)
_GIT_DUMPER_SUCCESS_RE = re.compile(
    r"\b(?:fetching|downloading|downloaded|repository|objects|refs/heads|HEAD)\b",
    re.IGNORECASE,
)
_SOURCE_SECRET_RE = re.compile(
    r"\b(?P<key>password|passwd|pwd|secret|api[_-]?key|token|connection(?:string)?|connstr)"
    r"\b\s*[:=]\s*(?P<value>[^\s\"']{4,}|\"[^\"]{4,}\"|'[^']{4,}')",
    re.IGNORECASE,
)
_NIKTO_NOISE_PREFIXES = (
    "target ip", "target hostname", "target port", "start time", "end time",
    "server:", "ssl info", "root page", "retrieved", "no cgi", "scan terminated",
    "host(s) tested", "requests:", "0 host", "1 host",
)
_SQLMAP_VULN_RE = re.compile(
    r"\b(?:parameter\s+['\"].+?['\"]\s+is vulnerable|is vulnerable to .+sql injection|"
    r"appears to be .+sql injectable)\b",
    re.IGNORECASE,
)
_SQLMAP_DBMS_RE = re.compile(r"\bback-end DBMS:\s*(?P<dbms>[^\r\n]+)", re.IGNORECASE)
_SQLMAP_DATABASE_HEADER_RE = re.compile(r"\bavailable databases\s*\[(?P<count>\d+)\]", re.IGNORECASE)
_SQLMAP_STAR_ROW_RE = re.compile(r"^\[\*\]\s+(?P<name>[A-Za-z0-9_$.-]{1,80})\s*$", re.MULTILINE)
_SQLMAP_TABLE_RE = re.compile(
    r"\bDatabase:\s*(?P<database>[A-Za-z0-9_$.-]+)\s*\n(?:\[[^\n]+\]\s*)?Table:\s*(?P<table>[A-Za-z0-9_$.-]+)",
    re.IGNORECASE,
)
_SQLMAP_DUMP_RE = re.compile(r"\b(?:dumped|dumping)\b.+\b(?:entries|CSV file|table)\b", re.IGNORECASE)
_SQLMAP_OS_SHELL_RE = re.compile(
    r"\bos-shell\b|os-shell\s*>|web backdoor.*(?:uploaded|created|saved)|command shell session",
    re.IGNORECASE,
)
_HTTP_STATUS_RE = re.compile(r"^HTTP/\S+\s+(?P<status>\d{3})(?:\s+(?P<reason>.*))?$", re.IGNORECASE | re.MULTILINE)
_HTTP_HEADER_RE = re.compile(r"^(?P<key>Server|X-Powered-By|Location|Content-Type):\s*(?P<value>.+)$", re.IGNORECASE | re.MULTILINE)
_WHATWEB_PLUGIN_RE = re.compile(r"\b(?P<name>[A-Za-z][A-Za-z0-9_.+-]{1,30})\[(?P<value>[^\]\r\n]{1,120})\]")
_SSH_BANNER_RE = re.compile(r"\bSSH-(?P<version>[12]\.\d+)-(?P<banner>[^\r\n]+)", re.IGNORECASE)
_FTP_BANNER_RE = re.compile(r"^(?:220[- ](?P<banner>.+)|230\s+(?P<login>Login successful.*))$", re.IGNORECASE | re.MULTILINE)
_SNMP_SYSDESCR_RE = re.compile(r"SNMPv2-MIB::sysDescr\.0\s*=\s*(?:STRING:\s*)?(?P<value>.+)", re.IGNORECASE)
_SNMP_SYSNAME_RE = re.compile(r"SNMPv2-MIB::sysName\.0\s*=\s*(?:STRING:\s*)?(?P<value>.+)", re.IGNORECASE)
_SNMP_SYSLOCATION_RE = re.compile(r"SNMPv2-MIB::sysLocation\.0\s*=\s*(?:STRING:\s*)?(?P<value>.+)", re.IGNORECASE)
_SNMP_SYSCONTACT_RE = re.compile(r"SNMPv2-MIB::sysContact\.0\s*=\s*(?:STRING:\s*)?(?P<value>.+)", re.IGNORECASE)
_OS_SIGNATURES: dict[str, tuple[re.Pattern, ...]] = {
    "windows": (
        re.compile(r"\bMicrosoft Windows\b", re.IGNORECASE),
        re.compile(r"\bWindows\s+(?:Server|\d|XP|Vista)\b", re.IGNORECASE),
        re.compile(r"\bOS:\s*Windows\b", re.IGNORECASE),
        re.compile(r"\bRunning:\s*(?:Microsoft\s+)?Windows\b", re.IGNORECASE),
        re.compile(r"cpe:/o:microsoft:windows", re.IGNORECASE),
        re.compile(r"\bMicrosoft-IIS\b", re.IGNORECASE),
    ),
    "linux": (
        re.compile(r"\bLinux\b", re.IGNORECASE),
        re.compile(r"\bUbuntu\b", re.IGNORECASE),
        re.compile(r"\bDebian\b", re.IGNORECASE),
        re.compile(r"\bCentOS\b", re.IGNORECASE),
        re.compile(r"\bRed Hat\b", re.IGNORECASE),
        re.compile(r"\bFedora\b", re.IGNORECASE),
        re.compile(r"\bSamba\b", re.IGNORECASE),
        re.compile(r"\bUnix\b", re.IGNORECASE),
        re.compile(r"cpe:/o:linux", re.IGNORECASE),
    ),
}
_PRIVESC_ACTION_IDS = {
    "linux-enum", "sudo-abuse", "writable-passwd", "nfs-squash",
    "lxc-lxd-escape", "docker-socket", "suid-gtfobins", "pspy-monitor",
    "cron-abuse", "capabilities", "linux-loot-hunt", "linux-persistence",
    "windows-enum", "seimpersonate", "unquoted-service-path",
    "weak-service-permissions", "alwaysinstallelevated", "dpapi-secrets",
    "stored-credentials", "wesng-patch-gaps", "windows-persistence",
    "lsass-dump-onbox",
}
_LINUX_PRIVESC_ACTION_IDS = {
    "linux-enum", "sudo-abuse", "writable-passwd", "nfs-squash",
    "lxc-lxd-escape", "docker-socket", "suid-gtfobins", "pspy-monitor",
    "cron-abuse", "capabilities", "linux-loot-hunt", "linux-persistence",
}
_WINDOWS_PRIVESC_ACTION_IDS = _PRIVESC_ACTION_IDS - _LINUX_PRIVESC_ACTION_IDS
_UNAME_RE = re.compile(
    r"\bLinux\s+(?P<host>\S+)\s+(?P<kernel>[0-9][^\s]+).*?\b(?P<arch>x86_64|i[3-6]86|aarch64|armv\w+)\b",
    re.IGNORECASE,
)
_SUID_PATH_RE = re.compile(r"(?P<path>/[A-Za-z0-9_./+-]+)")
_CAPABILITY_RE = re.compile(r"^(?P<path>/\S+)\s*=\s*(?P<caps>[^#\r\n]+cap_[^#\r\n]+)$", re.IGNORECASE | re.MULTILINE)
_PASSWD_MODE_RE = re.compile(r"^(?P<mode>-[rwxstST-]{9})\s+.*\s+(?P<path>/etc/passwd)\b", re.MULTILINE)
_WIN_PRIV_RE = re.compile(r"^\s*(?P<name>Se[A-Za-z0-9]+Privilege)\s+.+?\s+(?P<state>Enabled|Disabled)\s*$", re.IGNORECASE | re.MULTILINE)
_SYSTEMINFO_FIELD_RE = re.compile(r"^\s*(?P<key>OS Name|OS Version|System Type):\s*(?P<value>.+)$", re.IGNORECASE | re.MULTILINE)
_DANGEROUS_WIN_PRIVS = {
    "seimpersonateprivilege", "seassignprimarytokenprivilege", "sedebugprivilege",
    "sebackupprivilege", "serestoreprivilege", "setakeownershipprivilege",
    "seloaddriverprivilege", "semanagevolumeprivilege", "setcbprivilege",
}

# Post-credential AD path signals.
_NXC_AUTH_RE = re.compile(r"^\s*(?P<proto>SMB|LDAP|WINRM|RDP|SSH|FTP)\s+\S+\s+\d+\s+\S+\s+\[\+\]\s+(?P<auth>.+)$", re.IGNORECASE | re.MULTILINE)
_AUTH_MATERIAL_RE = re.compile(r"^(?:(?P<domain>[^\\\s:/]+)\\)?(?P<user>[A-Za-z0-9._$-]{2,}):(?P<secret>[^\s()]+)")
# An NT hash (or LM:NT pair) — pass-the-hash auth material, not a plaintext password.
_NT_HASH_RE = re.compile(r"^(?:[0-9a-fA-F]{32}:)?[0-9a-fA-F]{32}$")
_EW_PROMPT_RE = re.compile(r"\*Evil-WinRM\*\s+PS\s+", re.IGNORECASE)
_BH_ZIP_RE = re.compile(r"\b[^\s/\\]+(?:bloodhound|bhloot|sharphound)?[^\s/\\]*\.zip\b", re.IGNORECASE)
_BH_JSON_RE = re.compile(r"\b(?:users|groups|computers|domains|ous|gpos|containers|sessions|localadmins|trusts|acls)\.json\b", re.IGNORECASE)
_ATTACK_PATH_RE = re.compile(r"\b(?:attack path|shortest paths? to domain admins?|path to da|owned principal)\b", re.IGNORECASE)
_FAILURE_REASONS = {
    "status_logon_failure": "logon_failure",
    "status_account_locked_out": "account_locked_out",
    "status_password_expired": "password_expired",
    "status_account_disabled": "account_disabled",
    "status_access_denied": "access_denied",
}

_NOISE_USERS = {
    "badpwdcount",
    "description",
    "distinguishedname",
    "dn",
    "lastlogon",
    "name",
    "pwdlastset",
    "samaccountname",
    "useraccountcontrol",
    "username",
}
_SHARE_HEADER_WORDS = {"share", "sharename", "-----", "---------", "name"}
_SHARE_PERMISSION_WORDS = {"READ", "WRITE", "READ,WRITE", "WRITE,READ", "NO ACCESS", "NONE"}
_JOHN_NOISE_PREFIXES = (
    "loaded ",
    "session.",
    "cost ",
    "will run ",
    "press ",
    "use the ",
    "warning:",
    "no password hashes",
    "password hash",
    "password hashes",
)


# --------------------------------------------------------------------------- #
# Shared scoping / validation helpers
# --------------------------------------------------------------------------- #
def _domain_from_facts(ws: Workspace) -> str:
    vals = ws.facts.values("ad.domain_known")
    if vals:
        return vals[0].get("name", "")
    return ""


def _scope_for_domain(ws: Workspace, domain: str = "") -> str:
    name = domain or _domain_from_facts(ws) or "domain"
    return f"domain:{name}"


def _add(out: list[Fact], fact: Fact) -> None:
    if not any(
        existing.kind == fact.kind and existing.value == fact.value and existing.state == fact.state
        for existing in out
    ):
        out.append(fact)


def _line_for_match(text: str, match: re.Match) -> str:
    start = text.rfind("\n", 0, match.start()) + 1
    end = text.find("\n", match.end())
    if end == -1:
        end = len(text)
    return text[start:end].strip()[:220]


def _add_os_observation(
    facts: list[Fact],
    ws: Workspace,
    source: str,
    *,
    family: str,
    evidence: str,
    confidence: str,
    tool: str,
    promote: bool = False,
) -> None:
    family = family.strip().lower()
    if family not in {"windows", "linux"}:
        return
    value = {
        "family": family,
        "confidence": confidence,
        "tool": tool,
        "evidence": evidence.strip()[:220],
    }
    _add(facts, Fact("host.os_hint", f"host:{ws.target}", value, ProofState.SUPPORTED, source))
    if promote:
        _add(facts, Fact("host.os_family", f"host:{ws.target}", value, ProofState.SUPPORTED, source))


def _add_os_from_text(
    text: str,
    ws: Workspace,
    source: str,
    facts: list[Fact],
    *,
    tool: str,
    confidence: str = "high",
    promote: bool = False,
) -> None:
    matches: dict[str, str] = {}
    for family, patterns in _OS_SIGNATURES.items():
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                matches[family] = _line_for_match(text, match) or match.group(0)
                break
    # Multiple families in one transcript means a proxy, relay, Samba-on-Linux vs
    # Windows-service mix, or otherwise ambiguous evidence. Keep hints, but do not
    # promote to a single OS family from conflicting text.
    promote_single = promote and len(matches) == 1
    for family, evidence in matches.items():
        _add_os_observation(
            facts,
            ws,
            source,
            family=family,
            evidence=evidence,
            confidence=confidence,
            tool=tool,
            promote=promote_single,
        )


def _clean_username(user: str) -> str:
    user = user.strip().strip(",;:")
    if "\\" in user:
        user = user.rsplit("\\", 1)[1]
    if "@" in user:
        user = user.split("@", 1)[0]
    return user.strip()


def _valid_username(user: str, *, allow_machine: bool = True) -> bool:
    if not user:
        return False
    if user.lower() in _NOISE_USERS:
        return False
    if not allow_machine and user.endswith("$"):
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9._$-]{2,}", user))


def _valid_password(password: str) -> bool:
    password = password.strip()
    if not password or password in {"?", "*", "<password>", "{{password}}"}:
        return False
    lowered = password.lower()
    if lowered.startswith(("status", "recovered", "progress", "guess")):
        return False
    return True


def _domain_from_text(text: str) -> str:
    match = _DOMAIN_RE.search(text)
    if not match:
        return ""
    domain = match.group(1).strip()
    if domain in {"None", "-"}:
        return ""
    return domain


def _base_dn_from_domain(domain: str) -> str:
    return ",".join(f"DC={part}" for part in domain.split(".") if part)


def _usernames(text: str) -> list[str]:
    users: set[str] = set()
    for regex in (_SAM_RE, _UPN_RE, _NXC_USER_ROW_RE):
        for match in regex.finditer(text):
            user = _clean_username(match.group(1))
            if not _valid_username(user):
                continue
            users.add(user)
    return sorted(users, key=str.lower)


def _rid_usernames(text: str) -> list[str]:
    users: set[str] = set()
    for regex in (_NXC_RID_USER_RE, _RPC_USER_RE):
        for match in regex.finditer(text):
            user = _clean_username(match.group("user"))
            if not _valid_username(user, allow_machine=False):
                continue
            users.add(user)
    return sorted(users, key=str.lower)


def _command_arg(command: str, *names: str) -> str:
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()
    for idx, token in enumerate(parts):
        if token in names and idx + 1 < len(parts):
            return parts[idx + 1]
        for name in names:
            if token.startswith(f"{name}="):
                return token.split("=", 1)[1]
    return ""


def _is_ldap_command(command: str) -> bool:
    cmd = f" {command.lower()} "
    return " ldap " in cmd or "ldapsearch" in cmd


def _is_smb_command(command: str) -> bool:
    cmd = f" {command.lower()} "
    return " smb " in cmd or "smbclient" in cmd or "rpcclient" in cmd or "enum4linux" in cmd or "smbmap" in cmd


def _is_cracking_command(command: str) -> bool:
    lowered = f" {command.lower()} "
    return " hashcat " in lowered or re.search(r"(^|[\s/])john(\s|$)", lowered) is not None


def _is_ssh_command(command: str) -> bool:
    """An ssh login/exec command (ssh, sshpass-wrapped ssh, or `nxc ssh`). Used to
    route to the Linux-shell proof parser and to keep the Windows exec parser from
    misfiring on a Linux target."""
    lowered = f" {command.lower()} "
    if "sshuttle" in lowered:   # a tunnel, not a login — never a shell proof
        return False
    return "sshpass" in lowered or " ssh " in lowered or " nxc ssh " in lowered


def _is_exec_command(command: str) -> bool:
    lowered = command.lower()
    is_nxc = "nxc " in lowered or lowered.startswith("nxc ")
    # -x/-X is NetExec command execution; other tools (e.g. ldapsearch -x = simple
    # auth) use -x for unrelated things, so only treat it as exec for nxc.
    if is_nxc and re.search(r"\s-x(\s|'|\")", lowered):
        return True
    return any(
        tool in lowered
        for tool in ("wmiexec", "psexec", "atexec", "smbexec", "evil-winrm", "enter-pssession", "penelope")
    )


# Interactive Windows sessions (a shell you can run on-host tooling from), as
# opposed to a one-shot nxc -x command. Penelope is handled separately because
# its shells are OS-classified from the handler banner.
_INTERACTIVE_WIN_TOOLS = {"evil-winrm", "wmiexec", "psexec", "atexec", "smbexec", "winrs"}
_INTERACTIVE_RE = re.compile(
    r"\*Evil-WinRM\*\s+PS|semi-interactive shell|Launching semi-interactive|^\[[^\]]+\]:\s*PS[> ]",
    re.IGNORECASE | re.MULTILINE,
)


def _is_web_vhost_command(command: str) -> bool:
    c = command.lower()
    if "gobuster vhost" in c:
        return True
    if "host: fuzz" in c or "host:fuzz" in c:
        return True
    return "wfuzz" in c and "host:" in c and "fuzz" in c


def _is_web_content_command(command: str) -> bool:
    if _is_web_vhost_command(command):
        return False
    c = command.lower()
    if "feroxbuster" in c or "gobuster dir" in c or "dirb " in c or "dirsearch" in c:
        return True
    # ffuf content mode fuzzes the path (…/FUZZ); vhost mode fuzzes the Host header.
    return "ffuf" in c and "/fuzz" in c


def _url_path(url: str) -> str:
    match = re.match(r"https?://[^/]+(/\S*)", url)
    return match.group(1) if match else url


def _looks_anonymous_ldap_command(command: str, action: Action) -> bool:
    lowered = command.lower()
    if action.id == "ad-anon-ldap-enum":
        return True
    return _is_ldap_command(command) and (" -x " in f" {lowered} " or "-u ''" in lowered or '-u ""' in lowered)


# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #
def parse_action_output(action: Action, ws: Workspace, command: str, stdout: str, stderr: str, source: str) -> list[Fact]:
    """Dispatch parser for the current action/command."""
    text = "\n".join(part for part in (stdout, stderr) if part)
    facts: list[Fact] = []
    lowered_command = command.lower()
    domain_hint = _domain_from_text(text)

    if "nmap " in lowered_command or lowered_command.startswith("nmap "):
        _parse_nmap(text, ws, source, facts, action.id)

    if "nxc " in lowered_command or lowered_command.startswith("nxc "):
        _parse_nxc_common(text, ws, source, facts)
        if _is_ldap_command(command) and (action.id == "ad-anon-ldap-enum" or "--users" in lowered_command):
            _parse_user_list(
                text,
                ws,
                source,
                facts,
                prove_anonymous_ldap=_looks_anonymous_ldap_command(command, action),
                domain_hint=domain_hint,
            )
        if _is_smb_command(command):
            _parse_nxc_smb_session(text, ws, command, source, facts)
            _parse_smb_shares(text, ws, source, facts)
            if action.id == "ad-user-enum" or "--rid-brute" in lowered_command:
                _parse_rid_user_list(text, ws, source, facts, domain_hint=domain_hint)
        if "--asreproast" in lowered_command:
            _parse_asrep_hashes(text, ws, source, facts)
        _parse_nxc_auth_validation(text, ws, source, facts)
        _parse_auth_failures(text, ws, source, facts)
        if "--kerberoast" in lowered_command or "--kerberoasting" in lowered_command:
            _parse_tgs_hashes(text, ws, source, facts)
        if "--bloodhound" in lowered_command:
            _parse_bloodhound_collection(text, ws, source, facts)

    if "ldapsearch" in lowered_command:
        _parse_ldapsearch(text, ws, source, facts)
        if "(objectclass=user)" in lowered_command.lower():
            _parse_user_list(
                text,
                ws,
                source,
                facts,
                prove_anonymous_ldap=_looks_anonymous_ldap_command(command, action),
                domain_hint=domain_hint,
            )

    if "smbclient" in lowered_command or "smbmap" in lowered_command or "rpcclient" in lowered_command or "enum4linux" in lowered_command:
        _parse_smb_shares(text, ws, source, facts)
        _parse_gpp_artifacts(text, ws, source, facts)
        if action.id == "ad-user-enum" or "enumdomusers" in lowered_command:
            _parse_rid_user_list(text, ws, source, facts, domain_hint=domain_hint)

    if "getnpusers" in lowered_command.lower() or "asreproast" in lowered_command:
        _parse_asrep_hashes(text, ws, source, facts)

    if "getuserspns" in lowered_command or "kerberoast" in lowered_command:
        _parse_tgs_hashes(text, ws, source, facts)

    is_nxc = "nxc " in lowered_command or lowered_command.startswith("nxc ")
    if "secretsdump" in lowered_command or (is_nxc and any(flag in lowered_command for flag in ("--ntds", "--sam", "--lsa"))):
        _parse_ntlm_dump(text, ws, command, source, facts)

    if "bloodhound-python" in lowered_command or "sharphound" in lowered_command:
        _parse_bloodhound_collection(text, ws, source, facts)
    if "bloodhound" in lowered_command:
        _parse_bloodhound_analysis(text, ws, source, facts)

    if " winrm " in f" {lowered_command} " or "evil-winrm" in lowered_command:
        _parse_evil_winrm(text, ws, command, source, facts)

    is_ssh = _is_ssh_command(command)
    if is_ssh:
        _parse_ssh_exec(text, ws, command, source, facts)

    if is_nxc and " rdp " in f" {lowered_command} ":
        _parse_nxc_rdp(text, ws, command, source, facts)

    if _is_cracking_command(command):
        _parse_cracked_credentials(text, ws, command, source, facts)

    # A Linux ssh login is handled above; the Windows exec parser must not claim a
    # Windows foothold from `nxc ssh -x id` output.
    if _is_exec_command(command) and not is_ssh:
        _parse_command_execution(text, ws, command, source, facts)

    if "penelope" in lowered_command:
        _parse_penelope(text, ws, source, facts)

    if action.id in _PRIVESC_ACTION_IDS:
        _parse_privesc_output(action.id, text, ws, command, source, facts)

    if "certipy" in lowered_command or "pywhisker" in lowered_command:
        _parse_adcs(text, ws, command, source, facts)

    if _is_web_vhost_command(command):
        _parse_web_vhosts(text, ws, source, facts)
    elif _is_web_content_command(command):
        _parse_web_content(text, ws, source, facts)
    if "sqlmap" in lowered_command:
        _parse_sqlmap(text, ws, source, facts)
    if "git-dumper" in lowered_command or "/.git/" in lowered_command or _GIT_HEAD_RE.search(text):
        _parse_git_source(text, ws, command, source, facts)
    if "nikto" in lowered_command:
        _parse_nikto(text, ws, source, facts)
    if "whatweb" in lowered_command or "curl" in lowered_command:
        _parse_http_metadata(text, ws, source, facts)
    if any(tool in lowered_command for tool in ("snmpwalk", "snmp-check", "onesixtyone")):
        _parse_snmp_output(text, ws, command, source, facts)
    if "ftp " in f" {lowered_command} " or "lftp" in lowered_command:
        _parse_ftp_output(text, ws, command, source, facts)
    if _SSH_BANNER_RE.search(text):
        _parse_ssh_banner(text, ws, source, facts)
    if (" 21" in f" {lowered_command} " or "ftp" in lowered_command) and _FTP_BANNER_RE.search(text):
        _parse_ftp_output(text, ws, command, source, facts)

    return facts


# --------------------------------------------------------------------------- #
# nmap
# --------------------------------------------------------------------------- #
def _parse_nmap(text: str, ws: Workspace, source: str, facts: list[Fact], action_id: str) -> None:
    open_ports: dict[tuple[int, str], dict] = {}
    _add_os_from_text(text, ws, source, facts, tool="nmap", confidence="high", promote=True)

    for match in _NMAP_DISCOVERED_RE.finditer(text):
        port = int(match.group("port"))
        proto = match.group("proto").lower()
        open_ports[(port, proto)] = {"port": port, "protocol": proto}

    for match in _NMAP_OPEN_RE.finditer(text):
        port_text = match.group("port")
        line = match.group(0)
        proto = "udp" if f"{port_text}/udp" in line.lower() else "tcp"
        port = int(port_text)
        service = (match.group("service") or "").strip()
        version = (match.group("version") or "").strip()
        value = {"port": port, "protocol": proto}
        if service:
            value["service"] = service
        if version:
            value["version"] = version
        open_ports[(port, proto)] = value

    if re.search(r"Host is up|Nmap scan report for", text, re.IGNORECASE):
        value = {"target": ws.target}
        latency = re.search(r"Host is up \(([^)]+)\)", text, re.IGNORECASE)
        if latency:
            value["latency"] = latency.group(1)
        _add(facts, Fact("host.up", f"host:{ws.target}", value, ProofState.SUPPORTED, source))

    scan_seen = bool(open_ports) or bool(re.search(r"Host is up|Nmap done|Nmap scan report for", text, re.IGNORECASE))
    if scan_seen and ("nmap-fast" in action_id or "all-ports" in action_id or "-p-" in source):
        _add(facts, Fact("scan.nmap.quick", f"host:{ws.target}", {"profile": "open-port-discovery"}, ProofState.SUPPORTED, source))
    if scan_seen and ("version" in action_id or "-sc" in source.lower() or "-sv" in source.lower()):
        _add(facts, Fact("scan.nmap.version", f"host:{ws.target}", {"profile": "service-version"}, ProofState.SUPPORTED, source))
    if scan_seen and ("udp" in action_id or " -su" in source.lower()):
        _add(facts, Fact("scan.nmap.udp", f"host:{ws.target}", {"profile": "udp"}, ProofState.SUPPORTED, source))

    ports_for_summary: list[int] = []
    for (_port, _proto), value in sorted(open_ports.items()):
        port = value["port"]
        proto = value["protocol"]
        service = value.get("service", "")
        ports_for_summary.append(port)
        _add(facts, Fact(f"port:{port}", f"host:{ws.target}", value, ProofState.SUPPORTED, source))
        if service:
            _add(facts, Fact(f"service.{_normalize_service(service)}", f"host:{ws.target}", value, ProofState.SUPPORTED, source))
        _parse_service_reachability(port, proto, service, ws, source, facts)

    if ports_for_summary:
        _add(facts, Fact("ports.open", f"host:{ws.target}", {"ports": sorted(set(ports_for_summary))}, ProofState.SUPPORTED, source))

    script_context = _parse_nmap_script_facts(text, ws, source, facts)
    tcp_ports = {value["port"] for value in open_ports.values() if value["protocol"] == "tcp"}
    if {88, 389, 445}.issubset(tcp_ports) or _looks_like_ad_ldap(text):
        value = {"ports": sorted(tcp_ports & {88, 389, 445})}
        value.update(script_context)
        _add(facts, Fact("ad.dc_candidate", f"host:{ws.target}", value, ProofState.SUPPORTED, source))


def _parse_nmap_script_facts(text: str, ws: Workspace, source: str, facts: list[Fact]) -> dict:
    context: dict = {}
    domains = {match.group("domain").strip().lower() for match in _NMAP_DOMAIN_NAME_RE.finditer(text)}
    fqdns = {match.group("fqdn").strip().lower() for match in _NMAP_FQDN_RE.finditer(text)}
    for match in _NMAP_FQDN_RE.finditer(text):
        fqdn = match.group("fqdn").strip().lower()
        parts = [part for part in fqdn.split(".") if part]
        if len(parts) > 2:
            domains.add(".".join(parts[1:]))
    domain = sorted(domains, key=str.lower)[0] if domains else ""
    if domain:
        context["domain"] = domain
        _add(facts, Fact("ad.domain_known", f"domain:{domain}", {"name": domain}, ProofState.SUPPORTED, source))
        _add(facts, Fact("ad.base_dn", f"domain:{domain}", {"base_dn": _base_dn_from_domain(domain)}, ProofState.SUPPORTED, source))
        _add(facts, Fact("host.domain", f"host:{ws.target}", {"domain": domain}, ProofState.SUPPORTED, source))

    names = {match.group("name").strip() for match in _NMAP_COMPUTER_NAME_RE.finditer(text)}
    if names:
        context["name"] = sorted(names, key=str.lower)[0]
        _add(facts, Fact("host.hostname", f"host:{ws.target}", {"name": context["name"]}, ProofState.SUPPORTED, source))

    for fqdn in sorted(fqdns, key=str.lower):
        parts = [part for part in fqdn.split(".") if part]
        value = {"fqdn": fqdn}
        if parts:
            value["hostname"] = parts[0]
        if len(parts) > 1:
            value["domain"] = ".".join(parts[1:])
        _add(facts, Fact("host.fqdn", f"host:{ws.target}", value, ProofState.SUPPORTED, source))

    signing = _NMAP_SMB_SIGNING_RE.search(text)
    if signing:
        value = {"enabled": True, "tool": "nmap"}
        if signing.group("required"):
            value["required"] = True
        elif "but not required" in signing.group(0).lower():
            value["required"] = False
        _add(facts, Fact("smb.signing", f"host:{ws.target}", value, ProofState.SUPPORTED, source))

    titles = []
    for match in _NMAP_HTTP_TITLE_RE.finditer(text):
        title = match.group("title").strip()
        if not title or title.lower().startswith(("did not follow redirect", "site doesn't have a title")):
            continue
        titles.append(title)
    if titles:
        _add(facts, Fact("web.title", f"host:{ws.target}", {"titles": sorted(set(titles))[:10]}, ProofState.SUPPORTED, source))

    headers = sorted({match.group("header").strip() for match in _NMAP_HTTP_SERVER_RE.finditer(text) if match.group("header").strip()})
    if headers:
        _add(facts, Fact("web.server", f"host:{ws.target}", {"headers": headers[:10]}, ProofState.SUPPORTED, source))

    generators = sorted({match.group("generator").strip() for match in _NMAP_HTTP_GENERATOR_RE.finditer(text) if match.group("generator").strip()})
    tech = []
    for item in generators:
        tech.append({"name": "generator", "value": item})
    redirects = sorted({match.group("location").strip() for match in _NMAP_HTTP_REDIRECT_RE.finditer(text) if match.group("location").strip()})
    if redirects:
        _add(facts, Fact("http.redirect", f"host:{ws.target}", {"locations": redirects[:10]}, ProofState.SUPPORTED, source))
    if tech:
        _add(facts, Fact("web.tech", f"host:{ws.target}", {"items": tech[:20], "tool": "nmap"}, ProofState.SUPPORTED, source))

    if _NMAP_FTP_ANON_RE.search(text):
        _add(facts, Fact("ftp.reachable", f"host:{ws.target}", {"tool": "nmap"}, ProofState.SUPPORTED, source))
        _add(facts, Fact("ftp.anonymous_login", f"host:{ws.target}", {"tool": "nmap"}, ProofState.SUPPORTED, source))

    if "ssh-hostkey" in text.lower():
        keys = []
        for match in _NMAP_SSH_HOSTKEY_RE.finditer(text):
            keys.append({
                "bits": int(match.group("bits")),
                "fingerprint": match.group("fingerprint"),
                "type": match.group("kind").strip(),
            })
        if keys:
            _add(facts, Fact("ssh.reachable", f"host:{ws.target}", {"tool": "nmap"}, ProofState.SUPPORTED, source))
            _add(facts, Fact("ssh.hostkey", f"host:{ws.target}", {"keys": keys[:10], "count": len(keys)}, ProofState.SUPPORTED, source))

    snmp_values: dict[str, str] = {}
    if "snmp-info" in text.lower():
        for match in _NMAP_SNMP_FIELD_RE.finditer(text):
            key = match.group("key").lower()
            snmp_values[key] = match.group("value").strip()
    if snmp_values:
        _add(facts, Fact("snmp.reachable", f"host:{ws.target}", {"tool": "nmap"}, ProofState.SUPPORTED, source))
        _add(facts, Fact("snmp.info", f"host:{ws.target}", snmp_values, ProofState.SUPPORTED, source))
        if snmp_values.get("name"):
            _add(facts, Fact("host.hostname", f"host:{ws.target}", {"name": snmp_values["name"]}, ProofState.SUPPORTED, source))

    return context


def _normalize_service(service: str) -> str:
    cleaned = re.sub(r"[^a-z0-9_.-]+", "-", service.lower()).strip("-")
    aliases = {
        "microsoft-ds": "smb",
        "netbios-ssn": "smb",
        "domain": "dns",
        "ms-wbt-server": "rdp",
        "ssl-http": "https",
    }
    return aliases.get(cleaned, cleaned or "unknown")


def _parse_service_reachability(port: int, proto: str, service: str, ws: Workspace, source: str, facts: list[Fact]) -> None:
    service_l = service.lower()
    value = {"port": port, "protocol": proto}
    if service:
        value["service"] = service

    if port == 53 or service_l in {"domain", "dns"}:
        _add(facts, Fact("dns.reachable", f"host:{ws.target}", value, ProofState.SUPPORTED, source))
    if port == 161 or "snmp" in service_l:
        _add(facts, Fact("snmp.reachable", f"host:{ws.target}", value, ProofState.SUPPORTED, source))

    if proto != "tcp":
        return
    if port == 21 or service_l == "ftp":
        _add(facts, Fact("ftp.reachable", f"host:{ws.target}", value, ProofState.SUPPORTED, source))
    if port == 22 or service_l == "ssh":
        _add(facts, Fact("ssh.reachable", f"host:{ws.target}", value, ProofState.SUPPORTED, source))
    if port in {389, 636, 3268, 3269} or "ldap" in service_l:
        _add(facts, Fact("ldap.reachable", f"host:{ws.target}", value, ProofState.SUPPORTED, source))
    if port in {445, 139} or service_l in {"microsoft-ds", "netbios-ssn"}:
        _add(facts, Fact("smb.reachable", f"host:{ws.target}", value, ProofState.SUPPORTED, source))
    if port == 88 or "kerberos" in service_l:
        _add(facts, Fact("kerberos.reachable", f"host:{ws.target}", value, ProofState.SUPPORTED, source))
    if port == 3389 or service_l == "ms-wbt-server" or "rdp" in service_l:
        _add(facts, Fact("rdp.reachable", f"host:{ws.target}", value, ProofState.SUPPORTED, source))
        _add_os_observation(
            facts, ws, source,
            family="windows",
            evidence=f"{port}/{proto} {service or 'rdp'}",
            confidence="medium",
            tool="nmap",
            promote=False,
        )
    if port in {5985, 5986} or "wsman" in service_l or "winrm" in service_l:
        _add(facts, Fact("winrm.reachable", f"host:{ws.target}", value, ProofState.SUPPORTED, source))
        _add_os_observation(
            facts, ws, source,
            family="windows",
            evidence=f"{port}/{proto} {service or 'winrm'}",
            confidence="high",
            tool="nmap",
            promote=True,
        )
    if port in {80, 443, 8080, 8000, 8443} or service_l in {"http", "https", "ssl/http"}:
        _add(facts, Fact("http.reachable", f"host:{ws.target}", value, ProofState.SUPPORTED, source))


def _looks_like_ad_ldap(text: str) -> bool:
    return bool(re.search(r"Active Directory|Domain Controller|Global Catalog|ldap-rootdse", text, re.IGNORECASE))


# --------------------------------------------------------------------------- #
# NetExec / LDAP / SMB enumeration
# --------------------------------------------------------------------------- #
def _parse_nxc_common(text: str, ws: Workspace, source: str, facts: list[Fact]) -> None:
    _add_os_from_text(text, ws, source, facts, tool="nxc", confidence="high", promote=True)
    domain = ""
    domain_match = _DOMAIN_RE.search(text)
    if domain_match:
        domain = domain_match.group(1).strip()
        if domain and domain not in {"None", "-"}:
            _add(facts, Fact("ad.domain_known", f"domain:{domain}", {"name": domain}, ProofState.SUPPORTED, source))
            _add(facts, Fact("ad.base_dn", f"domain:{domain}", {"base_dn": _base_dn_from_domain(domain)}, ProofState.SUPPORTED, source))
            _add(facts, Fact("host.domain", f"host:{ws.target}", {"domain": domain}, ProofState.SUPPORTED, source))

    name_match = _NAME_RE.search(text)
    if name_match:
        _add(facts, Fact("host.hostname", f"host:{ws.target}", {"name": name_match.group(1).strip()}, ProofState.SUPPORTED, source))
    if name_match or domain:
        value = {"host": ws.target}
        if name_match:
            value["name"] = name_match.group(1).strip()
        if domain:
            value["domain"] = domain
        _add(facts, Fact("ad.dc_candidate", f"host:{ws.target}", value, ProofState.SUPPORTED, source))

    signing = _NXC_SIGNING_RE.search(text)
    if signing:
        _add(
            facts,
            Fact(
                "smb.signing",
                f"host:{ws.target}",
                {"enabled": signing.group("enabled").lower() == "true", "tool": "nxc"},
                ProofState.SUPPORTED,
                source,
            ),
        )
    smbv1 = _NXC_SMBV1_RE.search(text)
    if smbv1:
        _add(
            facts,
            Fact(
                "smb.smbv1",
                f"host:{ws.target}",
                {"enabled": smbv1.group("enabled").lower() == "true", "tool": "nxc"},
                ProofState.SUPPORTED,
                source,
            ),
        )

    for match in _NXC_PROTO_REACHABLE_RE.finditer(text):
        proto = match.group("proto").lower()
        if proto in {"ldap", "smb", "winrm", "rdp", "ssh", "ftp"}:
            _add(facts, Fact(f"{proto}.reachable", f"host:{ws.target}", {"tool": "nxc"}, ProofState.SUPPORTED, source))
        if proto in {"winrm", "rdp"}:
            _add_os_observation(
                facts, ws, source,
                family="windows",
                evidence=match.group(0).strip(),
                confidence="high" if proto == "winrm" else "medium",
                tool="nxc",
                promote=(proto == "winrm"),
            )

    if re.search(r"^LDAP\s+.*\[\+\].*(?:\\\\:|anonymous|guest|'')", text, re.IGNORECASE | re.MULTILINE):
        _add(facts, Fact("ad.anonymous_bind", _scope_for_domain(ws, domain), {"tool": "nxc"}, ProofState.SUPPORTED, source))


def _parse_nxc_smb_session(text: str, ws: Workspace, command: str, source: str, facts: list[Fact]) -> None:
    anonymous_command = "-u ''" in command or '-u ""' in command
    guest_command = re.search(r"\s-u\s+guest\b", command, re.IGNORECASE) is not None
    for line in text.splitlines():
        if not re.match(r"^\s*SMB\s+", line, re.IGNORECASE) or "[+]" not in line:
            continue
        auth = line.split("[+]", 1)[1].strip()
        auth_l = auth.lower()
        if guest_command or "guest" in auth_l:
            _add(facts, Fact("smb.guest_session", f"host:{ws.target}", {"tool": "nxc"}, ProofState.SUPPORTED, source))
        if anonymous_command or re.search(r"(?:^|\\):(?:\s|$)", auth) or auth in {":", "\\:", ""}:
            _add(facts, Fact("smb.null_session", f"host:{ws.target}", {"tool": "nxc"}, ProofState.SUPPORTED, source))


def _parse_user_list(
    text: str,
    ws: Workspace,
    source: str,
    facts: list[Fact],
    *,
    prove_anonymous_ldap: bool = False,
    domain_hint: str = "",
) -> None:
    users = _usernames(text)
    if not users:
        return
    domain = domain_hint or _domain_from_facts(ws)
    _add(facts, Fact("ad.user_list", _scope_for_domain(ws, domain), {"users": users, "count": len(users)}, ProofState.SUPPORTED, source))
    if prove_anonymous_ldap:
        _add(facts, Fact("ad.anonymous_bind", _scope_for_domain(ws, domain), {"tool": "nxc"}, ProofState.SUPPORTED, source))


def _parse_rid_user_list(text: str, ws: Workspace, source: str, facts: list[Fact], *, domain_hint: str = "") -> None:
    users = _rid_usernames(text)
    if not users:
        return
    domain = domain_hint or _domain_from_facts(ws)
    _add(
        facts,
        Fact(
            "ad.user_list",
            _scope_for_domain(ws, domain),
            {"users": users, "count": len(users), "method": "smb-rid"},
            ProofState.SUPPORTED,
            source,
        ),
    )


def _parse_ldapsearch(text: str, ws: Workspace, source: str, facts: list[Fact]) -> None:
    dns = sorted(set(_BASE_DN_RE.findall(text)), key=str.lower)
    for base_dn in dns:
        domain = ".".join(part.split("=", 1)[1] for part in base_dn.split(",") if part.upper().startswith("DC="))
        scope = f"domain:{domain}" if domain else _scope_for_domain(ws)
        value = {"base_dn": base_dn}
        if domain:
            value["domain"] = domain
            _add(facts, Fact("ad.domain_known", f"domain:{domain}", {"name": domain}, ProofState.SUPPORTED, source))
            _add(facts, Fact("host.domain", f"host:{ws.target}", {"domain": domain}, ProofState.SUPPORTED, source))
        _add(facts, Fact("ad.base_dn", scope, value, ProofState.SUPPORTED, source))
        _add(facts, Fact("ldap.reachable", f"host:{ws.target}", {"tool": "ldapsearch"}, ProofState.SUPPORTED, source))


def _parse_smb_shares(text: str, ws: Workspace, source: str, facts: list[Fact]) -> None:
    shares: list[dict] = []
    seen: set[tuple[str, str, str]] = set()

    def add_share(name: str, permission: str = "", share_type: str = "", readable: bool | None = None) -> None:
        name = name.strip()
        if not name or name.lower() in _SHARE_HEADER_WORDS or name.startswith("["):
            return
        if not re.fullmatch(r"[A-Za-z0-9_$.-]{2,}", name):
            return
        key = (name.upper(), permission.upper(), share_type.upper())
        if key in seen:
            return
        seen.add(key)
        row = {"name": name}
        if permission:
            row["permission"] = permission
        if share_type:
            row["type"] = share_type
        if readable is not None:
            row["readable"] = readable
        shares.append(row)

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if re.match(r"^SMB\s+", line, re.IGNORECASE):
            parts = line.split()
            if len(parts) < 6:
                continue
            share = parts[4]
            perm = parts[5].upper()
            if perm == "NO" and len(parts) > 6 and parts[6].upper() == "ACCESS":
                perm = "NO ACCESS"
            if perm not in _SHARE_PERMISSION_WORDS:
                continue
            add_share(share, permission=perm, readable=("READ" in perm or "WRITE" in perm))
            continue

        parts = line.split()
        if len(parts) >= 2 and parts[1] in {"Disk", "IPC", "Printer"}:
            add_share(parts[0], share_type=parts[1])

    if shares:
        _add(facts, Fact("smb.shares", f"host:{ws.target}", {"shares": shares, "count": len(shares)}, ProofState.SUPPORTED, source))
        readable_domain_shares = sorted(
            share["name"]
            for share in shares
            if share.get("name", "").upper() in {"SYSVOL", "NETLOGON"} and share.get("readable") is True
        )
        if readable_domain_shares:
            _add(
                facts,
                Fact(
                    "config.review",
                    f"host:{ws.target}",
                    {"kind": "readable_domain_shares", "shares": readable_domain_shares},
                    ProofState.SUPPORTED,
                    source,
                ),
            )


def _parse_gpp_artifacts(text: str, ws: Workspace, source: str, facts: list[Fact]) -> None:
    files = sorted(set(_GPP_FILE_RE.findall(text)), key=str.lower)
    if files:
        _add(facts, Fact("config.review", f"host:{ws.target}", {"kind": "gpp_xml", "files": files}, ProofState.SUPPORTED, source))
    cpasswords = sorted(set(_CPASSWORD_RE.findall(text)))
    if cpasswords:
        _add(
            facts,
            Fact(
                "credential.candidate",
                f"host:{ws.target}",
                {"kind": "gpp_cpassword", "count": len(cpasswords), "values": cpasswords},
                ProofState.SUPPORTED,
                source,
            ),
        )


# --------------------------------------------------------------------------- #
# Hashes / cracking
# --------------------------------------------------------------------------- #
def _parse_hash_user(hash_text: str) -> tuple[str, str, str]:
    asrep = _ASREP_USER_RE.search(hash_text)
    if asrep:
        user = _clean_username(asrep.group(1))
        domain = (asrep.group(2) or "").lower()
        return user, domain, "asrep"

    tgs = _TGS_USER_RE.search(hash_text)
    if tgs:
        user = _clean_username(tgs.group(1))
        return user, "", "tgs"

    return "", "", ""


def _add_plaintext_credential(
    facts: list[Fact],
    ws: Workspace,
    source: str,
    *,
    user: str,
    password: str,
    domain: str = "",
    method: str,
    hash_type: str = "",
) -> None:
    user = _clean_username(user)
    password = password.strip()
    if not _valid_username(user, allow_machine=False) or not _valid_password(password):
        return

    domain_name = domain or _domain_from_facts(ws)
    value = {"user": user, "password": password, "method": method}
    if domain_name:
        value["domain"] = domain_name
    if hash_type:
        value["hash_type"] = hash_type

    scope = _scope_for_domain(ws, domain_name)
    _add(facts, Fact("credential.plaintext", scope, value, ProofState.SUPPORTED, source))
    _add(facts, Fact("credential.available", scope, value, ProofState.SUPPORTED, source))


def _parse_cracked_credentials(text: str, ws: Workspace, command: str, source: str, facts: list[Fact]) -> None:
    """Parse crack output into plaintext credentials, not access or privilege.

    Supported inputs are intentionally narrow:
    - hashcat --show style krb5asrep/krb5tgs lines ending in :password
    - john --show style user:password lines
    """
    lowered_command = command.lower()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        if line.lower().startswith(_JOHN_NOISE_PREFIXES):
            continue

        if "$krb5asrep$" in line.lower() or "$krb5tgs$" in line.lower():
            hash_text, sep, password = line.rpartition(":")
            if not sep:
                continue
            user, domain, hash_type = _parse_hash_user(hash_text)
            _add_plaintext_credential(
                facts,
                ws,
                source,
                user=user,
                password=password,
                domain=domain,
                method="hashcat" if "hashcat" in lowered_command else "john",
                hash_type=hash_type,
            )
            continue

        if "john" not in lowered_command:
            continue
        if "--show" not in lowered_command and "password hash" not in text.lower():
            continue

        match = _JOHN_SHOW_RE.match(line)
        if not match:
            continue
        _add_plaintext_credential(
            facts,
            ws,
            source,
            user=match.group("user"),
            password=match.group("password"),
            method="john",
        )


def _parse_asrep_hashes(text: str, ws: Workspace, source: str, facts: list[Fact]) -> None:
    hashes = sorted(set(_ASREP_RE.findall(text)))
    if not hashes:
        return
    _add(facts, Fact("hash.asrep", _scope_for_domain(ws), {"hashes": hashes, "count": len(hashes)}, ProofState.SUPPORTED, source))
    _add(facts, Fact("credential.candidate", _scope_for_domain(ws), {"kind": "asrep_hash", "count": len(hashes)}, ProofState.SUPPORTED, source))


def _parse_tgs_hashes(text: str, ws: Workspace, source: str, facts: list[Fact]) -> None:
    hashes = sorted(set(_TGS_RE.findall(text)))
    if not hashes:
        return
    _add(facts, Fact("hash.tgs", _scope_for_domain(ws), {"hashes": hashes, "count": len(hashes)}, ProofState.SUPPORTED, source))
    _add(facts, Fact("credential.candidate", _scope_for_domain(ws), {"kind": "tgs_hash", "count": len(hashes)}, ProofState.SUPPORTED, source))


def _parse_ntlm_dump(text: str, ws: Workspace, command: str, source: str, facts: list[Fact]) -> None:
    """Parse SAM/LSA/NTDS dump output into crackable NTLM material, not access.

    Handles both raw impacket-secretsdump lines and NetExec-prefixed dump lines
    (`SMB  host  445  DC  DOMAIN\\user:RID:LM:NT:::`). A dumped NTLM hash is
    pass-the-hash/crackable material — it never proves plaintext credentials or
    that the operator has used it for access. A domain (NTDS) dump additionally
    records `loot.ntds`; the krbtgt hash is called out for golden-ticket gating.
    """
    entries: list[dict] = []
    seen: set[tuple[str, str]] = set()
    krbtgt_nt = ""
    for match in _NTDS_HASH_RE.finditer(text):
        user = _clean_username(match.group("user"))
        if not user:
            continue
        nt = match.group("nt").lower()
        key = (user.lower(), nt)
        if key in seen:
            continue
        seen.add(key)
        entries.append({"user": user, "rid": int(match.group("rid")), "nthash": nt})
        if user.lower() == "krbtgt":
            krbtgt_nt = nt
    if not entries:
        return

    lowered = text.lower()
    lowered_command = command.lower()
    ntds_context = (
        bool(krbtgt_nt)
        or "--ntds" in lowered_command
        or "-just-dc" in lowered_command
        or any(marker in lowered for marker in ("ntds.dit", "drsuapi", "dumping domain credentials"))
    )

    scope = _scope_for_domain(ws)
    _add(facts, Fact("hash.ntlm", scope, {"count": len(entries), "entries": entries}, ProofState.SUPPORTED, source))
    _add(facts, Fact("credential.candidate", scope, {"kind": "ntlm_hash", "count": len(entries)}, ProofState.SUPPORTED, source))
    if krbtgt_nt:
        _add(facts, Fact("hash.krbtgt", scope, {"nthash": krbtgt_nt}, ProofState.SUPPORTED, source))
    if ntds_context:
        _add(facts, Fact("loot.ntds", scope, {"count": len(entries), "method": "credential-dump"}, ProofState.SUPPORTED, source))


# --------------------------------------------------------------------------- #
# Post-credential AD path: auth validation, footholds, BloodHound
# --------------------------------------------------------------------------- #
def _nt_hash(secret: str) -> str:
    """The NT hash if `secret` is an NT hash or LM:NT pair, else "" (a plaintext
    password). The LM half is discarded — only the NT hash is pass-the-hash material."""
    secret = secret.strip()
    if not _NT_HASH_RE.match(secret):
        return ""
    return secret.rsplit(":", 1)[-1].lower()


def _parse_auth_material(auth: str) -> tuple[str, str, str]:
    auth = re.sub(r"\s+\([^)]*\)\s*$", "", auth.strip())
    match = _AUTH_MATERIAL_RE.match(auth)
    if not match:
        return "", "", ""
    domain = (match.group("domain") or "").strip()
    user = _clean_username(match.group("user"))
    secret = match.group("secret").strip()
    return domain, user, secret


def _add_authenticated_service(
    facts: list[Fact],
    ws: Workspace,
    source: str,
    *,
    proto: str,
    user: str,
    secret: str,
    domain: str = "",
    admin: bool = False,
) -> None:
    """Record a validated credential + service auth from `user:secret`. `secret` is
    an NT hash (pass-the-hash) or a plaintext password — recorded as the narrowest
    truth for each, never a hash mislabeled as a password."""
    user = _clean_username(user)
    if not _valid_username(user, allow_machine=False):
        return
    nthash = _nt_hash(secret)
    if not nthash and not _valid_password(secret):
        return
    domain_name = domain or _domain_from_facts(ws)
    value = {"user": user, "service": proto, "method": "pth" if nthash else "nxc"}
    if nthash:
        value["nthash"] = nthash
    else:
        value["password"] = secret
    if domain_name:
        value["domain"] = domain_name
    _add(facts, Fact("credential.available", _scope_for_domain(ws, domain_name), value, ProofState.SUPPORTED, source))
    _add(facts, Fact(f"{proto}.authenticated", f"host:{ws.target}", value, ProofState.SUPPORTED, source))
    if proto == "winrm":
        _add(facts, Fact("winrm.reachable", f"host:{ws.target}", {"tool": "nxc"}, ProofState.SUPPORTED, source))
        _add(facts, Fact("foothold.windows", f"host:{ws.target}", value, ProofState.SUPPORTED, source))
    if admin:
        _add(facts, Fact("access.admin", f"host:{ws.target}", value, ProofState.SUPPORTED, source))


def _parse_nxc_auth_validation(text: str, ws: Workspace, source: str, facts: list[Fact]) -> None:
    for match in _NXC_AUTH_RE.finditer(text):
        proto = match.group("proto").lower()
        auth = match.group("auth").strip()
        domain, user, secret = _parse_auth_material(auth)
        if not user or not secret:
            continue
        _add_authenticated_service(
            facts,
            ws,
            source,
            proto=proto,
            user=user,
            secret=secret,
            domain=domain,
            admin="pwn3d" in auth.lower(),
        )


def _parse_auth_failures(text: str, ws: Workspace, source: str, facts: list[Fact]) -> None:
    lowered = text.lower()
    for marker, reason in _FAILURE_REASONS.items():
        if marker in lowered:
            _add(facts, Fact("credential.validation", f"host:{ws.target}", {"reason": reason}, ProofState.REFUTED, source))


def _parse_evil_winrm(text: str, ws: Workspace, command: str, source: str, facts: list[Fact]) -> None:
    if not (_EW_PROMPT_RE.search(text) or "evil-winrm shell" in text.lower() or "establishing connection to remote endpoint" in text.lower()):
        return
    user = _command_arg(command, "-u", "--user", "--username")
    password = _command_arg(command, "-p", "--password")
    nthash = _nt_hash(_command_arg(command, "-H", "--hash"))
    domain = _command_arg(command, "-r", "--realm", "-d", "--domain")
    value = {"service": "winrm", "tool": "evil-winrm"}
    if user:
        value["user"] = _clean_username(user)
    if nthash:
        value["nthash"] = nthash
    elif password:
        value["password"] = password
    if domain:
        value["domain"] = domain
    _add(facts, Fact("winrm.authenticated", f"host:{ws.target}", value, ProofState.SUPPORTED, source))
    _add(facts, Fact("foothold.windows", f"host:{ws.target}", value, ProofState.SUPPORTED, source))
    _add_os_observation(
        facts, ws, source,
        family="windows",
        evidence="evil-winrm authenticated shell",
        confidence="high",
        tool="evil-winrm",
        promote=True,
    )
    if user and (nthash or (password and _valid_password(password))):
        cred_value = {"user": _clean_username(user), "service": "winrm",
                      "method": "pth" if nthash else "evil-winrm"}
        if nthash:
            cred_value["nthash"] = nthash
        else:
            cred_value["password"] = password
        if domain:
            cred_value["domain"] = domain
        _add(facts, Fact("credential.available", _scope_for_domain(ws, domain), cred_value, ProofState.SUPPORTED, source))


def _parse_bloodhound_collection(text: str, ws: Workspace, source: str, facts: list[Fact]) -> None:
    lowered = text.lower()
    zips = sorted(set(_BH_ZIP_RE.findall(text)), key=str.lower)
    jsons = sorted(set(_BH_JSON_RE.findall(text)), key=str.lower)
    collected = bool(zips or jsons) and (
        "bloodhound" in lowered
        or "sharphound" in lowered
        or "compressing" in lowered
        or "collection" in lowered
        or "saved" in lowered
    )
    if not collected:
        return
    value: dict = {"tool": "bloodhound"}
    if zips:
        value["archives"] = zips
    if jsons:
        value["files"] = jsons
    _add(facts, Fact("ad.graph.collected", _scope_for_domain(ws), value, ProofState.SUPPORTED, source))


def _parse_bloodhound_analysis(text: str, ws: Workspace, source: str, facts: list[Fact]) -> None:
    if not _ATTACK_PATH_RE.search(text):
        return
    _add(facts, Fact("ad.attack_paths", _scope_for_domain(ws), {"tool": "bloodhound", "evidence": "analysis_output"}, ProofState.SUPPORTED, source))


def _exec_tool(command: str) -> str:
    lowered = command.lower()
    for tool in ("evil-winrm", "wmiexec", "psexec", "atexec", "smbexec"):
        if tool in lowered:
            return tool
    if "enter-pssession" in lowered:
        return "winrs"
    if "nxc " in lowered or lowered.startswith("nxc "):
        return "nxc"
    return "exec"


def _parse_command_execution(text: str, ws: Workspace, command: str, source: str, facts: list[Fact]) -> None:
    """Prove code execution and SYSTEM from command-execution output.

    Triggered only for execution commands (nxc -x/-X, impacket psexec/wmiexec,
    evil-winrm, Enter-PSSession). Returned `whoami`/command output showing
    `nt authority\\system` proves `access.system`; any confirmed command
    execution proves a Windows foothold. A normal-user shell proves the
    foothold only — never admin or SYSTEM on its own.
    """
    identities = [_normalize_identity(match.group("id")) for match in _WHOAMI_ID_RE.finditer(text)]
    identities = [ident for ident in identities if ident]
    is_system = bool(_SYSTEM_ID_RE.search(text))
    interactive = bool(_INTERACTIVE_RE.search(text)) or "enter-pssession" in command.lower()
    executed = bool(identities) or bool(_EXEC_SUCCESS_RE.search(text)) or interactive
    if not executed:
        return

    tool = _exec_tool(command)
    foothold_value = {"method": tool}
    non_system = [ident for ident in identities if ident.lower() != "nt authority\\system"]
    if non_system:
        foothold_value["identity"] = non_system[0]
        facts[:] = [
            fact for fact in facts
            if not (
                fact.kind == "foothold.windows"
                and fact.scope == f"host:{ws.target}"
                and "identity" not in fact.value
            )
        ]
    _add(facts, Fact("foothold.windows", f"host:{ws.target}", foothold_value, ProofState.SUPPORTED, source))
    _add_os_observation(
        facts, ws, source,
        family="windows",
        evidence="Windows command execution output",
        confidence="high",
        tool=tool,
        promote=True,
    )

    if is_system:
        _add(
            facts,
            Fact(
                "access.system",
                f"host:{ws.target}",
                {"identity": "nt authority\\system", "method": tool},
                ProofState.SUPPORTED,
                source,
            ),
        )

    # An interactive Windows session (not a one-shot nxc -x command) is a shell
    # the operator can run on-host enumeration from -> access.desktop.
    if interactive and tool in _INTERACTIVE_WIN_TOOLS:
        _add(facts, Fact("access.desktop", f"host:{ws.target}", {"session": tool}, ProofState.SUPPORTED, source))


def _parse_ssh_exec(text: str, ws: Workspace, command: str, source: str, facts: list[Fact]) -> None:
    """Prove a Linux shell from `id`/`uid=` output over ssh.

    `uid=1000(bob) gid=…` proves an interactive shell as that user
    (`access.shell` + `foothold.linux`); `uid=0(root)` is privileged
    (`access.admin`). Nothing is claimed without a real `uid=` line — a failed
    login prints none.
    """
    m = _LINUX_ID_RE.search(text)
    if not m:
        return
    user = m.group("user").strip()
    _add(facts, Fact("access.shell", f"host:{ws.target}", {"service": "ssh"}, ProofState.SUPPORTED, source))
    _add(facts, Fact("foothold.linux", f"host:{ws.target}",
                     {"service": "ssh", "identity": user}, ProofState.SUPPORTED, source))
    _add_os_observation(
        facts, ws, source,
        family="linux",
        evidence=m.group(0),
        confidence="high",
        tool="ssh",
        promote=True,
    )
    if m.group("uid") == "0" or user.lower() == "root":
        _add(facts, Fact("access.admin", f"host:{ws.target}",
                         {"service": "ssh", "identity": user}, ProofState.SUPPORTED, source))


def _parse_nxc_rdp(text: str, ws: Workspace, command: str, source: str, facts: list[Fact]) -> None:
    """Prove RDP access from a `nxc rdp` success line.

    A `[+] domain\\user:pass` line proves the credential authenticates over RDP — an
    interactive Windows foothold (a desktop the operator can log into). `(Pwn3d!)`
    additionally proves administrative access. A failed auth prints no `[+]`.
    """
    if "[+]" not in text:
        return
    user = _command_arg(command, "-u", "--user", "--username")
    value = {"service": "rdp"}
    if user:
        value["user"] = _clean_username(user)
    _add(facts, Fact("rdp.authenticated", f"host:{ws.target}", value, ProofState.SUPPORTED, source))
    foothold = {"method": "rdp"}
    if user:
        foothold["identity"] = _clean_username(user)
    _add(facts, Fact("foothold.windows", f"host:{ws.target}", foothold, ProofState.SUPPORTED, source))
    _add_os_observation(
        facts, ws, source,
        family="windows",
        evidence="nxc rdp authentication succeeded",
        confidence="high",
        tool="nxc",
        promote=True,
    )
    if "pwn3d" in text.lower():
        _add(facts, Fact("access.admin", f"host:{ws.target}",
                         {"service": "rdp"}, ProofState.SUPPORTED, source))


def _parse_penelope(text: str, ws: Workspace, source: str, facts: list[Fact]) -> None:
    """Parse penelope (reverse-shell handler) output into an interactive shell.

    A caught shell is a real interactive session (access.shell); when penelope
    reports the OS it also lands the OS-specific foothold, and a Windows shell
    is a session the operator can run on-host enumeration from (access.desktop).
    SYSTEM is not claimed here — that comes from actual `whoami` output via the
    command-execution parser.
    """
    got = _PENELOPE_GOT_RE.search(text)
    upgraded = bool(_PENELOPE_UPGRADE_RE.search(text))
    if not got and not upgraded:
        return

    info = got.group("info").strip() if got else ""
    haystack = f"{info}\n{text}".lower()
    os_name = "windows" if "windows" in haystack else ("linux" if "linux" in haystack else "")

    value: dict = {"handler": "penelope"}
    if os_name:
        value["os"] = os_name
    sid = _PENELOPE_SID_RE.search(text)
    if sid:
        value["session_id"] = sid.group("sid")
    host = _PENELOPE_HOST_RE.search(info)
    if host:
        value["hostname"] = host.group("host")
        value["source_ip"] = host.group("ip")

    _add(facts, Fact("access.shell", f"host:{ws.target}", value, ProofState.SUPPORTED, source))
    if os_name == "windows":
        _add_os_observation(
            facts, ws, source,
            family="windows",
            evidence=info or "penelope reported Windows shell",
            confidence="high",
            tool="penelope",
            promote=True,
        )
        _add(facts, Fact("foothold.windows", f"host:{ws.target}", {"method": "penelope"}, ProofState.SUPPORTED, source))
        _add(facts, Fact("access.desktop", f"host:{ws.target}", {"session": "penelope"}, ProofState.SUPPORTED, source))
    elif os_name == "linux":
        _add_os_observation(
            facts, ws, source,
            family="linux",
            evidence=info or "penelope reported Linux shell",
            confidence="high",
            tool="penelope",
            promote=True,
        )
        _add(facts, Fact("foothold.linux", f"host:{ws.target}", {"method": "penelope"}, ProofState.SUPPORTED, source))


def _add_host_privesc_fact(
    facts: list[Fact],
    ws: Workspace,
    source: str,
    kind: str,
    value: dict,
    lead_kinds: set[str],
) -> None:
    _add(facts, Fact(kind, f"host:{ws.target}", value, ProofState.SUPPORTED, source))
    if kind.startswith("privesc.") and kind != "privesc.leads":
        lead_kinds.add(kind)


def _add_privesc_leads(facts: list[Fact], ws: Workspace, source: str, lead_kinds: set[str]) -> None:
    if not lead_kinds:
        return
    _add(
        facts,
        Fact(
            "privesc.leads",
            f"host:{ws.target}",
            {"kinds": sorted(lead_kinds), "count": len(lead_kinds)},
            ProofState.SUPPORTED,
            source,
        ),
    )


def _parse_linux_privesc_output(
    text: str,
    ws: Workspace,
    command: str,
    source: str,
    facts: list[Fact],
    lead_kinds: set[str],
) -> None:
    lowered = text.lower()
    lowered_command = command.lower()
    id_match = _LINUX_ID_RE.search(text)
    if id_match:
        user = id_match.group("user").strip()
        _add_os_observation(
            facts, ws, source,
            family="linux",
            evidence=id_match.group(0),
            confidence="high",
            tool="local-enum",
            promote=True,
        )
        id_line = _line_for_match(text, id_match) or id_match.group(0)
        groups = sorted({match.group(1).lower() for match in re.finditer(r"\d+\(([^)]+)\)", id_line)})
        if {"lxd", "lxc"} & set(groups):
            _add_host_privesc_fact(facts, ws, source, "privesc.lxd_group", {"groups": groups, "user": user}, lead_kinds)
        if "docker" in groups:
            _add_host_privesc_fact(facts, ws, source, "privesc.docker_group", {"groups": groups, "user": user}, lead_kinds)
        if id_match.group("uid") == "0" or user.lower() == "root":
            _add(facts, Fact("access.admin", f"host:{ws.target}", {"identity": user, "method": "local-enum"}, ProofState.SUPPORTED, source))
    elif "whoami" in lowered_command and re.search(r"(?im)^\s*root\s*$", text):
        _add(facts, Fact("access.admin", f"host:{ws.target}", {"identity": "root", "method": "whoami"}, ProofState.SUPPORTED, source))

    uname = _UNAME_RE.search(text)
    if uname:
        _add_host_privesc_fact(
            facts, ws, source,
            "host.kernel",
            {"kernel": uname.group("kernel"), "tool": "uname", "evidence": uname.group(0).strip()[:220]},
            lead_kinds,
        )
        _add_host_privesc_fact(facts, ws, source, "host.arch", {"arch": uname.group("arch"), "tool": "uname"}, lead_kinds)

    sudo_entries = []
    if "may run the following commands" in lowered or "nopasswd:" in lowered:
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.lower().startswith(("matching defaults", "user ", "sudoers")):
                continue
            if "nopasswd:" in line.lower() or re.search(r"\([^)]+\)\s+\S+", line):
                sudo_entries.append(line[:220])
    if sudo_entries:
        _add_host_privesc_fact(
            facts, ws, source,
            "privesc.sudo_rights",
            {"entries": sorted(set(sudo_entries))[:20], "nopasswd": any("nopasswd" in e.lower() for e in sudo_entries)},
            lead_kinds,
        )

    suid_paths: set[str] = set()
    if "-perm -4000" in lowered_command or "suid" in lowered or "rws" in lowered:
        for raw in text.splitlines():
            line = raw.strip()
            if not line or "/proc/" in line:
                continue
            if line.startswith("/") and " " not in line:
                suid_paths.add(line)
                continue
            if "rws" in line.lower():
                match = _SUID_PATH_RE.search(line)
                if match:
                    suid_paths.add(match.group("path"))
    if suid_paths:
        _add_host_privesc_fact(
            facts, ws, source,
            "privesc.suid_candidate",
            {"paths": sorted(suid_paths)[:40], "count": len(suid_paths)},
            lead_kinds,
        )

    caps = []
    for match in _CAPABILITY_RE.finditer(text):
        caps.append({"path": match.group("path"), "capabilities": match.group("caps").strip()})
    if caps:
        _add_host_privesc_fact(
            facts, ws, source,
            "privesc.capability",
            {"entries": caps[:40], "count": len(caps)},
            lead_kinds,
        )

    passwd = _PASSWD_MODE_RE.search(text)
    if passwd:
        mode = passwd.group("mode")
        group_writable = mode[5] == "w"
        world_writable = mode[8] == "w"
        if group_writable or world_writable:
            _add_host_privesc_fact(
                facts, ws, source,
                "privesc.passwd_writable",
                {"path": "/etc/passwd", "mode": mode, "world_writable": world_writable, "group_writable": group_writable},
                lead_kinds,
            )

    if "no_root_squash" in lowered:
        exports = [line.strip() for line in text.splitlines() if "no_root_squash" in line.lower()]
        _add_host_privesc_fact(
            facts, ws, source,
            "privesc.nfs_no_root_squash",
            {"exports": exports[:20], "count": len(exports) or 1},
            lead_kinds,
        )

    cron_lines = [
        line.strip() for line in text.splitlines()
        if re.search(r"cron|timer|systemd", line, re.IGNORECASE) and re.search(r"\b(writable|world-writable|rwx|777)\b", line, re.IGNORECASE)
    ]
    if cron_lines:
        _add_host_privesc_fact(facts, ws, source, "privesc.cron_writable", {"evidence": cron_lines[:20]}, lead_kinds)

    process_lines = [
        line.strip() for line in text.splitlines()
        if re.search(r"\bUID=0\b|\broot\b.*\bCMD\b|\bCMD:", line, re.IGNORECASE)
    ]
    if process_lines and ("pspy" in lowered_command or "uid=0" in lowered or "cmd:" in lowered):
        _add_host_privesc_fact(facts, ws, source, "privesc.process_lead", {"commands": process_lines[:30]}, lead_kinds)

    if re.search(r"password\s*[=:]\s*\S+|BEGIN OPENSSH|api[_-]?key|secret", text, re.IGNORECASE):
        _add(
            facts,
            Fact("credential.candidate", f"host:{ws.target}", {"kind": "local_file_secret", "evidence": "local loot output"}, ProofState.SUPPORTED, source),
        )


def _parse_windows_privesc_output(
    text: str,
    ws: Workspace,
    command: str,
    source: str,
    facts: list[Fact],
    lead_kinds: set[str],
) -> None:
    lowered = text.lower()
    if _SYSTEM_ID_RE.search(text):
        _add_os_observation(
            facts, ws, source,
            family="windows",
            evidence="Windows local command output",
            confidence="high",
            tool="local-enum",
            promote=True,
        )
        _add(facts, Fact("access.system", f"host:{ws.target}", {"identity": "nt authority\\system", "method": "local-enum"}, ProofState.SUPPORTED, source))

    sysinfo: dict[str, str] = {}
    for match in _SYSTEMINFO_FIELD_RE.finditer(text):
        sysinfo[match.group("key").lower()] = match.group("value").strip()
    if sysinfo:
        os_name = sysinfo.get("os name", "")
        os_version = sysinfo.get("os version", "")
        if os_name or os_version:
            _add_host_privesc_fact(
                facts, ws, source,
                "host.kernel",
                {"kernel": " ".join(part for part in (os_name, os_version) if part), "tool": "systeminfo"},
                lead_kinds,
            )
            _add_os_observation(
                facts, ws, source,
                family="windows",
                evidence=(os_name or os_version),
                confidence="high",
                tool="systeminfo",
                promote=True,
            )
        if sysinfo.get("system type"):
            _add_host_privesc_fact(facts, ws, source, "host.arch", {"arch": sysinfo["system type"], "tool": "systeminfo"}, lead_kinds)

    privileges = []
    for match in _WIN_PRIV_RE.finditer(text):
        name = match.group("name")
        state = match.group("state").lower()
        if state == "enabled" and name.lower() in _DANGEROUS_WIN_PRIVS:
            privileges.append(name)
    if privileges:
        _add_host_privesc_fact(
            facts, ws, source,
            "privesc.windows_privilege",
            {"privileges": sorted(set(privileges)), "state": "Enabled"},
            lead_kinds,
        )

    if "alwaysinstallelevated" in lowered and len(re.findall(r"0x1|\b0*1\b", lowered)) >= 2:
        _add_host_privesc_fact(
            facts, ws, source,
            "privesc.always_install_elevated",
            {"hklm": True, "hkcu": True},
            lead_kinds,
        )

    unquoted = []
    if ".exe" in lowered:
        for raw in text.splitlines():
            line = raw.strip()
            if not line or ".exe" not in line.lower() or '"' in line:
                continue
            if re.search(r"[A-Za-z]:\\Program Files[^,\r\n]+\.exe", line, re.IGNORECASE):
                unquoted.append(line[:220])
    if unquoted:
        _add_host_privesc_fact(
            facts, ws, source,
            "privesc.unquoted_service_path",
            {"services": sorted(set(unquoted))[:20], "count": len(set(unquoted))},
            lead_kinds,
        )

    weak_service = []
    for raw in text.splitlines():
        line = raw.strip()
        if re.search(r"SERVICE_CHANGE_CONFIG|\(F\)|\(M\)|BUILTIN\\Users:.*\([FM]\)", line, re.IGNORECASE):
            weak_service.append(line[:220])
    if weak_service:
        _add_host_privesc_fact(
            facts, ws, source,
            "privesc.weak_service_permission",
            {"evidence": sorted(set(weak_service))[:30]},
            lead_kinds,
        )

    stored = []
    for marker, label in (
        ("Target:", "cmdkey"),
        ("DefaultPassword", "autologon"),
        ("unattend.xml", "unattend"),
        ("sysprep", "sysprep"),
        ("confCons.xml", "mRemoteNG"),
        (".rdp", "rdp_file"),
    ):
        if marker.lower() in lowered:
            stored.append(label)
    if stored:
        _add_host_privesc_fact(
            facts, ws, source,
            "privesc.stored_credentials",
            {"kinds": sorted(set(stored)), "count": len(set(stored))},
            lead_kinds,
        )
        _add(facts, Fact("credential.candidate", f"host:{ws.target}", {"kind": "stored_windows_credentials"}, ProofState.SUPPORTED, source))

    patch_lines = [
        line.strip() for line in text.splitlines()
        if re.search(r"\bMS\d{2}-\d{3}\b|CVE-\d{4}-\d+|missing patches?|exploit", line, re.IGNORECASE)
    ]
    if patch_lines and ("wesng" in command.lower() or "windows-exploit-suggester" in command.lower() or "missing" in lowered):
        _add_host_privesc_fact(facts, ws, source, "privesc.patch_gap", {"evidence": patch_lines[:30]}, lead_kinds)
        _add(facts, Fact("exploit.candidate", f"host:{ws.target}", {"tool": "windows-exploit-suggester", "findings": patch_lines[:30]}, ProofState.SUPPORTED, source))


def _parse_privesc_output(action_id: str, text: str, ws: Workspace, command: str, source: str, facts: list[Fact]) -> None:
    if not text.strip():
        return
    lead_kinds: set[str] = set()
    if action_id in _LINUX_PRIVESC_ACTION_IDS:
        _parse_linux_privesc_output(text, ws, command, source, facts, lead_kinds)
    if action_id in _WINDOWS_PRIVESC_ACTION_IDS:
        _parse_windows_privesc_output(text, ws, command, source, facts, lead_kinds)
    _add_privesc_leads(facts, ws, source, lead_kinds)


def _parse_adcs(text: str, ws: Workspace, command: str, source: str, facts: list[Fact]) -> None:
    """Parse certipy/pywhisker output into ADCS findings and certificate material.

    A `certipy find` ESC finding proves a vulnerable template exists
    (enumeration/context). Obtaining a .pfx (certipy req, pywhisker) proves
    certificate material for a principal — auth material that still has to be
    used (PKINIT/UnPAC) to yield a ticket or hash. Neither proves access here.
    """
    lowered_command = command.lower()
    escs = sorted({int(match.group(1)) for match in _ESC_RE.finditer(text)})
    if escs and ("vulnerab" in text.lower() or "certipy" in lowered_command):
        value: dict = {"esc": [f"ESC{n}" for n in escs]}
        templates = sorted({match.group("name").strip() for match in _CERTIPY_TEMPLATE_RE.finditer(text)})
        if templates:
            value["templates"] = templates
        _add(facts, Fact("adcs.vulnerable", _scope_for_domain(ws), value, ProofState.SUPPORTED, source))

    pfxs = sorted({match.group("pfx") for match in _PFX_SAVED_RE.finditer(text)})
    if pfxs:
        value = {"files": pfxs}
        upn = _CERTIPY_UPN_RE.search(text)
        principal = ""
        if upn:
            principal = _clean_username(upn.group("upn"))
        if not principal:
            principal = _clean_username(_command_arg(command, "-upn", "--upn", "--target"))
        if not principal:
            principal = _clean_username(pfxs[0].replace("\\", "/").rsplit("/", 1)[-1].rsplit(".", 1)[0])
        if principal and _valid_username(principal):
            value["principal"] = principal
        _add(facts, Fact("credential.certificate", _scope_for_domain(ws), value, ProofState.SUPPORTED, source))


def _normalize_identity(identity: str) -> str:
    identity = identity.strip()
    if identity.lower() == "nt authority\\system":
        return "nt authority\\system"
    return identity


# --------------------------------------------------------------------------- #
# Generic service metadata: HTTP, SSH, FTP, SNMP
# --------------------------------------------------------------------------- #
def _parse_http_metadata(text: str, ws: Workspace, source: str, facts: list[Fact]) -> None:
    """HTTP metadata from curl/whatweb-style output.

    Headers, titles, redirects, and technology fingerprints are context for follow-up
    enum. They are not vulnerability, credential, or access facts.
    """
    _add_os_from_text(text, ws, source, facts, tool="http", confidence="medium", promote=False)
    status_values = []
    for match in _HTTP_STATUS_RE.finditer(text):
        value = {"status": int(match.group("status"))}
        reason = (match.group("reason") or "").strip()
        if reason:
            value["reason"] = reason
        status_values.append(value)
    if status_values:
        _add(facts, Fact("http.reachable", f"host:{ws.target}", {"tool": "http-client"}, ProofState.SUPPORTED, source))
        _add(facts, Fact("http.response", f"host:{ws.target}", {"responses": status_values[:10]}, ProofState.SUPPORTED, source))

    servers: set[str] = set()
    redirects: set[str] = set()
    content_types: set[str] = set()
    tech: list[dict] = []
    for match in _HTTP_HEADER_RE.finditer(text):
        key = match.group("key").lower()
        value = match.group("value").strip()
        if not value:
            continue
        if key == "server":
            servers.add(value)
        elif key == "x-powered-by":
            tech.append({"name": "x-powered-by", "value": value})
        elif key == "location":
            redirects.add(value)
        elif key == "content-type":
            content_types.add(value)

    for match in _WHATWEB_PLUGIN_RE.finditer(text):
        name = match.group("name").strip()
        value = match.group("value").strip()
        if name.lower() in {"title", "ip", "country", "email", "summary"}:
            continue
        if name.lower() in {"httpserver", "server"}:
            servers.add(value)
        else:
            tech.append({"name": name, "value": value})

    title_match = re.search(r"\bTitle\[(?P<title>[^\]\r\n]+)\]", text)
    if title_match and title_match.group("title").strip():
        _add(facts, Fact("web.title", f"host:{ws.target}", {"titles": [title_match.group("title").strip()]}, ProofState.SUPPORTED, source))
    if servers:
        _add(facts, Fact("web.server", f"host:{ws.target}", {"headers": sorted(servers)[:10]}, ProofState.SUPPORTED, source))
    if redirects:
        _add(facts, Fact("http.redirect", f"host:{ws.target}", {"locations": sorted(redirects)[:10]}, ProofState.SUPPORTED, source))
    if content_types:
        tech.extend({"name": "content-type", "value": item} for item in sorted(content_types))
    if tech:
        dedup: list[dict] = []
        seen: set[tuple[str, str]] = set()
        for item in tech:
            key = (item["name"].lower(), item["value"].lower())
            if key in seen:
                continue
            seen.add(key)
            dedup.append(item)
        _add(facts, Fact("web.tech", f"host:{ws.target}", {"items": dedup[:20]}, ProofState.SUPPORTED, source))


def _parse_ssh_banner(text: str, ws: Workspace, source: str, facts: list[Fact]) -> None:
    banners = sorted({match.group(0).strip() for match in _SSH_BANNER_RE.finditer(text)}, key=str.lower)
    if not banners:
        return
    _add_os_from_text("\n".join(banners), ws, source, facts, tool="ssh", confidence="medium", promote=False)
    _add(facts, Fact("ssh.reachable", f"host:{ws.target}", {"tool": "banner"}, ProofState.SUPPORTED, source))
    _add(facts, Fact("ssh.banner", f"host:{ws.target}", {"banners": banners[:10]}, ProofState.SUPPORTED, source))


def _parse_ftp_output(text: str, ws: Workspace, command: str, source: str, facts: list[Fact]) -> None:
    banners: list[str] = []
    login_success = False
    for match in _FTP_BANNER_RE.finditer(text):
        banner = (match.group("banner") or match.group("login") or "").strip()
        if banner:
            banners.append(banner)
        if match.group("login"):
            login_success = True
    if not banners and not login_success:
        return
    _add(facts, Fact("ftp.reachable", f"host:{ws.target}", {"tool": "ftp-client"}, ProofState.SUPPORTED, source))
    if banners:
        _add(facts, Fact("ftp.banner", f"host:{ws.target}", {"banners": sorted(set(banners))[:10]}, ProofState.SUPPORTED, source))
    if login_success and re.search(r"\banonymous\b", command, re.IGNORECASE):
        _add(facts, Fact("ftp.anonymous_login", f"host:{ws.target}", {"tool": "ftp-client"}, ProofState.SUPPORTED, source))


def _parse_snmp_output(text: str, ws: Workspace, command: str, source: str, facts: list[Fact]) -> None:
    lowered = text.lower()
    if any(marker in lowered for marker in ("timeout", "no response from", "authorizationerror", "authentication failure")):
        return
    if "snmpv2-mib::" not in lowered and not re.search(r"\[[^\]]+\]\s+\S", text):
        return

    value: dict = {}
    for key, regex in (
        ("description", _SNMP_SYSDESCR_RE),
        ("name", _SNMP_SYSNAME_RE),
        ("location", _SNMP_SYSLOCATION_RE),
        ("contact", _SNMP_SYSCONTACT_RE),
    ):
        match = regex.search(text)
        if match:
            value[key] = match.group("value").strip().strip('"')

    community = _command_arg(command, "-c", "--community")
    if not community:
        one = re.search(r"\[(?P<community>[^\]]+)\]\s+(?P<description>.+)", text)
        if one:
            community = one.group("community").strip()
            value.setdefault("description", one.group("description").strip())
    if community:
        _add(facts, Fact("snmp.community", f"host:{ws.target}", {"community": community}, ProofState.SUPPORTED, source))

    _add(facts, Fact("snmp.reachable", f"host:{ws.target}", {"tool": "snmp"}, ProofState.SUPPORTED, source))
    if value:
        _add(facts, Fact("snmp.info", f"host:{ws.target}", value, ProofState.SUPPORTED, source))
        _add_os_from_text(
            "\n".join(str(v) for v in value.values()),
            ws,
            source,
            facts,
            tool="snmp",
            confidence="high",
            promote=True,
        )
        if value.get("name"):
            _add(facts, Fact("host.hostname", f"host:{ws.target}", {"name": value["name"]}, ProofState.SUPPORTED, source))


# --------------------------------------------------------------------------- #
# Web recon: content discovery, virtual hosts, nikto
# --------------------------------------------------------------------------- #
def _parse_web_content(text: str, ws: Workspace, source: str, facts: list[Fact]) -> None:
    """Directory/content-discovery hits (gobuster/feroxbuster/ffuf/dirb) -> web.content_map.

    Discovered paths are attack surface, not a vulnerability or access. Only the
    hits the tool reports are recorded; 404s are ignored.
    """
    paths: set[str] = set()
    for match in _WEB_GOBUSTER_RE.finditer(text):
        if match.group("code") != "404":
            paths.add(match.group("path"))
    for match in _WEB_FEROX_RE.finditer(text):
        if match.group("code") != "404":
            paths.add(_url_path(match.group("url")))
    for match in _WEB_DIRB_RE.finditer(text):
        if match.group("code") != "404":
            paths.add(_url_path(match.group("url")))
    for match in _WEB_FFUF_RE.finditer(text):
        token = match.group("token")
        if match.group("code") == "404" or token.startswith(":") or token.lower() == "status":
            continue
        paths.add(token if token.startswith("/") else "/" + token)

    paths = {p for p in paths if p and not p.lower().startswith("http")}
    if not paths:
        return
    ordered = sorted(paths, key=str.lower)
    value: dict = {"paths": ordered[:50], "count": len(ordered)}
    interesting = [p for p in ordered if _WEB_INTERESTING_RE.search(p)]
    if interesting:
        value["interesting"] = interesting[:20]
    _add(facts, Fact("web.content_map", f"host:{ws.target}", value, ProofState.SUPPORTED, source))


def _parse_web_vhosts(text: str, ws: Workspace, source: str, facts: list[Fact]) -> None:
    """Virtual-host fuzzing hits (ffuf/wfuzz/gobuster vhost) -> web.vhost."""
    names: set[str] = set()
    for match in _WEB_GOBUSTER_VHOST_RE.finditer(text):
        if match.group("code") != "404":
            names.add(match.group("name"))
    for match in _WEB_FFUF_RE.finditer(text):
        token = match.group("token")
        if match.group("code") == "404" or token.startswith(":") or token.lower() == "status":
            continue
        names.add(token)

    names = {n.strip().rstrip(",") for n in names if n and not n.lower().startswith("http")}
    names = {n for n in names if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{1,}", n)}
    if not names:
        return
    ordered = sorted(names, key=str.lower)
    _add(facts, Fact("web.vhost", f"host:{ws.target}", {"vhosts": ordered[:50], "count": len(ordered)}, ProofState.SUPPORTED, source))


def _secret_snippets(text: str) -> list[dict]:
    """Short source/dump snippets that look like secret-bearing lines.

    These are candidate material only. They deliberately do not validate a login or
    convert a found string into a working credential.
    """
    snippets: list[dict] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or len(line) > 260:
            continue
        match = _SOURCE_SECRET_RE.search(line)
        if not match:
            continue
        key = match.group("key").lower()
        if key in seen:
            continue
        seen.add(key)
        snippets.append({"key": key, "line": line[:220]})
    return snippets


def _parse_git_source(text: str, ws: Workspace, command: str, source: str, facts: list[Fact]) -> None:
    """Exposed Git recovery signals.

    A readable `.git/HEAD` or successful git-dumper run proves source disclosure.
    Secret-looking lines in that recovered source are candidate material, not
    validated credentials.
    """
    branch = ""
    head = _GIT_HEAD_RE.search(text)
    if head:
        branch = head.group("branch")

    lowered_command = command.lower()
    source_found = bool(head) or (
        "git-dumper" in lowered_command
        and _GIT_DUMPER_SUCCESS_RE.search(text)
        and not re.search(r"\b(?:error|failed|not found|403|404)\b", text, re.IGNORECASE)
    )
    if source_found:
        value = {"kind": "git", "tool": "git-dumper" if "git-dumper" in lowered_command else "curl"}
        if branch:
            value["branch"] = branch
        _add(facts, Fact("web.source", f"host:{ws.target}", value, ProofState.SUPPORTED, source))

    secrets = _secret_snippets(text)
    if secrets:
        _add(
            facts,
            Fact(
                "credential.candidate",
                f"host:{ws.target}",
                {"kind": "source_secret", "count": len(secrets), "secrets": secrets[:20]},
                ProofState.SUPPORTED,
                source,
            ),
        )


def _parse_sqlmap(text: str, ws: Workspace, source: str, facts: list[Fact]) -> None:
    """SQLMap output, kept proof-bound.

    SQLMap can prove a confirmed SQLi primitive, database metadata, candidate
    credential material from dumped tables, or a web/app command channel. None of
    those prove OS admin/root/SYSTEM or validate a credential for lateral movement.
    """
    if not text.strip():
        return

    vuln = _SQLMAP_VULN_RE.search(text)
    if vuln:
        _add(
            facts,
            Fact(
                "web.sqli_confirmed",
                f"host:{ws.target}",
                {"tool": "sqlmap", "evidence": _line_for_match(text, vuln)},
                ProofState.SUPPORTED,
                source,
            ),
        )

    dbms = ""
    dbms_match = _SQLMAP_DBMS_RE.search(text)
    if dbms_match:
        dbms = dbms_match.group("dbms").strip()

    database_names: list[str] = []
    if _SQLMAP_DATABASE_HEADER_RE.search(text):
        database_names = sorted(
            {
                match.group("name")
                for match in _SQLMAP_STAR_ROW_RE.finditer(text)
                if match.group("name").lower() not in {"available", "database", "databases"}
            },
            key=str.lower,
        )
    if database_names or dbms:
        value: dict = {"tool": "sqlmap"}
        if dbms:
            value["dbms"] = dbms
        if database_names:
            value["databases"] = database_names[:50]
            value["count"] = len(database_names)
        _add(facts, Fact("db.databases", f"host:{ws.target}", value, ProofState.SUPPORTED, source))

    table_refs = [
        {"database": match.group("database"), "table": match.group("table")}
        for match in _SQLMAP_TABLE_RE.finditer(text)
    ]
    if table_refs:
        _add(
            facts,
            Fact("db.tables", f"host:{ws.target}", {"tool": "sqlmap", "tables": table_refs[:50]}, ProofState.SUPPORTED, source),
        )

    credential_columns = sorted(
        {
            key.lower()
            for key in re.findall(r"\b(user(?:name)?|login|email|pass(?:word)?|passwd|pwd|hash|token|api[_-]?key)\b", text, re.IGNORECASE)
        },
        key=str.lower,
    )
    if credential_columns and (_SQLMAP_DUMP_RE.search(text) or "dump" in text.lower() or table_refs):
        value = {"tool": "sqlmap", "credential_columns": credential_columns[:20]}
        if table_refs:
            value["tables"] = table_refs[:20]
        _add(facts, Fact("db.creds", f"host:{ws.target}", value, ProofState.SUPPORTED, source))
        _add(
            facts,
            Fact(
                "credential.candidate",
                f"host:{ws.target}",
                {"kind": "database_dump_secret", "count": len(credential_columns), "sources": credential_columns[:20]},
                ProofState.SUPPORTED,
                source,
            ),
        )

    shell = _SQLMAP_OS_SHELL_RE.search(text)
    if shell:
        _add(
            facts,
            Fact(
                "foothold.webshell",
                f"host:{ws.target}",
                {"tool": "sqlmap", "method": "os-shell", "evidence": _line_for_match(text, shell)},
                ProofState.SUPPORTED,
                source,
            ),
        )


def _parse_nikto(text: str, ws: Workspace, source: str, facts: list[Fact]) -> None:
    """Nikto output -> candidate findings (exploit.candidate) and any paths it reveals.

    Nikto findings are leads to verify, never confirmed vulnerabilities or access.
    """
    findings: list[str] = []
    for raw in _NIKTO_FINDING_RE.findall(text):
        finding = raw.strip()
        if not finding or finding.lower().startswith(_NIKTO_NOISE_PREFIXES):
            continue
        findings.append(finding)
    if not findings:
        return

    paths: set[str] = set()
    for finding in findings:
        paths.update(_WEB_PATH_IN_TEXT_RE.findall(finding))
    if paths:
        ordered = sorted(paths, key=str.lower)
        _add(
            facts,
            Fact(
                "web.content_map",
                f"host:{ws.target}",
                {"paths": ordered[:50], "count": len(ordered), "tool": "nikto"},
                ProofState.SUPPORTED,
                source,
            ),
        )
    _add(
        facts,
        Fact(
            "exploit.candidate",
            f"host:{ws.target}",
            {"count": len(findings), "findings": findings[:20], "tool": "nikto"},
            ProofState.SUPPORTED,
            source,
        ),
    )
