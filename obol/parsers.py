"""Evidence parsers for tool output.

Parsers map observed output to the narrowest supported facts. They should parse
stable tool signals, not walkthrough-specific names, passwords, hosts, or paths.
Unknown output is still preserved by the runner; it simply produces no facts.
"""
from __future__ import annotations

import re

from .facts import Fact, FactSet, ProofState
from .pack import Action
from .workspace import Workspace

_DOMAIN_RE = re.compile(r"\(domain:([^)]+)\)", re.IGNORECASE)
_NAME_RE = re.compile(r"\(name:([^)]+)\)", re.IGNORECASE)
_NXC_PROTO_REACHABLE_RE = re.compile(r"^(?P<proto>LDAP|SMB)\s+\S+\s+\d+\s+\S+", re.IGNORECASE | re.MULTILINE)
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
_BASE_DN_RE = re.compile(r"\bnamingContexts:\s*([A-Za-z0-9_=,.-]+)", re.IGNORECASE)
_ASREP_RE = re.compile(r"(\$krb5asrep\$[^\s]+)", re.IGNORECASE)
_ASREP_USER_RE = re.compile(r"\$krb5asrep\$\d+\$([^:@$]+)(?:@([^:$]+))?:", re.IGNORECASE)
_TGS_RE = re.compile(r"(\$krb5tgs\$[^\s]+)", re.IGNORECASE)
_TGS_USER_RE = re.compile(r"\$krb5tgs\$\d+\$\*?([^$*:]+)", re.IGNORECASE)
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


def _scope_for_domain(ws: Workspace, domain: str = "") -> str:
    name = domain or _domain_from_facts(ws.facts) or "domain"
    return f"domain:{name}"


def _domain_from_facts(facts: FactSet) -> str:
    vals = facts.values("ad.domain_known")
    if vals:
        return vals[0].get("name", "")
    return ""


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


def _add(out: list[Fact], fact: Fact) -> None:
    if not any(existing.kind == fact.kind and existing.value == fact.value for existing in out):
        out.append(fact)


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


def _is_ldap_command(command: str) -> bool:
    cmd = f" {command.lower()} "
    return " ldap " in cmd or "ldapsearch" in cmd


def _is_smb_command(command: str) -> bool:
    cmd = f" {command.lower()} "
    return " smb " in cmd or "smbclient" in cmd or "rpcclient" in cmd or "enum4linux" in cmd or "smbmap" in cmd


def _is_cracking_command(command: str) -> bool:
    lowered = f" {command.lower()} "
    return " hashcat " in lowered or re.search(r"(^|[\s/])john(\s|$)", lowered) is not None


def _looks_anonymous_ldap_command(command: str, action: Action) -> bool:
    lowered = command.lower()
    if action.id == "ad-anon-ldap-enum":
        return True
    return _is_ldap_command(command) and (" -x " in f" {lowered} " or "-u ''" in lowered or '-u ""' in lowered)


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

    if _is_cracking_command(command):
        _parse_cracked_credentials(text, ws, command, source, facts)

    return facts


def _parse_nmap(text: str, ws: Workspace, source: str, facts: list[Fact], action_id: str) -> None:
    open_ports: dict[tuple[int, str], dict] = {}

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

    tcp_ports = {value["port"] for value in open_ports.values() if value["protocol"] == "tcp"}
    if {88, 389, 445}.issubset(tcp_ports) or _looks_like_ad_ldap(text):
        _add(facts, Fact("ad.dc_candidate", f"host:{ws.target}", {"ports": sorted(tcp_ports & {88, 389, 445})}, ProofState.SUPPORTED, source))


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
    if proto != "tcp":
        return
    if port in {389, 636, 3268, 3269} or "ldap" in service_l:
        _add(facts, Fact("ldap.reachable", f"host:{ws.target}", value, ProofState.SUPPORTED, source))
    if port in {445, 139} or service_l in {"microsoft-ds", "netbios-ssn"}:
        _add(facts, Fact("smb.reachable", f"host:{ws.target}", value, ProofState.SUPPORTED, source))
    if port == 88 or "kerberos" in service_l:
        _add(facts, Fact("kerberos.reachable", f"host:{ws.target}", value, ProofState.SUPPORTED, source))
    if port in {5985, 5986} or "wsman" in service_l or "winrm" in service_l:
        _add(facts, Fact("winrm.reachable", f"host:{ws.target}", value, ProofState.SUPPORTED, source))
    if port in {80, 443, 8080, 8000, 8443} or service_l in {"http", "https", "ssl/http"}:
        _add(facts, Fact("http.reachable", f"host:{ws.target}", value, ProofState.SUPPORTED, source))


def _looks_like_ad_ldap(text: str) -> bool:
    return bool(re.search(r"Active Directory|Domain Controller|Global Catalog|ldap-rootdse", text, re.IGNORECASE))


def _parse_nxc_common(text: str, ws: Workspace, source: str, facts: list[Fact]) -> None:
    domain = ""
    domain_match = _DOMAIN_RE.search(text)
    if domain_match:
        domain = domain_match.group(1).strip()
        if domain and domain not in {"None", "-"}:
            _add(facts, Fact("ad.domain_known", f"domain:{domain}", {"name": domain}, ProofState.SUPPORTED, source))
            _add(facts, Fact("ad.base_dn", f"domain:{domain}", {"base_dn": _base_dn_from_domain(domain)}, ProofState.SUPPORTED, source))

    name_match = _NAME_RE.search(text)
    if name_match or domain:
        value = {"host": ws.target}
        if name_match:
            value["name"] = name_match.group(1).strip()
        if domain:
            value["domain"] = domain
        _add(facts, Fact("ad.dc_candidate", f"host:{ws.target}", value, ProofState.SUPPORTED, source))

    for match in _NXC_PROTO_REACHABLE_RE.finditer(text):
        proto = match.group("proto").lower()
        if proto in {"ldap", "smb"}:
            _add(facts, Fact(f"{proto}.reachable", f"host:{ws.target}", {"tool": "nxc"}, ProofState.SUPPORTED, source))

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
    domain = domain_hint or _domain_from_facts(ws.facts)
    _add(facts, Fact("ad.user_list", _scope_for_domain(ws, domain), {"users": users, "count": len(users)}, ProofState.SUPPORTED, source))
    if prove_anonymous_ldap:
        _add(facts, Fact("ad.anonymous_bind", _scope_for_domain(ws, domain), {"tool": "nxc"}, ProofState.SUPPORTED, source))


def _parse_rid_user_list(text: str, ws: Workspace, source: str, facts: list[Fact], *, domain_hint: str = "") -> None:
    users = _rid_usernames(text)
    if not users:
        return
    domain = domain_hint or _domain_from_facts(ws.facts)
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

    domain_name = domain or _domain_from_facts(ws.facts)
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
