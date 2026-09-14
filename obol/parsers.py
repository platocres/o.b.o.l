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
_BASE_DN_RE = re.compile(r"\bnamingContexts:\s*([A-Za-z0-9_=,.-]+)", re.IGNORECASE)
_ASREP_RE = re.compile(r"(\$krb5asrep\$[^\s]+)", re.IGNORECASE)
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


def _scope_for_domain(ws: Workspace, domain: str = "") -> str:
    name = domain or _domain_from_facts(ws.facts) or "domain"
    return f"domain:{name}"


def _domain_from_facts(facts: FactSet) -> str:
    vals = facts.values("ad.domain_known")
    if vals:
        return vals[0].get("name", "")
    return ""


def _base_dn_from_domain(domain: str) -> str:
    return ",".join(f"DC={part}" for part in domain.split(".") if part)


def _add(out: list[Fact], fact: Fact) -> None:
    if not any(existing.kind == fact.kind and existing.value == fact.value for existing in out):
        out.append(fact)


def _usernames(text: str) -> list[str]:
    users: set[str] = set()
    for regex in (_SAM_RE, _UPN_RE, _NXC_USER_ROW_RE):
        for match in regex.finditer(text):
            user = match.group(1).strip()
            if not user or user.lower() in _NOISE_USERS:
                continue
            users.add(user)
    return sorted(users, key=str.lower)


def parse_action_output(action: Action, ws: Workspace, command: str, stdout: str, stderr: str, source: str) -> list[Fact]:
    """Dispatch parser for the current action/command."""
    text = "\n".join(part for part in (stdout, stderr) if part)
    facts: list[Fact] = []
    lowered_command = command.lower()

    if "nmap " in lowered_command or lowered_command.startswith("nmap "):
        _parse_nmap(text, ws, source, facts, action.id)

    if "nxc " in lowered_command or lowered_command.startswith("nxc "):
        _parse_nxc_common(text, ws, source, facts)
        if action.id == "ad-anon-ldap-enum" or "--users" in lowered_command:
            _parse_user_list(text, ws, source, facts)
        if "--asreproast" in lowered_command:
            _parse_asrep_hashes(text, ws, source, facts)

    if "ldapsearch" in lowered_command:
        _parse_ldapsearch(text, ws, source, facts)
        if "(objectclass=user)" in lowered_command.lower():
            _parse_user_list(text, ws, source, facts)

    if "getnpusers" in lowered_command.lower() or "asreproast" in lowered_command:
        _parse_asrep_hashes(text, ws, source, facts)

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

    if re.search(r"\[\+\].*(?:\\\\:|anonymous|guest|'')", text, re.IGNORECASE):
        _add(facts, Fact("ad.anonymous_bind", _scope_for_domain(ws, domain), {"tool": "nxc"}, ProofState.SUPPORTED, source))


def _parse_user_list(text: str, ws: Workspace, source: str, facts: list[Fact]) -> None:
    users = _usernames(text)
    if not users:
        return
    domain = _domain_from_facts(ws.facts)
    _add(facts, Fact("ad.user_list", _scope_for_domain(ws, domain), {"users": users, "count": len(users)}, ProofState.SUPPORTED, source))
    _add(facts, Fact("ad.anonymous_bind", _scope_for_domain(ws, domain), {"tool": "nxc"}, ProofState.SUPPORTED, source))


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


def _parse_asrep_hashes(text: str, ws: Workspace, source: str, facts: list[Fact]) -> None:
    hashes = sorted(set(_ASREP_RE.findall(text)))
    if not hashes:
        return
    _add(facts, Fact("hash.asrep", _scope_for_domain(ws), {"hashes": hashes, "count": len(hashes)}, ProofState.SUPPORTED, source))
    _add(facts, Fact("credential.candidate", _scope_for_domain(ws), {"kind": "asrep_hash", "count": len(hashes)}, ProofState.SUPPORTED, source))
