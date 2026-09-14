"""Roadmap parser expansion layered over the legacy parser core.

This module preserves the working parser behavior in parsers_legacy, then adds
larger post-credential AD path evidence parsing: credential validation, TGS
roast material, WinRM footholds, and BloodHound collection/analysis signals.
"""
from __future__ import annotations

import re
import shlex

from .facts import Fact, ProofState
from .pack import Action
from .parsers_legacy import parse_action_output as _legacy_parse_action_output
from .workspace import Workspace

_NXC_AUTH_RE = re.compile(r"^\s*(?P<proto>SMB|LDAP|WINRM)\s+\S+\s+\d+\s+\S+\s+\[\+\]\s+(?P<auth>.+)$", re.IGNORECASE)
_AUTH_MATERIAL_RE = re.compile(r"^(?:(?P<domain>[^\\\s:/]+)\\)?(?P<user>[A-Za-z0-9._$-]{2,}):(?P<password>[^\s()]+)")
_TGS_RE = re.compile(r"(\$krb5tgs\$[^\s]+)", re.IGNORECASE)
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


def parse_action_output(action: Action, ws: Workspace, command: str, stdout: str, stderr: str, source: str) -> list[Fact]:
    """Parse tool output with the legacy core plus roadmap expansion facts."""
    text = "\n".join(part for part in (stdout, stderr) if part)
    facts = _legacy_parse_action_output(action, ws, command, stdout, stderr, source)
    lowered_command = command.lower()

    if "nxc " in lowered_command or lowered_command.startswith("nxc "):
        _parse_nxc_auth_validation(text, ws, source, facts)
        _parse_auth_failures(text, ws, source, facts)
        if "--kerberoast" in lowered_command or "--kerberoasting" in lowered_command:
            _parse_tgs_hashes(text, ws, source, facts)
        if "--bloodhound" in lowered_command:
            _parse_bloodhound_collection(text, ws, source, facts)

    if "getuserspns" in lowered_command or "kerberoast" in lowered_command:
        _parse_tgs_hashes(text, ws, source, facts)

    if "bloodhound-python" in lowered_command or "sharphound" in lowered_command:
        _parse_bloodhound_collection(text, ws, source, facts)
    if "bloodhound" in lowered_command:
        _parse_bloodhound_analysis(text, ws, source, facts)

    if " winrm " in f" {lowered_command} " or "evil-winrm" in lowered_command:
        _parse_evil_winrm(text, ws, command, source, facts)

    return facts


def _domain_from_facts(ws: Workspace) -> str:
    vals = ws.facts.values("ad.domain_known")
    if vals:
        return vals[0].get("name", "")
    return ""


def _scope_for_domain(ws: Workspace, domain: str = "") -> str:
    return f"domain:{domain or _domain_from_facts(ws) or 'domain'}"


def _add(out: list[Fact], fact: Fact) -> None:
    if not any(existing.kind == fact.kind and existing.value == fact.value and existing.state == fact.state for existing in out):
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


def _parse_auth_material(auth: str) -> tuple[str, str, str]:
    auth = re.sub(r"\s+\([^)]*\)\s*$", "", auth.strip())
    match = _AUTH_MATERIAL_RE.match(auth)
    if not match:
        return "", "", ""
    domain = (match.group("domain") or "").strip()
    user = _clean_username(match.group("user"))
    password = match.group("password").strip()
    return domain, user, password


def _add_authenticated_service(
    facts: list[Fact],
    ws: Workspace,
    source: str,
    *,
    proto: str,
    user: str,
    password: str,
    domain: str = "",
    admin: bool = False,
) -> None:
    user = _clean_username(user)
    if not _valid_username(user, allow_machine=False) or not _valid_password(password):
        return
    domain_name = domain or _domain_from_facts(ws)
    value = {"user": user, "password": password, "service": proto, "method": "nxc"}
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
        domain, user, password = _parse_auth_material(auth)
        if not user or not password:
            continue
        _add_authenticated_service(
            facts,
            ws,
            source,
            proto=proto,
            user=user,
            password=password,
            domain=domain,
            admin="pwn3d" in auth.lower(),
        )


def _parse_auth_failures(text: str, ws: Workspace, source: str, facts: list[Fact]) -> None:
    lowered = text.lower()
    for marker, reason in _FAILURE_REASONS.items():
        if marker in lowered:
            _add(facts, Fact("credential.validation", f"host:{ws.target}", {"reason": reason}, ProofState.REFUTED, source))


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


def _parse_evil_winrm(text: str, ws: Workspace, command: str, source: str, facts: list[Fact]) -> None:
    if not (_EW_PROMPT_RE.search(text) or "evil-winrm shell" in text.lower() or "establishing connection to remote endpoint" in text.lower()):
        return
    user = _command_arg(command, "-u", "--user", "--username")
    password = _command_arg(command, "-p", "--password")
    domain = _command_arg(command, "-r", "--realm", "-d", "--domain")
    value = {"service": "winrm", "tool": "evil-winrm"}
    if user:
        value["user"] = _clean_username(user)
    if password:
        value["password"] = password
    if domain:
        value["domain"] = domain
    _add(facts, Fact("winrm.authenticated", f"host:{ws.target}", value, ProofState.SUPPORTED, source))
    _add(facts, Fact("foothold.windows", f"host:{ws.target}", value, ProofState.SUPPORTED, source))
    if user and password and _valid_password(password):
        cred_value = {"user": _clean_username(user), "password": password, "service": "winrm", "method": "evil-winrm"}
        if domain:
            cred_value["domain"] = domain
        _add(facts, Fact("credential.available", _scope_for_domain(ws, domain), cred_value, ProofState.SUPPORTED, source))


def _parse_tgs_hashes(text: str, ws: Workspace, source: str, facts: list[Fact]) -> None:
    hashes = sorted(set(_TGS_RE.findall(text)))
    if not hashes:
        return
    _add(facts, Fact("hash.tgs", _scope_for_domain(ws), {"hashes": hashes, "count": len(hashes)}, ProofState.SUPPORTED, source))
    _add(facts, Fact("credential.candidate", _scope_for_domain(ws), {"kind": "tgs_hash", "count": len(hashes)}, ProofState.SUPPORTED, source))


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
