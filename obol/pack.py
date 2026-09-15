"""Methodology packs: fact-gated actions loaded from data, plus the planner.

An Action is a methodology branch expressed as data: what facts must already be
proven for it to apply (`requires_*`), what a successful run can prove
(`produces`, as fact kinds), and — conservatively derived — what it does *not*
prove. The planner does no cleverness: it asks which actions the current facts
unlock, which are blocked and why, and ranks the unlocked ones.

Packs live as JSON under obol/packs/ and are loaded here. The default pack is the
Active Directory set exported from the Orange Cyberdefense 2025.03 methodology
(see obol/packs/NOTICE.md) — the grounded replacement for the earlier hardcoded
Forest placeholder. Keeping actions as data, not planner code, is what let that
swap happen without touching the planner.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .facts import Fact, FactSet, ProofState
from .phases import frontier_index, phase_index, phase_of_action

PACKS_DIR = Path(__file__).parent / "packs"
DEFAULT_PACK = "orange_ad_2025_03"
# Packs loaded together by the planner. Sibling packs reuse the shared fact-kind
# namespace so cross-domain gating works (e.g. an HTTP port unlocks web actions,
# a web foothold could unlock a privesc pack, and a proven foothold can unlock
# pivot-candidate local enumeration). Order is load order only; the planner ranks
# by each action's priority, not pack order.
PACK_NAMES = [
    "orange_ad_2025_03",
    "orange_web_2025_03",
    "orange_linux_privesc_2025_03",
    "orange_windows_privesc_2025_03",
    "obol_local_pivot_2026_09",
    "obol_flag_hunt_2026_09",
]


@dataclass
class Action:
    id: str
    title: str
    tool: str = ""
    command: str = ""                  # primary command template (first of `commands`)
    proves: str = ""
    does_not_prove: str = ""
    priority: int = 50
    phase: str = ""                    # optional pack override; else derived from produces
    autonomy: str = ""                 # optional pack override (auto/approve/manual);
                                       # else derived (obol/autonomy.py)
    requires_all: list[str] = field(default_factory=list)
    requires_any: list[str] = field(default_factory=list)
    produces: list[str] = field(default_factory=list)   # fact kinds
    hypothesis: str = ""
    tools: list[str] = field(default_factory=list)
    os: list[str] = field(default_factory=list)
    report: dict | None = None
    refs: list[str] = field(default_factory=list)
    commands: list[dict] = field(default_factory=list)  # [{tool, run, note}]

    def produced_kinds(self) -> set[str]:
        return set(self.produces)

    def settled(self, facts: FactSet) -> bool:
        pk = self.produced_kinds()
        return bool(pk) and pk.issubset(facts.kinds())

    def eligible(self, facts: FactSet) -> bool:
        if not os_compatible(facts, self.os):
            return False
        if not all(facts.has(k) for k in self.requires_all):
            return False
        if self.requires_any and not any(facts.has(k) for k in self.requires_any):
            return False
        return True

    def unmet(self, facts: FactSet) -> str:
        if not os_compatible(facts, self.os):
            family = host_os_family(facts) or "another OS"
            return f"blocked because target looks like {family}"
        for k in self.requires_all:
            if not facts.has(k):
                return f"blocked until {friendly(k)} exists"
        if self.requires_any and not any(facts.has(k) for k in self.requires_any):
            alts = " or ".join(friendly(k) for k in self.requires_any)
            return f"blocked until {alts}"
        return "blocked"

    @classmethod
    def from_json(cls, d: dict) -> "Action":
        cmds = d.get("commands", [])
        return cls(
            id=d["id"], title=d.get("title", d["id"]),
            tool=d.get("tool", ""),
            command=(cmds[0]["run"] if cmds else d.get("command", "")),
            proves=d.get("proves", ""), does_not_prove=d.get("does_not_prove", ""),
            priority=int(d.get("priority", 50)), phase=d.get("phase", ""),
            autonomy=d.get("autonomy", ""),
            requires_all=list(d.get("requires_all", [])),
            requires_any=list(d.get("requires_any", [])),
            produces=list(d.get("produces", [])),
            hypothesis=d.get("hypothesis", ""), tools=list(d.get("tools", [])),
            os=list(d.get("os", [])), report=d.get("report"),
            refs=list(d.get("refs", [])), commands=list(cmds),
        )


# --------------------------------------------------------------------------- #
# friendly fact-kind phrasing (blocked reasons, board)                         #
# --------------------------------------------------------------------------- #
_FRIENDLY = {
    "target.configured": "a configured target",
    "host.up": "a live host",
    "host.os_family": "target OS family",
    "host.os_hint": "target OS hint",
    "host.interface": "host network interface",
    "host.ip_address": "host IP address",
    "host.route": "host route",
    "host.arp_neighbor": "host ARP neighbor",
    "host.dns_server": "host DNS server",
    "host.listen_socket": "host listening socket",
    "host.multihomed": "multi-homed host",
    "network.subnet_candidate": "candidate adjacent subnet",
    "pivot.candidate": "pivot candidate",
    "ports.open": "open ports",
    "scan.nmap.quick": "a quick nmap open-port scan",
    "scan.nmap.version": "an nmap service/version scan",
    "scan.nmap.udp": "an nmap UDP scan",
    "scan.local.interfaces": "local interface enumeration",
    "scan.local.routes": "local route table enumeration",
    "scan.local.neighbors": "local neighbor cache enumeration",
    "scan.local.dns": "local resolver enumeration",
    "scan.local.listeners": "local listening-socket enumeration",
    "ad.dc_candidate": "a domain-controller candidate", "ad.domain_known": "the domain",
    "ad.base_dn": "the LDAP base DN", "ad.user_list": "a domain user list",
    "ad.anonymous_bind": "anonymous LDAP bind", "ad.graph.collected": "the AD graph",
    "ad.attack_paths": "attack paths", "ad.control_paths": "object-control paths",
    "ad.trusts": "domain trusts", "ad.computer_added": "an added computer account",
    "hash.asrep": "an AS-REP hash", "hash.tgs": "a Kerberoast hash", "hash.ntlm": "NTLM hashes",
    "hash.krbtgt": "the krbtgt hash", "hash.tgt": "a TGT",
    "credential.candidate": "candidate credentials", "credential.available": "a usable credential",
    "credential.validation": "credential validation evidence",
    "credential.admin": "an admin credential", "credential.certificate": "certificate material",
    "credential.ntlm_hash": "an NT hash", "credential.plaintext": "a plaintext password",
    "kerberos.tickets": "Kerberos tickets", "kerberos.reachable": "Kerberos is reachable",
    "ldap.reachable": "LDAP is reachable", "ldap.authenticated": "authenticated LDAP access",
    "smb.reachable": "SMB is reachable", "smb.authenticated": "authenticated SMB access",
    "smb.null_session": "SMB null session", "smb.guest_session": "SMB guest session",
    "smb.shares": "SMB shares", "winrm.authenticated": "authenticated WinRM access",
    "winrm.reachable": "WinRM is reachable", "rdp.reachable": "RDP is reachable",
    "rdp.authenticated": "authenticated RDP access", "ssh.reachable": "SSH is reachable",
    "ssh.authenticated": "authenticated SSH access", "ssh.banner": "an SSH banner",
    "ssh.hostkey": "SSH host keys", "ftp.reachable": "FTP is reachable",
    "ftp.authenticated": "authenticated FTP access", "ftp.banner": "an FTP banner",
    "ftp.anonymous_login": "anonymous FTP login", "snmp.reachable": "SNMP is reachable",
    "snmp.community": "an SNMP community", "snmp.info": "SNMP system info",
    "dns.reachable": "DNS is reachable", "http.response": "an HTTP response",
    "http.redirect": "an HTTP redirect",
    "access.admin": "administrative access", "access.system": "SYSTEM access",
    "access.desktop": "an interactive desktop", "foothold.windows": "a Windows foothold",
    "access.shell": "an interactive shell", "foothold.linux": "a Linux foothold",
    "loot.ntds": "NTDS secrets", "adcs.vulnerable": "a vulnerable ADCS template",
    "persistence.domain": "domain persistence", "enum.deep": "deep enumeration",
    "vuln.candidates": "vulnerability candidates", "relay.success": "a successful relay",
    "config.review": "config review", "lateral.movement": "lateral movement",
    "host.kernel": "host kernel/version", "host.arch": "host architecture",
    "privesc.leads": "local privilege escalation leads",
    "privesc.sudo_rights": "sudo rights lead",
    "privesc.suid_candidate": "SUID/SGID candidate",
    "privesc.capability": "dangerous Linux capability",
    "privesc.cron_writable": "writable scheduled task or cron lead",
    "privesc.process_lead": "process-monitoring privesc lead",
    "privesc.passwd_writable": "writable /etc/passwd lead",
    "privesc.nfs_no_root_squash": "NFS no_root_squash lead",
    "privesc.lxd_group": "LXD group escape lead",
    "privesc.docker_group": "Docker socket/group escape lead",
    "privesc.windows_privilege": "dangerous Windows privilege",
    "privesc.always_install_elevated": "AlwaysInstallElevated lead",
    "privesc.unquoted_service_path": "unquoted service path lead",
    "privesc.weak_service_permission": "weak service permission lead",
    "privesc.stored_credentials": "stored Windows credential lead",
    "privesc.patch_gap": "missing-patch privesc lead",
    "persistence.linux": "Linux persistence", "persistence.windows": "Windows persistence",
    "http.reachable": "HTTP is reachable",
    "web.content_map": "a map of discovered web content", "web.vhost": "a discovered virtual host",
    "web.title": "a web page title", "web.server": "a web server header",
    "web.tech": "web technology fingerprints",
    "web.source": "exposed application source", "web.parameterized": "a parameterized web endpoint",
    "web.authenticated": "authenticated web access", "web.upload_form": "a file-upload form",
    "web.upload_confirmed": "a confirmed file upload", "web.lfi_confirmed": "a confirmed local file inclusion",
    "web.sqli_confirmed": "a confirmed SQL injection", "web.cmdi_confirmed": "a confirmed command injection",
    "web.ssrf_confirmed": "a confirmed SSRF", "web.users": "enumerated application users",
    "web.nosqli_confirmed": "a confirmed NoSQL injection",
    "web.jwt_secret": "a recovered JWT signing secret",
    "web.authz_bypass": "a web authorization bypass",
    "foothold.webshell": "a web shell", "db.databases": "database names",
    "db.tables": "database tables", "db.creds": "database credential material",
    "loot.files": "recovered files", "cloud.aws_access": "AWS cloud access",
    "exploit.candidate": "a candidate exploit",
    "objective.flag": "a captured flag",
    "objective.local_flag": "a captured local flag",
    "objective.root_flag": "a captured root/proof flag",
}


def friendly(kind: str) -> str:
    if kind in _FRIENDLY:
        return _FRIENDLY[kind]
    if kind.startswith("port:"):
        return f"port {kind.split(':', 1)[1]} open"
    if kind.startswith("service."):
        return f"{kind.split('.', 1)[1]} service evidence"
    return kind


def _normalize_os_name(value: str) -> str:
    text = str(value or "").strip().lower()
    if text in {"windows", "win"}:
        return "windows"
    if text in {"linux", "unix", "gnu/linux"}:
        return "linux"
    return ""


def host_os_family(facts: FactSet) -> str:
    """Return the single proven target OS family, or '' when unknown/conflicting."""
    families = {
        family
        for value in facts.values("host.os_family")
        for family in [_normalize_os_name(value.get("family", ""))]
        if family
    }
    if not families:
        if facts.has("foothold.windows") or facts.has("winrm.authenticated") or facts.has("rdp.authenticated"):
            families.add("windows")
        if facts.has("foothold.linux"):
            families.add("linux")
    return next(iter(families)) if len(families) == 1 else ""


def os_compatible(facts: FactSet, action_os: list[str] | tuple[str, ...] | None) -> bool:
    """Whether an action's OS tags fit this target.

    Unknown target OS stays permissive so early recon still works. Once a host has
    one proven OS family, wrong-platform actions are hidden from next moves and
    tool palettes.
    """
    allowed = {_normalize_os_name(item) for item in (action_os or [])}
    allowed.discard("")
    if not allowed:
        return True
    family = host_os_family(facts)
    if not family:
        return True
    return family in allowed


# --------------------------------------------------------------------------- #
# pack loading                                                                 #
# --------------------------------------------------------------------------- #
def load_pack(name: str = DEFAULT_PACK) -> list[Action]:
    path = name if name.endswith(".json") else str(PACKS_DIR / f"{name}.json")
    data = json.loads(Path(path).read_text())
    return [Action.from_json(a) for a in data["actions"]]


def load_packs(names: list[str] | None = None) -> list[Action]:
    """Load and concatenate several packs (default: all shipped packs).

    Action ids are unique across packs; if a later pack ever reused an id, the
    first definition wins and the duplicate is dropped, so a merge can never
    silently shadow methodology.
    """
    names = names if names is not None else PACK_NAMES
    seen: set[str] = set()
    out: list[Action] = []
    for name in names:
        for action in load_pack(name):
            if action.id in seen:
                continue
            seen.add(action.id)
            out.append(action)
    return out


# --------------------------------------------------------------------------- #
# planner                                                                      #
# --------------------------------------------------------------------------- #
def next_actions(facts: FactSet, pack: list[Action] | None = None) -> list[Action]:
    """The live actions, ranked by the engagement phase/flow model.

    Actions are bucketed by how far *ahead of the target's current frontier* they
    reach (0 = on-flow, at or behind the stage being pushed into) and then, within a
    bucket, by their pack priority. So recon and low-risk enumeration sort ahead of a
    premature high-value branch (a loot dump that becomes eligible mid-enumeration
    drops below the enum you should finish first), while a deliberately low-priority
    recon step never leapfrogs the real next move — priority still orders the on-flow
    band. The frontier is per-factset, so each target ranks by its own progress.
    """
    pack = pack if pack is not None else load_packs()
    live = [a for a in pack if a.eligible(facts) and not a.settled(facts)]
    frontier = frontier_index(facts)
    return sorted(
        live,
        key=lambda a: (max(0, phase_index(phase_of_action(a)) - frontier), -a.priority),
    )


def blocked_actions(facts: FactSet, pack: list[Action] | None = None) -> list[Action]:
    pack = pack if pack is not None else load_packs()
    blocked = [a for a in pack if not a.eligible(facts) and not a.settled(facts)]
    return sorted(blocked, key=lambda a: a.priority, reverse=True)


def apply_action(action: Action, facts: FactSet, source: str) -> list[Fact]:
    """'Run' an action by recording the fact kinds it produces (stubbed execution).

    Later this is where the runner executes the command and a parser reads real
    output, recording facts only for what the output actually supports. For now
    the pack's declared `produces` stand in so the loop visibly advances.
    """
    new: list[Fact] = []
    for kind in action.produces:
        scope = "domain:htb.local" if kind.startswith("ad.") else "host:target"
        fact = Fact(kind=kind, scope=scope, value={}, state=ProofState.SUPPORTED, source=source)
        if facts.add(fact):
            new.append(fact)
    return new
