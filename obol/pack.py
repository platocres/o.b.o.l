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

PACKS_DIR = Path(__file__).parent / "packs"
DEFAULT_PACK = "orange_ad_2025_03"


@dataclass
class Action:
    id: str
    title: str
    tool: str = ""
    command: str = ""                  # primary command template (first of `commands`)
    proves: str = ""
    does_not_prove: str = ""
    priority: int = 50
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
        if not all(facts.has(k) for k in self.requires_all):
            return False
        if self.requires_any and not any(facts.has(k) for k in self.requires_any):
            return False
        return True

    def unmet(self, facts: FactSet) -> str:
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
            priority=int(d.get("priority", 50)),
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
    "ports.open": "open ports",
    "scan.nmap.quick": "a quick nmap open-port scan",
    "scan.nmap.version": "an nmap service/version scan",
    "scan.nmap.udp": "an nmap UDP scan",
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
    "access.admin": "administrative access", "access.system": "SYSTEM access",
    "access.desktop": "an interactive desktop", "foothold.windows": "a Windows foothold",
    "access.shell": "an interactive shell", "foothold.linux": "a Linux foothold",
    "loot.ntds": "NTDS secrets", "adcs.vulnerable": "a vulnerable ADCS template",
    "persistence.domain": "domain persistence", "enum.deep": "deep enumeration",
    "vuln.candidates": "vulnerability candidates", "relay.success": "a successful relay",
    "config.review": "config review", "lateral.movement": "lateral movement",
    "http.reachable": "HTTP is reachable", "winrm.reachable": "WinRM is reachable",
}


def friendly(kind: str) -> str:
    if kind in _FRIENDLY:
        return _FRIENDLY[kind]
    if kind.startswith("port:"):
        return f"port {kind.split(':', 1)[1]} open"
    if kind.startswith("service."):
        return f"{kind.split('.', 1)[1]} service evidence"
    return kind


# --------------------------------------------------------------------------- #
# pack loading                                                                 #
# --------------------------------------------------------------------------- #
def load_pack(name: str = DEFAULT_PACK) -> list[Action]:
    path = name if name.endswith(".json") else str(PACKS_DIR / f"{name}.json")
    data = json.loads(Path(path).read_text())
    return [Action.from_json(a) for a in data["actions"]]


# --------------------------------------------------------------------------- #
# planner                                                                      #
# --------------------------------------------------------------------------- #
def next_actions(facts: FactSet, pack: list[Action] | None = None) -> list[Action]:
    pack = pack if pack is not None else load_pack()
    live = [a for a in pack if a.eligible(facts) and not a.settled(facts)]
    return sorted(live, key=lambda a: a.priority, reverse=True)


def blocked_actions(facts: FactSet, pack: list[Action] | None = None) -> list[Action]:
    pack = pack if pack is not None else load_pack()
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
