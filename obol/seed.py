"""Seed facts for the demo engagement (HTB Forest, post-initial-nmap).

These stand in for what a real `obol run nmap` would ingest: the host is up, the
AD service surface is open, and nmap's SMB/LDAP scripts revealed the domain name.
No users, no naming context, no credentials — those are what the methodology
chain has to earn. Later, `init` starts empty and the nmap parser produces these.
"""
from __future__ import annotations

from .facts import Fact, FactSet
from .workspace import Workspace

FOREST_TARGET = "10.10.10.161"


def seed_forest(ws: Workspace) -> Workspace:
    ws.target = FOREST_TARGET
    src = "nmap -p- -sC -sV 10.10.10.161 (seeded)"
    f = ws.facts
    for fact in [
        Fact("host.up", f"host:{FOREST_TARGET}", {"os": "Windows Server 2016"}, source=src),
        Fact("ad.dc_candidate", f"host:{FOREST_TARGET}", {}, source=src),
        Fact("ad.domain", "domain:htb.local", {"name": "htb.local"}, source=src),
        Fact("dns.reachable", f"host:{FOREST_TARGET}", {"port": 53}, source=src),
        Fact("kerberos.reachable", f"host:{FOREST_TARGET}", {"port": 88}, source=src),
        Fact("smb.reachable", f"host:{FOREST_TARGET}", {"port": 445}, source=src),
        Fact("ldap.reachable", f"host:{FOREST_TARGET}", {"port": 389}, source=src),
        Fact("winrm.reachable", f"host:{FOREST_TARGET}", {"port": 5985}, source=src),
    ]:
        f.add(fact)
    ws.record_run("nmap", src, ["host.up", "ad.domain", "ldap.reachable", "winrm.reachable"])
    return ws
