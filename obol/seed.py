"""Seed facts for the demo engagement (HTB Forest, post-initial-nmap + DC identify).

Stands in for what `obol run nmap` + DC identification would ingest: the host is
up, the AD service surface is reachable, and the domain is known. No users, no
naming context, no credentials — those are what the Orange AD pack has to earn.
Fact kinds match the pack's namespace so the methodology chain unlocks from here.
"""
from __future__ import annotations

from .facts import Fact
from .workspace import Workspace

FOREST_TARGET = "10.10.10.161"


def seed_forest(ws: Workspace) -> Workspace:
    ws.target = FOREST_TARGET
    ws.add_scope(FOREST_TARGET)
    src = "nmap -p- -sC -sV 10.10.10.161  +  DC identify (seeded)"
    for fact in [
        Fact("target.configured", f"host:{FOREST_TARGET}", {"target": FOREST_TARGET}, source="obol init --demo"),
        Fact("host.up", f"host:{FOREST_TARGET}", {"os": "Windows Server 2016"}, source=src),
        Fact("scan.nmap.quick", f"host:{FOREST_TARGET}", {"profile": "open-port-discovery"}, source=src),
        Fact("scan.nmap.version", f"host:{FOREST_TARGET}", {"profile": "service-version"}, source=src),
        Fact("ports.open", f"host:{FOREST_TARGET}", {"ports": [88, 389, 445]}, source=src),
        Fact("port:88", f"host:{FOREST_TARGET}", {"port": 88, "protocol": "tcp", "service": "kerberos-sec"}, source=src),
        Fact("port:389", f"host:{FOREST_TARGET}", {"port": 389, "protocol": "tcp", "service": "ldap"}, source=src),
        Fact("port:445", f"host:{FOREST_TARGET}", {"port": 445, "protocol": "tcp", "service": "microsoft-ds"}, source=src),
        Fact("ad.dc_candidate", f"host:{FOREST_TARGET}", {}, source=src),
        Fact("ad.domain_known", "domain:htb.local", {"name": "htb.local"}, source=src),
        Fact("kerberos.reachable", f"host:{FOREST_TARGET}", {"port": 88}, source=src),
        Fact("ldap.reachable", f"host:{FOREST_TARGET}", {"port": 389}, source=src),
        Fact("smb.reachable", f"host:{FOREST_TARGET}", {"port": 445}, source=src),
    ]:
        ws.facts.add(fact)
    ws.record_run("nmap", src, ["host.up", "ad.dc_candidate", "ad.domain_known"])
    return ws
