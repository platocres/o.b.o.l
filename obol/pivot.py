"""Pivot-candidate projection (§6c) — the reachable-subnet lead, surfaced.

The post-foothold local-enum parsers (`localenum.py`) already turn a host's
interface/route/neighbor output into narrow, proof-bound facts:
``host.multihomed``, ``network.subnet_candidate``, and a summarizing
``pivot.candidate``. This module is the read-only projection that lifts those
buried facts into a single "here is where you could pivot next" lead for the
target and engagement screens — the precondition display §6d's tunnels consume.

It invents nothing: a multi-homed host and an adjacent subnet are *candidates*,
not a working tunnel and not authorization. Whether a candidate subnet is already
in the operator's scope is reported so the tunnel layer (§6d) knows what it would
auto-extend, but this module never mutates scope or state.
"""
from __future__ import annotations

import ipaddress

from .scope import normalize_target
from .workspace import Workspace

# The lead facts this projection is built from — kept here so `report._fact_category`
# and the web roll-up group them under one "pivot" heading consistently.
PIVOT_FACT_KINDS = ("pivot.candidate", "host.multihomed", "network.subnet_candidate")


def _subnet_in_scope(cidr: str, scope: list[str]) -> bool:
    """True if a candidate subnet is already authorized — either listed verbatim or
    contained within an authorized CIDR entry. Used only to tag the lead for
    display and to tell §6d what it would need to auto-extend."""
    try:
        candidate = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    for entry in scope:
        item = str(entry or "").strip()
        if item == cidr:
            return True
        try:
            if candidate.subnet_of(ipaddress.ip_network(item, strict=False)):
                return True
        except (ValueError, TypeError):
            continue
    return False


def pivot_summary(ws: Workspace, host: str) -> dict:
    """A compact pivot-candidate lead for one host, or an ``empty`` marker.

    Reads only that host's proven facts. The important output is ``subnets`` — the
    candidate adjacent networks a pivot could reach — each tagged with whether it is
    already in scope, so §6d knows what a proven tunnel would auto-authorize."""
    norm = normalize_target(host)
    host_scope = f"host:{norm}"
    tf = ws.facts_for_target(norm)

    def host_values(kind: str) -> list[dict]:
        return [f.value for f in tf.facts
                if f.kind == kind and f.scope == host_scope and f.state.value == "supported"]

    multihomed_vals = host_values("host.multihomed")
    pivot_vals = host_values("pivot.candidate")

    reasons: list[str] = []
    for v in pivot_vals:
        for r in v.get("reasons", []):
            if r not in reasons:
                reasons.append(r)

    # candidate subnets: the explicit subnet_candidate facts plus any named on a
    # pivot.candidate, de-duplicated and sorted, each tagged in/out of scope.
    cidrs: list[str] = []
    for v in host_values("network.subnet_candidate"):
        cidr = v.get("cidr", "")
        if cidr and cidr not in cidrs:
            cidrs.append(cidr)
    for v in pivot_vals:
        for cidr in v.get("subnets", []):
            if cidr and cidr not in cidrs:
                cidrs.append(cidr)
    subnets = [
        {"cidr": cidr, "in_scope": _subnet_in_scope(cidr, ws.scope)}
        for cidr in sorted(cidrs)
    ]

    interfaces = [
        {"name": v.get("name", ""), "address": v.get("address", ""),
         "cidr": v.get("cidr", ""), "network": v.get("network", "")}
        for v in host_values("host.interface")
    ]
    neighbors = len(host_values("host.arp_neighbor"))
    dns_servers = sorted({v.get("address", "") for v in host_values("host.dns_server") if v.get("address")})

    empty = not (multihomed_vals or subnets or reasons)
    return {
        "host": norm,
        "empty": empty,
        "multihomed": bool(multihomed_vals),
        "interface_count": max((v.get("interfaces", 0) for v in multihomed_vals), default=len(interfaces)),
        "interfaces": interfaces,
        "subnets": subnets,
        "unscoped_subnets": [s["cidr"] for s in subnets if not s["in_scope"]],
        "reasons": reasons,
        "neighbors": neighbors,
        "dns_servers": dns_servers,
    }


def engagement_pivots(ws: Workspace) -> list[dict]:
    """Every host that has a pivot-candidate lead, for the engagement screen. Only
    hosts with a real lead are returned, so the view stays lean."""
    out: list[dict] = []
    for t in ws.targets:
        summary = pivot_summary(ws, t["host"])
        if summary["empty"]:
            continue
        summary["label"] = t.get("label") or t["host"]
        out.append(summary)
    return out


__all__ = ["PIVOT_FACT_KINDS", "pivot_summary", "engagement_pivots"]
