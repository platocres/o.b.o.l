"""Engagement discovery sweep — turn an authorized range into targets.

The operator authorizes a network (a CIDR or host, in `Workspace.scope`), and a
sweep enumerates the *live hosts* in it and adds each as a target — so obol can
populate an engagement without the operator hand-adding a single host.

This is engagement **scaffolding**, exactly like the nmap prelude actions
(`docs/SOURCES.md §2`): it is obol's own execution infrastructure, not an Orange
methodology claim, and it stays honest about proof — a host answering discovery
probes is *reachable*, nothing more. Its per-host services, credentials, and
access are established later by the service-aware Quick Start fan-out and the
packs, each behind its own parser.

Everything here goes through the one scope-enforced runner (`runner.run_command`)
and the one store; there is no second engine. The sweep is gated on the range
being an authorized scope entry (a stricter check than host membership), so it
can never touch a network the operator has not put in scope.
"""
from __future__ import annotations

import re

from .runner import RunnerError, run_command
from .scope import normalize_target, target_in_scope
from .workspace import Workspace

# Reliable host discovery for OSCP/AD networks: ICMP echo + TCP SYN/ACK to common
# (including AD) ports + a UDP NetBIOS probe, so hosts that filter ICMP — most
# Windows/AD boxes, e.g. HTB Forest — are still found. `-sn` means discovery only
# (no port scan); the service scan is the per-host Quick Start's job. `{range}` is
# substituted with the authorized scope entry. Fixed-argv, no shell metacharacters.
DISCOVERY_COMMAND = (
    "nmap -sn -PE -PS21,22,25,53,80,88,135,139,443,445,464,636,3268,3389 "
    "-PA80,443,3389 -PU137 -T4 {range}"
)

# "Nmap scan report for 10.10.10.161" or "... for dc01.htb.local (10.10.10.161)".
# In `-sn`, nmap prints a report line only for hosts that are up, so each match is
# a live host. The IP is in parentheses when reverse DNS resolved, else bare.
_REPORT_RE = re.compile(
    r"^Nmap scan report for (?P<name>\S+)(?: \((?P<ip>[0-9A-Fa-f:.]+)\))?\s*$",
    re.MULTILINE,
)


def discovery_command(ws: Workspace, range_: str) -> str:
    """Render the discovery command for a range. An operator override lives in the
    engagement input `discovery_cmd` (must contain `{range}`, or the range is
    appended); otherwise the default AD-aware sweep is used."""
    template = (ws.inputs.get("discovery_cmd") or "").strip() or DISCOVERY_COMMAND
    if "{range}" in template:
        return template.replace("{range}", range_)
    return f"{template} {range_}"


def parse_live_hosts(text: str) -> list[str]:
    """Extract the live host IPs from `nmap -sn` output, de-duplicated, in order."""
    hosts: list[str] = []
    seen: set[str] = set()
    for match in _REPORT_RE.finditer(text or ""):
        raw = match.group("ip") or match.group("name")
        norm = normalize_target(raw)
        # Only real IPs become targets — a bare rDNS name with no IP is skipped
        # rather than guessed at.
        if not norm or norm in seen:
            continue
        try:
            int(norm.split(".")[0]) if "." in norm else int(norm.split(":")[0], 16)
        except ValueError:
            continue
        seen.add(norm)
        hosts.append(norm)
    return hosts


def run_sweep(ws: Workspace, range_: str, *, dry_run: bool = False,
              timeout: int = 600) -> dict:
    """Sweep an authorized range for live hosts and add each as a target.

    Runs the discovery command through the shared scope-enforced runner, parses
    the live hosts, and creates a target for each in-scope host (idempotently).
    Records a ledger row and persists. Raises RunnerError if the range is not an
    authorized scope entry. Returns a summary dict.
    """
    range_ = str(range_ or "").strip()
    if range_ not in ws.scope:
        raise RunnerError(
            f"scope refused {range_}: authorize the range first (add it to scope)")

    command = discovery_command(ws, range_)
    result = run_command(ws, command=command, tool="nmap", timeout=timeout,
                         dry_run=dry_run, scope_target=range_)

    summary: dict = {
        "range": range_, "command": command, "dry_run": dry_run,
        "returncode": result.returncode, "timed_out": result.timed_out,
        "hosts": [], "created": [], "existing": [],
    }
    if dry_run:
        return summary

    hosts = parse_live_hosts(result.stdout)
    created: list[str] = []
    existing: list[str] = []
    for host in hosts:
        # Defense in depth: only add a host that really falls inside an authorized
        # scope entry (it does — it came from a scoped range — but never trust the
        # parse alone to widen scope).
        allowed, _ = target_in_scope(host, ws.scope)
        if not allowed:
            continue
        (existing if ws.get_target(host) else created).append(host)
        ws.add_target(host)

    summary["hosts"] = hosts
    summary["created"] = created
    summary["existing"] = existing
    ws.record_run(
        "nmap", command, [],
        target="", surface="sweep", sweep=True, range=range_,
        returncode=result.returncode, timed_out=result.timed_out,
        dry_run=False, stdout=str(result.stdout_path), stderr=str(result.stderr_path),
        duration_ms=result.duration_ms,
        discovered=len(hosts), created=len(created),
    )
    ws.save()
    return summary


__all__ = ["DISCOVERY_COMMAND", "discovery_command", "parse_live_hosts", "run_sweep"]
