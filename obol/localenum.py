"""Post-foothold local network enumeration parsers.

These parsers are the first pivot-awareness brick: once a host has a proven
foothold, O.B.O.L can run small, non-interactive OS commands and turn their
network output into narrow facts. They deliberately stop at *candidate* language:
an interface, route, ARP neighbor, or adjacent subnet is not a tunnel and not proof
that another segment is authorized or reachable through a working pivot.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Iterable

from .facts import Fact
from .scope import normalize_target

LOCAL_ENUM_ACTION_IDS = {
    "local-linux-interfaces",
    "local-linux-routes",
    "local-linux-neighbors",
    "local-linux-dns",
    "local-windows-interfaces",
    "local-windows-routes",
    "local-windows-neighbors",
    "local-windows-listeners",
}

_LINUX_INTERFACE_RE = re.compile(
    r"^\d+:\s+(?P<iface>[^\s:]+)\s+inet\s+(?P<addr>\d+(?:\.\d+){3})/(?P<prefix>\d{1,2})\b"
)
_LINUX_ROUTE_RE = re.compile(r"^(?P<dest>default|\d+(?:\.\d+){3}(?:/\d{1,2})?)\b(?P<rest>.*)$")
_LINUX_NEIGH_RE = re.compile(
    r"^(?P<addr>\d+(?:\.\d+){3})\s+dev\s+(?P<iface>\S+)(?:\s+lladdr\s+(?P<mac>[0-9a-fA-F:.-]+))?"
)
_DNS_RE = re.compile(r"^\s*nameserver\s+(?P<addr>\d+(?:\.\d+){3})\s*$", re.I)

_NXC_PREFIX_RE = re.compile(r"^(?:SMB|WINRM|WMI|RPC|SSH)\s+\S+\s+\d+\s+\S+\s+(?P<body>.*)$", re.I)
_WIN_ADAPTER_RE = re.compile(r"^\s*(?P<kind>.+?)\s+adapter\s+(?P<name>.+?):\s*$", re.I)
_WIN_IPV4_RE = re.compile(r"IPv4 Address[^:]*:\s*(?P<addr>\d+(?:\.\d+){3})", re.I)
_WIN_MASK_RE = re.compile(r"Subnet Mask[^:]*:\s*(?P<mask>\d+(?:\.\d+){3})", re.I)
_WIN_GATEWAY_RE = re.compile(r"Default Gateway[^:]*:\s*(?P<gw>\d+(?:\.\d+){3})", re.I)
_WIN_DNS_RE = re.compile(r"DNS Servers[^:]*:\s*(?P<addr>\d+(?:\.\d+){3})", re.I)
_WIN_CONTINUED_IP_RE = re.compile(r"^\s+(?P<addr>\d+(?:\.\d+){3})\s*$")
_WIN_ROUTE_RE = re.compile(
    r"^\s*(?P<dest>\d+(?:\.\d+){3})\s+"
    r"(?P<mask>\d+(?:\.\d+){3})\s+"
    r"(?P<gateway>On-link|\d+(?:\.\d+){3})\s+"
    r"(?P<interface>\d+(?:\.\d+){3})\s+"
    r"(?P<metric>\d+)\s*$",
    re.I,
)
_WIN_ARP_RE = re.compile(
    r"^\s*(?P<addr>\d+(?:\.\d+){3})\s+"
    r"(?P<mac>[0-9a-fA-F:-]{11,17})\s+"
    r"(?P<state>\w+)\s*$"
)
_WIN_NETSTAT_RE = re.compile(
    r"^\s*(?P<proto>TCP|UDP)\s+"
    r"(?P<local>\S+)"
    r"(?:\s+(?P<remote>\S+)\s+(?P<state>\S+))?"
    r"(?:\s+(?P<pid>\d+))?\s*$",
    re.I,
)


def _scope(ws, target: str = "") -> str:
    host = normalize_target(target or getattr(ws, "target", "") or "")
    return f"host:{host}" if host else ""


def _emit(out: list[Fact], seen: set[tuple[str, str, str]], kind: str, scope: str, value: dict, source: str) -> None:
    if not scope:
        return
    key = (kind, scope, repr(sorted(value.items())))
    if key in seen:
        return
    seen.add(key)
    out.append(Fact(kind, scope, value, source=source))


def _network_from_interface(addr: str, prefix: str | int) -> str:
    try:
        return str(ipaddress.ip_interface(f"{addr}/{prefix}").network)
    except ValueError:
        return ""


def _network_from_mask(addr: str, mask: str) -> str:
    try:
        return str(ipaddress.ip_network(f"{addr}/{mask}", strict=False))
    except ValueError:
        return ""


def _network_from_dest(dest: str, mask: str = "") -> str:
    try:
        if mask:
            return str(ipaddress.ip_network(f"{dest}/{mask}", strict=False))
        if "/" in dest:
            return str(ipaddress.ip_network(dest, strict=False))
        return str(ipaddress.ip_network(f"{dest}/32", strict=False))
    except ValueError:
        return ""


def _interesting_network(cidr: str) -> bool:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    if net.prefixlen == 0 or net.prefixlen >= 32:
        return False
    if net.is_loopback or net.is_link_local or net.is_multicast or net.is_unspecified:
        return False
    return True


def _interesting_host(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified)


def _logical_lines(text: str) -> Iterable[str]:
    """Yield command-output lines after removing common NetExec row prefixes.

    NetExec prepends rows like ``WINRM 10.10.10.5 5985 HOST`` before command
    output. Stripping that prefix lets the Windows parsers consume the same
    shapes they would see from a direct console transcript.
    """
    for raw in text.splitlines():
        line = raw.rstrip()
        match = _NXC_PREFIX_RE.match(line)
        yield match.group("body") if match else line


def _maybe_pivot_facts(out: list[Fact], seen: set[tuple[str, str, str]], scope: str, source: str,
                       interface_networks: Iterable[str], route_networks: Iterable[str]) -> None:
    iface_nets = sorted({n for n in interface_networks if _interesting_network(n)})
    route_nets = sorted({n for n in route_networks if _interesting_network(n)})
    for cidr in sorted(set(iface_nets + route_nets)):
        _emit(out, seen, "network.subnet_candidate", scope, {"cidr": cidr}, source)

    reasons: list[str] = []
    if len(iface_nets) > 1:
        _emit(out, seen, "host.multihomed", scope, {"interfaces": len(iface_nets), "subnets": iface_nets}, source)
        reasons.append("multiple interface networks")

    # Route tables are noisy: a single connected subnet plus default route is normal
    # host context, not a pivot signal. Treat route-only output as pivot-worthy only
    # when it exposes multiple meaningful non-default networks. When interface
    # context is present, a route outside those interface networks is a stronger
    # "additional subnet" hint.
    if iface_nets:
        routed_only = [n for n in route_nets if n not in iface_nets]
    elif len(route_nets) > 1:
        routed_only = route_nets
    else:
        routed_only = []

    if routed_only:
        reasons.append("route to additional subnet")
    if reasons:
        _emit(out, seen, "pivot.candidate", scope, {"reasons": reasons, "subnets": sorted(set(iface_nets + routed_only))}, source)


def _parse_linux_interfaces(text: str, scope: str, source: str) -> list[Fact]:
    out: list[Fact] = []
    seen: set[tuple[str, str, str]] = set()
    networks: list[str] = []
    count = 0
    for line in text.splitlines():
        m = _LINUX_INTERFACE_RE.search(line.strip())
        if not m:
            continue
        iface = m.group("iface").split("@", 1)[0]
        addr = m.group("addr")
        prefix = int(m.group("prefix"))
        cidr = f"{addr}/{prefix}"
        network = _network_from_interface(addr, prefix)
        count += 1
        if network:
            networks.append(network)
        _emit(out, seen, "host.interface", scope, {"name": iface, "address": addr, "cidr": cidr, "network": network, "family": "ipv4"}, source)
        _emit(out, seen, "host.ip_address", scope, {"address": addr, "cidr": cidr, "interface": iface, "network": network}, source)
    if count:
        _emit(out, seen, "scan.local.interfaces", scope, {"os": "linux", "count": count}, source)
        _maybe_pivot_facts(out, seen, scope, source, networks, [])
    return out


def _parse_linux_routes(text: str, scope: str, source: str) -> list[Fact]:
    out: list[Fact] = []
    seen: set[tuple[str, str, str]] = set()
    networks: list[str] = []
    count = 0
    for raw in text.splitlines():
        line = raw.strip()
        m = _LINUX_ROUTE_RE.search(line)
        if not m:
            continue
        dest = m.group("dest")
        rest = m.group("rest") or ""
        via = _search_value(rest, r"\bvia\s+(\S+)")
        dev = _search_value(rest, r"\bdev\s+(\S+)")
        src = _search_value(rest, r"\bsrc\s+(\d+(?:\.\d+){3})")
        network = "0.0.0.0/0" if dest == "default" else _network_from_dest(dest)
        count += 1
        if network:
            networks.append(network)
        _emit(out, seen, "host.route", scope, {"destination": dest, "cidr": network, "via": via, "interface": dev, "src": src}, source)
    if count:
        _emit(out, seen, "scan.local.routes", scope, {"os": "linux", "count": count}, source)
        _maybe_pivot_facts(out, seen, scope, source, [], networks)
    return out


def _parse_linux_neighbors(text: str, scope: str, source: str) -> list[Fact]:
    out: list[Fact] = []
    seen: set[tuple[str, str, str]] = set()
    count = 0
    for line in text.splitlines():
        m = _LINUX_NEIGH_RE.search(line.strip())
        if not m:
            continue
        addr = m.group("addr")
        if not _interesting_host(addr):
            continue
        count += 1
        _emit(out, seen, "host.arp_neighbor", scope, {
            "address": addr,
            "interface": m.group("iface"),
            "mac": (m.group("mac") or "").replace("-", ":").lower(),
        }, source)
    if count:
        _emit(out, seen, "scan.local.neighbors", scope, {"os": "linux", "count": count}, source)
    return out


def _parse_dns(text: str, scope: str, source: str, os_name: str) -> list[Fact]:
    out: list[Fact] = []
    seen: set[tuple[str, str, str]] = set()
    count = 0
    for line in text.splitlines():
        m = _DNS_RE.search(line)
        if not m:
            continue
        addr = m.group("addr")
        if not _interesting_host(addr):
            continue
        count += 1
        _emit(out, seen, "host.dns_server", scope, {"address": addr}, source)
    if count:
        _emit(out, seen, "scan.local.dns", scope, {"os": os_name, "count": count}, source)
    return out


def _parse_windows_interfaces(text: str, scope: str, source: str) -> list[Fact]:
    out: list[Fact] = []
    seen: set[tuple[str, str, str]] = set()
    networks: list[str] = []
    current = ""
    pending_ip = ""
    dns_pending = False
    count = 0

    def flush_ip(ip: str, mask: str = "") -> None:
        nonlocal count
        if not ip or not _interesting_host(ip):
            return
        network = _network_from_mask(ip, mask) if mask else ""
        cidr = ""
        if network:
            networks.append(network)
            prefix = ipaddress.ip_network(network, strict=False).prefixlen
            cidr = f"{ip}/{prefix}"
        count += 1
        _emit(out, seen, "host.interface", scope, {"name": current or "unknown", "address": ip, "cidr": cidr, "network": network, "family": "ipv4"}, source)
        _emit(out, seen, "host.ip_address", scope, {"address": ip, "cidr": cidr, "interface": current or "unknown", "network": network}, source)

    for line in _logical_lines(text):
        adapter = _WIN_ADAPTER_RE.search(line)
        if adapter:
            current = adapter.group("name").strip()
            pending_ip = ""
            dns_pending = False
            continue
        m = _WIN_IPV4_RE.search(line)
        if m:
            pending_ip = m.group("addr")
            dns_pending = False
            continue
        m = _WIN_MASK_RE.search(line)
        if m and pending_ip:
            flush_ip(pending_ip, m.group("mask"))
            pending_ip = ""
            dns_pending = False
            continue
        m = _WIN_GATEWAY_RE.search(line)
        if m:
            _emit(out, seen, "host.route", scope, {"destination": "default", "cidr": "0.0.0.0/0", "via": m.group("gw"), "interface": current}, source)
            dns_pending = False
            continue
        m = _WIN_DNS_RE.search(line)
        if m:
            _emit(out, seen, "host.dns_server", scope, {"address": m.group("addr"), "interface": current}, source)
            dns_pending = True
            continue
        if dns_pending:
            m = _WIN_CONTINUED_IP_RE.search(line)
            if m:
                _emit(out, seen, "host.dns_server", scope, {"address": m.group("addr"), "interface": current}, source)
                continue
            dns_pending = False

    if pending_ip:
        flush_ip(pending_ip)
    if count:
        _emit(out, seen, "scan.local.interfaces", scope, {"os": "windows", "count": count}, source)
        _maybe_pivot_facts(out, seen, scope, source, networks, [])
    dns_count = sum(1 for f in out if f.kind == "host.dns_server")
    if dns_count:
        _emit(out, seen, "scan.local.dns", scope, {"os": "windows", "count": dns_count}, source)
    return out


def _parse_windows_routes(text: str, scope: str, source: str) -> list[Fact]:
    out: list[Fact] = []
    seen: set[tuple[str, str, str]] = set()
    networks: list[str] = []
    count = 0
    for line in _logical_lines(text):
        m = _WIN_ROUTE_RE.search(line)
        if not m:
            continue
        network = _network_from_dest(m.group("dest"), m.group("mask"))
        count += 1
        if network:
            networks.append(network)
        _emit(out, seen, "host.route", scope, {
            "destination": m.group("dest"),
            "netmask": m.group("mask"),
            "cidr": network,
            "via": m.group("gateway"),
            "interface": m.group("interface"),
            "metric": int(m.group("metric")),
        }, source)
    if count:
        _emit(out, seen, "scan.local.routes", scope, {"os": "windows", "count": count}, source)
        _maybe_pivot_facts(out, seen, scope, source, [], networks)
    return out


def _parse_windows_neighbors(text: str, scope: str, source: str) -> list[Fact]:
    out: list[Fact] = []
    seen: set[tuple[str, str, str]] = set()
    count = 0
    for line in _logical_lines(text):
        m = _WIN_ARP_RE.search(line)
        if not m:
            continue
        addr = m.group("addr")
        if not _interesting_host(addr):
            continue
        count += 1
        _emit(out, seen, "host.arp_neighbor", scope, {
            "address": addr,
            "mac": m.group("mac").replace("-", ":").lower(),
            "state": m.group("state").lower(),
        }, source)
    if count:
        _emit(out, seen, "scan.local.neighbors", scope, {"os": "windows", "count": count}, source)
    return out


def _parse_windows_listeners(text: str, scope: str, source: str) -> list[Fact]:
    out: list[Fact] = []
    seen: set[tuple[str, str, str]] = set()
    count = 0
    for line in _logical_lines(text):
        m = _WIN_NETSTAT_RE.search(line)
        if not m:
            continue
        local = m.group("local") or ""
        if ":" not in local:
            continue
        host, port = local.rsplit(":", 1)
        try:
            port_int = int(port)
        except ValueError:
            continue
        state = (m.group("state") or ("LISTENING" if m.group("proto").upper() == "UDP" else "")).upper()
        if state and state != "LISTENING":
            continue
        count += 1
        _emit(out, seen, "host.listen_socket", scope, {
            "protocol": m.group("proto").lower(),
            "address": host.strip("[]"),
            "port": port_int,
            "pid": int(m.group("pid")) if (m.group("pid") or "").isdigit() else None,
        }, source)
    if count:
        _emit(out, seen, "scan.local.listeners", scope, {"os": "windows", "count": count}, source)
    return out


def _search_value(text: str, pattern: str) -> str:
    match = re.search(pattern, text)
    return match.group(1) if match else ""


def parse_local_enum_output(action, ws, command: str, stdout: str, stderr: str = "", *, source: str = "") -> list[Fact]:
    """Parse post-foothold host/network enum output into narrow facts.

    This is intentionally action-id scoped so generic command output elsewhere does
    not accidentally become pivot evidence.
    """
    action_id = getattr(action, "id", "")
    if action_id not in LOCAL_ENUM_ACTION_IDS:
        return []
    scope = _scope(ws)
    if not scope:
        return []
    text = "\n".join(part for part in (stdout or "", stderr or "") if part)
    src = source or command
    if not text.strip():
        return []

    if action_id == "local-linux-interfaces":
        return _parse_linux_interfaces(text, scope, src)
    if action_id == "local-linux-routes":
        return _parse_linux_routes(text, scope, src)
    if action_id == "local-linux-neighbors":
        return _parse_linux_neighbors(text, scope, src)
    if action_id == "local-linux-dns":
        return _parse_dns(text, scope, src, "linux")
    if action_id == "local-windows-interfaces":
        return _parse_windows_interfaces(text, scope, src)
    if action_id == "local-windows-routes":
        return _parse_windows_routes(text, scope, src)
    if action_id == "local-windows-neighbors":
        return _parse_windows_neighbors(text, scope, src)
    if action_id == "local-windows-listeners":
        return _parse_windows_listeners(text, scope, src)
    return []


__all__ = ["LOCAL_ENUM_ACTION_IDS", "parse_local_enum_output"]
