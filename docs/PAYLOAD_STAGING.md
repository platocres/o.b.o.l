# Payload staging & tool provisioning (§8)

This is the design contract for obol local's staging layer — the "one-click
move-material" milestone (`docs/ROADMAP.md §8`). It was deliberately deferred until
its posture was settled; this document is that settlement. Build against it.

The lesson comes from the operator's own prior tool, Charon (`docs/SOURCES.md §3`) —
the same author owns both repos, so this is porting a proven design onto obol's
clean, Orange-grounded spine, not reverse-engineering a third party. Charon's shipped
`exploit_intel/staging.py` is review-only (it stages a local workbench and never
pushes to the target); obol goes further, by explicit operator decision, but keeps
Charon's discipline: every material is pinned and cached, every on-target action is
proof-bound, and destructive or privilege-gaining steps are approval-gated with a
cleanup note.

## Why this comes before finishing tunnelling

The auto-tunnel cascade (`ROADMAP §6d`) must "stage the chisel/ligolo binary when
it isn't already on the target." You cannot build the cascade's fallback logic
without a material-mover. So §8's **spine** — the Kali-side cache and the transfer
channel — is a hard dependency of §6(d)/(e), and it is built first. The full §8
(enum run-and-rank, listeners, crafted exploit commands) then lands before tunnelling
resumes.

## The three capabilities

Staging exposes three tiers of on-target behaviour. They differ only in how much
obol does for you after the material is on the box; all three are scope-gated and
proof-bound.

1. **Enum material** (linpeas, winpeas, PowerView, Seatbelt, PowerUp, pspy). Push,
   run behind a one-click approval, parse, and **highlight** the promising findings.
   Read-only on the target — it changes nothing — so obol may run it for you. Output
   maps to proof-bound `privesc.*` / `credential.candidate` **lead** facts, never a
   proven win.
2. **Exploit material** (GodPotato, PrintSpoofer, JuicyPotato, RoguePotato,
   SweetPotato, PrintNightmare, RunasCs, pwnkit, dirtypipe, …). obol first runs the
   **applicability check** — the offer only appears when the OS and the parsed
   `privesc.*` lead facts justify it (e.g. `SeImpersonatePrivilege` enabled ⇒
   GodPotato/PrintSpoofer; a matching build ⇒ PrintNightmare). It then stages the
   binary and **crafts the exact command**, with your values filled in, offering a
   concrete outcome:
   - **add a user** (e.g. `net user obol … /add` + `localgroup administrators`), or
   - **a reverse shell back to obol** (the payload points at an obol-managed
     listener, see below).
   Execution is **per-step approval-gated**, every target-modifying step carries a
   **cleanup note** (remove the user, kill the callback), and admin/root/SYSTEM is
   recorded **only from proof output** — never assumed from the fact that a command
   was sent.
3. **Tunnel/support material** (ligolo-ng, chisel, plink, static nc, socat). Push
   and verify, then hand off to the tunnels layer (`§6d`) to start the tunnel.

## The one-click preface: check Kali first

Before any stage / run / tunnel action, obol scans the local Kali box for the
material that action needs. If it is missing, obol offers a **one-click download**
into its cache as the precondition. This is the entry point of the whole layer:
nothing is pushed to a target that obol could not first prove it has locally.

## Cache format (Kali-side)

The materials cache lives at `$OBOL_HOME/cache/` (obol is single-operator, so one
global cache — no per-run cache like Charon). Each material is a registry entry
(`obol/provision.py`, mirroring `obol/tools.py`'s `REGISTRY`) with:

- `key`, `label`, `category`, `purpose`
- `os` — `linux` / `windows` / `multi` (which foothold it is for)
- `arch` — e.g. `amd64` (informational; encoded in the asset URL)
- `kind` — the provisioning lane:
  - `apt` / `pipx` — a normal Kali package (resolved on `PATH`, like `tools.py`)
  - `cache-source` — a script downloaded to the cache (e.g. `linpeas.sh`)
  - `cache-binary` — a pinned binary downloaded to the cache (e.g. `chisel`)
  - `manual` — operator supplies it (add a path/URL), for items with no stable
    public asset
- `url` — the download source (for `cache-*` kinds)
- `version` — the pinned release tag, or `latest` when tracking the latest release
- `sha256` — the pinned digest, **enforced** when present
- `dest` — the filename inside the cache
- `bins` — binary/script names used to detect a system-installed copy
- `license`, `source` — attribution for the item (see `obol/provision.py`'s NOTICE)

### Integrity posture (honest v1)

Every download's **actual** sha256 is computed and recorded in the cache index
(`cache/index.json`) — trust-on-first-use. When a material pins a `sha256`, a
mismatch **rejects and deletes** the download. Entries ship pinned where a stable
release digest is known; the rest track `latest` and are recorded unverified, shown
as such in the UI, with pinning left to the maintainer/operator. obol never
fabricates a digest to look pinned. An operator can also point a material at a local
file or an override URL, exactly like `tools.py`'s add-path override.

## Transfer channel selection

The transfer registry (`obol/staging.py`) resolves, per foothold OS, the best push
channel available for that host, and pairs each push with a **verify** (size/hash
readback):

- **Linux foothold:** `scp`/`sshpass` over the proven SSH channel; or a throwaway
  `python3 -m http.server` on Kali + `wget`/`curl` on the target.
- **Windows foothold:** `evil-winrm` upload over the proven WinRM channel; SMB `put`
  (`smbclient`) to a writable share; or a `certutil`/PowerShell download-cradle from
  a throwaway Kali HTTP server.

Every push runs through the **one scope-enforced runner** and the exec channel the
sessions layer (`§6a`) already proves. A staged file is **live state**
(`Workspace.staged_files`, a new SQLite table), never a Fact — the same model
decision as sessions and tunnels: a file can be deleted, a Fact cannot flip.

## Listener layer

The "reverse shell back to obol" outcome needs somewhere to send the shell, so §8
absorbs the still-open piece of `§6a` — reverse-shell listeners. `obol/listeners.py`
starts a listener on Kali as **live state** (status connecting/up/down):

- **penelope** by default (auto-upgrades the TTY), **nc/rlwrap** fallback, or an
  **msf multi/handler**.
- It watches for the callback; when a shell lands, obol records the access fact
  **from proof output** (a captured `id`/`whoami`) and registers a live
  `Workspace.sessions` entry — the shell is proven by a captured command, never by
  the raw interactive handoff.

The reverse-shell command set is its own small data file (`obol/payloads/…`) — per
OS one-liners (PowerShell, `nc`, bash `/dev/tcp`, socat, …) — reused by the exploit
tier and any future "give me a rev shell" button.

## Non-negotiables (this layer must respect all of them)

- **Scope stays a hard gate.** Push and run only touch a host with a proven foothold
  (reuses the `§6` access fact) inside authorized scope. The Kali-side download is
  local material acquisition and is not scope-gated; the push is.
- **One runner, one store.** No second runner and no second state store for staging.
- **Facts stay proof-bound.** Staged files and listeners are live state; findings
  from enum tools are `privesc.*` / `credential.candidate` **leads**; admin/root is
  recorded only from proof output; a found string is candidate material, not a
  working credential.
- **Applicability lives in pack data, not planner branching.** Which exploit is
  offered is gated on lead facts in the staging pack, never in an `if` in the planner.
- **Progressive disclosure.** All of this lands in a dedicated per-target
  **Access / Pivot tab**, not on the Overview (`ROADMAP` UX guardrails). The Overview
  keeps only a compact "you're in / here's the pivot" summary that links in.
- **Terminal parity.** Every point-and-click action has a terminal equivalent
  (`obol cache`, `obol stage`, `obol listener`, …).

## Build sequence

1. **Cache/provisioner** — the manifest, download-to-Kali, hash verify, and the
   one-click "check Kali first" preface (`obol cache`). *This document ships with it.*
2. **Transfer channel + staged-file state** — push+verify to a foothold
   (`obol stage`). Minimum that unblocks the `§6d/e` tunnel-binary staging.
3. **Enum run-and-rank** — linpeas/winpeas/PowerView push → run → parse → highlight.
4. **Listener layer** — penelope/nc/msf as live state; closes the `§6a` open item.
5. **Exploit tier** — applicability gating + command crafting (add-user /
   rev-shell-to-obol) + cleanup tracking + proof-bound capture, over the full OSCP
   tool slate.
6. **Web Access/Pivot tab** + terminal parity across the layer.

After (6), tunnelling (`§6d/e/f`) resumes with the full staging layer available to
the auto-tunnel cascade.
