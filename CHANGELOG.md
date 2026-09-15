# Changelog

All notable changes to obol are recorded here. Agents must update this file
for every user-facing, code, pack, parser, runner, report, or documentation build.

## Unreleased

### Added

- Started the payload staging & tool-provisioning layer (§8), with a design contract
  in `docs/PAYLOAD_STAGING.md` (posture: enum material auto-runs behind one-click
  approval, exploit material is applicability-gated then stages + crafts a filled-in
  privesc command with an add-user or reverse-shell-to-obol outcome, all proof-bound
  and approval-gated). First slice: the **Kali-side material cache/provisioner**
  (`obol/provision.py`). A curated registry of stageable materials (linPEAS/winPEAS,
  linux-exploit-suggester, pspy, GodPotato/PrintSpoofer, RunasCs, SharpHound/Rubeus,
  chisel/ligolo-ng, nc64/socat) each with an OS, provisioning kind (cache-source/
  cache-binary/manual), download URL, and optional pinned sha256. A global cache under
  `$OBOL_HOME/cache/` with an index; a one-click `download()` that computes and records
  each file's sha256 (trust-on-first-use) and rejects+deletes a pinned-digest mismatch;
  `ensure()` (the "check Kali first, fetch if missing" preface every later stage/tunnel
  action calls); an operator override to register a local file for materials with no
  stable public asset; and a `scan()` inventory grouped by category. obol references
  the tools' public download URLs and never vendors the binaries (attribution in the
  module's NOTICE and `obol/packs/NOTICE.md`).
- Added `obol cache` with `list` / `get` / `use` / `rm` / `path` subcommands (terminal
  parity for the material cache), and web endpoints `GET /api/cache`, `POST
  /api/cache/get`, `POST /api/cache/use`, `POST /api/cache/rm`.
- Added the **transfer layer** (§8, second slice): `obol/staging.py` pushes a cached
  material onto a proven foothold through the one scope-enforced runner, with
  **redundancy** — a registry of transfer channels (`scp`/`wget`/`curl`/base64 over
  SSH for Linux; SMB `--put-file`, `certutil`/PowerShell pull, base64 over WinRM, and
  a guided `evil-winrm upload` for Windows) tried in a **fallback cascade** until one
  lands, with a sha256 read-back to mark the copy verified. Pull channels use a
  throwaway HTTP file server over a detected callback IP (`OBOL_LHOST`/tun0). A staged
  file is **live state, not a fact**: a new `Workspace.staged` list + SQLite `staged`
  table (upsert-by-id with `staged_added/updated/removed` events on the SSE feed),
  with a mutable status (staged/verified/failed). `obol stage <material> [host]`
  (with `--channel`, `--remote-dir`, `--dry-run`), `obol staged`, `obol unstage`, and
  web endpoints `GET /api/stage/channels`, `POST /api/run/stage`, `GET /api/staged`,
  `DELETE /api/staged`. This is the minimum §8 spine that unblocks the §6(d)/(e)
  auto-tunnel cascade's "stage the chisel/ligolo binary" step.
- Added **enum run-and-rank** (§8, third slice): `obol/enumrun.py` stages a read-only
  enumeration tool (linPEAS/winPEAS/LinEnum/linux-exploit-suggester) onto a foothold
  and runs it over the proven exec channel behind one action. Two proof-bound outputs:
  the existing `privesc.*` **lead** parsers fire on the tool's output (the run uses the
  `linux-enum`/`windows-enum` action id, so sudo rights, SUID, capabilities, and
  dangerous Windows privileges are extracted through the one parser pipeline), and a
  ranked `enum.findings` fact records the lines the tool itself flagged (known-exploit
  names, probability markers, credential hints) — **candidate leads, never proof**.
  A tool-agnostic highlight ranker (`extract_highlights`) strips ANSI, scores each line
  by its strongest signal, dedupes, and returns the top findings. PowerUp and other
  interactive tools are staged + guided, not auto-run. `obol enum <tool> [host]` and
  web `GET /api/enum/tools`, `POST /api/run/enum`.
- Added the **listener layer** (§8 fourth slice, closing the §6a reverse-shell gap):
  `obol/listeners.py` catches a reverse shell back to obol. A listener is **live
  state** (new `Workspace.listeners` + SQLite `listeners` table, status listening/
  caught/closed). `start_listener` records one and hands back the exact listen command
  (penelope default; nc/rlwrap or an msf handler as fallbacks) plus a matching
  reverse-shell payload set for the target OS; `record_catch` flips it to caught and,
  **only when given the shell's `id`/`whoami` output**, records the access fact from
  that proof and registers a live `revshell` session — never invents access from the
  listener's existence. Reverse-shell one-liners live as data
  (`obol/payloads/reverse_shells.json`), reused by the exploit tier. `obol listener
  start|catch|close|rm|list` and web `GET /api/listeners`, `POST
  /api/listener/{start,catch,close}`, `DELETE /api/listener`.
- Added the **exploit tier** (§8 fifth slice — the core of the layer): `obol/exploits.py`
  offers privilege-escalation exploits **gated on the parsed `privesc.*` lead facts**
  (SeImpersonate ⇒ GodPotato/PrintSpoofer; AlwaysInstallElevated ⇒ MSI; NOPASSWD sudo ⇒
  GTFOBins; a kernel gate ⇒ PwnKit). Applicability is declarative data (a predicate per
  registry entry), never planner branching. For an applicable exploit obol **stages the
  binary** (transfer layer) and **crafts the exact command** for a chosen **outcome** —
  add an admin **user**, a **SYSTEM shell** proof, or a **reverse shell** back to an
  obol listener — with a **cleanup note** for anything it changes. Execution is
  **approval-gated** (`--run` / `approve=true`); without approval obol only crafts for
  review. Proof-bound capture: SYSTEM/root is recorded **only from command output**, and
  an account it creates becomes a real `credential.available` (usable by `obol login`),
  never a fabricated win. `obol exploits [host]`, `obol exploit <key> --outcome
  add-user|system-shell|revshell [--user/--password/--listener] [--run]`, and web
  `GET /api/exploits`, `POST /api/exploit/plan`, `POST /api/run/exploit`.
- Added the **Access / Pivot tab** (§8 sixth slice) to the live web surface — the
  point-and-click home for staging, per the progressive-disclosure guardrail (a
  dedicated per-target tab, not the Overview). One aggregate endpoint
  (`GET /api/access`) returns the host's foothold OS, sessions, tunnels, staged
  material, listeners, eligible enum tools, applicable exploits, and cache summary; the
  tab renders foothold + listeners, one-click **Enumerate** (stage + run linpeas/winpeas
  → leads), **Escalate** (applicable exploits with craft-and-confirm, approval-gated
  execution through the runner), a staged-material list, and listener start/close. With
  this the whole §8 layer has full terminal + web parity, and tunnelling (§6d/e/f) can
  resume on a complete staging layer.
- Added a self-contained offline path graph for the static `obol web` snapshot
  (`graph.build_graph_svg`): the one-file snapshot now renders the shared graph model
  as inline SVG phase columns — no script, web font, or CDN — so its path graph works
  on an offline exam box, matching the live `obol serve` surface. Drops the previous
  CDN Mermaid embed that left the snapshot's graph blank offline.
- Added an engagement-wide redact switch the whole SPA respects: one header toggle
  sends `include_secrets=0` on every read, carried to every payload builder via a
  per-request context, so the findings roll-up, command ledger, per-target findings,
  sessions, and report all honor the same switch. Secrets still show by default (the
  single-operator localhost console product call); redaction is opt-in.
- Added the tunnels layer and a route-aware runner (§6d): `obol/tunnels.py` is a
  registry of pivot transports (ligolo-ng, sshuttle, chisel, ssh `-D`, ssh `-L`),
  each carrying its transport (transparent L3 vs SOCKS vs single-port forward), the
  foothold OS it fits, and the setup command handed to the operator. Tunnels are
  live state, not facts — recorded in `Workspace.tunnels` (a new SQLite `tunnels`
  table) with a mutable status. Bringing up a tunnel that exposes a subnet
  auto-extends the operator's scope to that subnet (tagged as pivot-authorized via
  that tunnel, retracted on removal unless a discovered target still lives there) —
  the hard scope gate is auto-populated from a proven foothold, never bypassed. The
  runner is now reachability-aware: `service.build_command` auto-prefixes
  `proxychains -q` for a host reachable only through a SOCKS tunnel and leaves a
  transparent L3 route (ligolo/sshuttle) or a directly-scoped host alone, so the
  operator never manages proxychains by hand.
- Added `obol pivots`, `obol tunnels`, and `obol tunnel open|close|rm`, plus web
  endpoints (`POST /api/run/tunnel`, `POST /api/tunnel/close`, `DELETE /api/tunnel`)
  and a Tunnels section in the target Overview's Pivot candidates card: one-click
  build a tunnel into an unscoped candidate subnet, live tunnel state with the
  proxychains flag and copyable setup command, and close/remove. The through-tunnel
  health sweep (§6e), the auto-tunnel cascade, and the topology map (§6f) build on
  this slice and remain to do.

- Surfaced post-foothold pivot candidates (§6c): a read-only projection
  (`obol/pivot.py`) lifts the already-parsed `host.multihomed`,
  `network.subnet_candidate`, and `pivot.candidate` lead facts into a single
  "where you could pivot next" view — multi-homed status and the candidate
  adjacent subnets, each tagged with whether it is already in scope (what a proven
  tunnel would auto-extend). Shown on the web target Overview (a Pivot candidates
  card), the terminal `obol overview`, the OSCP report's per-target section and
  structured report context, and grouped under a dedicated "Pivot candidates"
  category in the engagement findings roll-up. Stays proof-bound: a candidate
  subnet is a lead, never a working tunnel or an authorization.

- Added post-foothold flag capture: a thorough, non-interactive search for the
  well-known flag files (`user.txt`, `root.txt`, `local.txt`, `proof.txt`,
  `flag.txt`) run through the existing SSH/WinRM proof channel once a foothold is
  proven (`flag-hunt-linux`, `flag-hunt-windows` in the new
  `obol_flag_hunt_2026_09` pack), gated on a proven foothold + credential and
  routed through the one runner/parser/store path.
- Added a proof-bound flag parser (`obol/flags.py`) that records an `objective.*`
  fact (`objective.local_flag` / `objective.root_flag` / `objective.flag`,
  host-scoped) only when a flag file was actually read and its content looks like a
  real flag (hex, brace-format, or a lone short token), citing the command that
  captured it — a captured flag is proof, not a checkbox.
- Added an `objective` finding category so captured flags appear in the engagement
  findings roll-up, the report, and the evidence-by-category chart.
- Added per-target captured-flag display on the web engagement screen: each target
  card shows a flag count pill and the captured flag values, fed by a new `flags`
  list in the per-target report rollup.
- Added flag-capture parser regressions covering local/root capture, Windows
  marker output, action-id scoping, empty/unreadable output, non-flag filenames,
  de-duplication, value-extraction boundaries, and the per-target rollup.
- Added roadmap item 10 (credential-material harvesting): a Charon-inspired,
  proof-bound share/loot sweep that extracts and OCRs documents (including scanned
  PDFs) and returns ranked likely credential candidates.

- Added post-foothold host/network enumeration actions for Linux and Windows
  footholds, gated on proven shell/session facts and routed through the existing
  runner/parser/store path.
- Added `sshpass` to the tool inventory so Linux post-foothold SSH enum actions
  have install/preflight parity with the rest of the Tools page.
- Added pivot-candidate parsing for Linux `ip`/resolver output and Windows
  `ipconfig`/`route`/`arp`/`netstat` output, producing narrow facts for interfaces,
  IPs, routes, neighbors, DNS servers, listening sockets, multi-homed hosts, and
  candidate adjacent subnets without claiming a working tunnel.
- Added parser regressions for Linux and Windows local network enumeration and
  pivot-candidate overclaim boundaries.
- Added Orange-derived Linux and Windows privilege-escalation packs generated from
  the prior obol methodology lanes, with OS/foothold gates and lead-specific abuse
  paths.
- Added post-foothold privesc parsers for proof-bound local enum facts, including
  sudo rights, SUID/SGID candidates, Linux capabilities, writable `/etc/passwd`,
  NFS `no_root_squash`, LXD/Docker group leads, dangerous Windows privileges,
  AlwaysInstallElevated, unquoted service paths, weak service permissions, stored
  credential leads, host kernel/version, and host architecture.
- Added first-class privesc visibility in host Useful Facts, host Findings,
  engagement Activity, reports, charts, and the escalation phase of the path graph.
- Added evidence-backed host OS awareness with `host.os_hint` and `host.os_family`
  facts from nmap, NetExec, SNMP, WinRM/RDP/SSH proof output, Penelope shell
  output, and selected service banners.
- Added OS-aware action eligibility: unknown OS remains permissive, but proven
  Linux hosts hide Windows-only actions and proven Windows hosts hide Linux-only
  actions.
- Surfaced target OS family in `obol overview`, the web target cards, target
  overview, engagement map subtitles, Useful facts, and generated reports.
- Added changelog discipline: `AGENTS.md` points agents here, and the test suite
  checks that meaningful repo changes include a `CHANGELOG.md` update.
- Added pass-the-hash logins to the sessions layer: a dumped SAM/NTDS NT hash
  (`hash.ntlm` entries) or a validated credential carrying an `nthash` now logs in
  over WinRM (`nxc winrm -H` proof → `evil-winrm -H` handoff) and RDP via Restricted
  Admin, with no cracking. `eligible_sessions`/`open_session` auto-pick a password
  when one exists and otherwise fall back to pass-the-hash, preferring an
  Administrator hash and skipping machine accounts and `krbtgt`.
- Added `obol login --method password|pth` and a web login `method` so the operator
  can force either auth method; the web Access & sessions card surfaces
  "pass-the-hash".

### Changed

- Fixed the engagement-map credential model: the map now draws one node per distinct
  `(user, domain)` credential and a credential→host edge only where a fact ties them
  (a host-scoped credential fact, or a session logged in as that user) instead of one
  credential node glued to every foothold host; a credential links only to its own
  domain, with no arbitrary domain fallback.
- Fixed an exam-flow ranking nit: quiet AS-REP roasting now ranks above the noisy,
  lockout-risky password spray off a user list (an importer exam-flow override, since
  spraying produces a validated credential the weight table would otherwise score
  higher). Regenerating the AD pack keeps the new order.
- Local privilege escalation leads now unlock their matching abuse cards without
  claiming admin/root/SYSTEM unless command output explicitly proves it.
- Validated-credential recording is now hash-aware: a `user:<hash>` NetExec auth
  line or an `evil-winrm -H` login is recorded as an `nthash` (`method: pth`) rather
  than mislabeled as a plaintext password, and the chosen credential is pinned into
  session proof/login commands via a template `context` override so the exact hash
  is used instead of whichever credential sorts first.
- Parser fixture expectations now include OS facts where the existing transcripts
  already contain strong OS evidence.

## 2026-09-15 - Backfilled Project History

### Added

- Added the SQLite-backed engagement store (`.obol/state.db`) with WAL-friendly,
  targeted writes so terminal and web surfaces can share one state safely.
- Added the live localhost web surface with token gating, run-from-site, SSE
  change-feed updates, morphdom DOM patching, per-target tabs, tool palette,
  playbooks, findings, evidence, command ledger, and report view.
- Added `obol debug package` and `obol debug capture` for review bundles with
  state, facts, run output, reports, environment/tool inventory, and optional
  screenshots.
- Added the multi-target engagement library, scope management, target management,
  per-target fact views, and engagement-level state.
- Added scope-authorized discovery sweeps that find live hosts, create targets,
  and run the safe Quick Start baseline against newly discovered hosts.
- Added the scan-populated engagement map with scope ranges, discovered targets,
  domains, services, and BloodHound overlay links grounded in evidence.
- Added terminal parity for practical operator flow: `obol --help`, `obol help`,
  `obol manual`, `obol --version`, `obol info`, `obol scope paste`, `obol scan`,
  and `obol overview`.
- Added the engagement-level Activity view with live sweep/Quick Start jobs,
  cross-host findings roll-up, host filters, and command ledger.
- Added `obol findings` as a terminal findings roll-up with category grouping,
  host/domain origins, source command lineage, and optional redaction.
- Added command composer and run preflight behavior so web run buttons show command
  variants, missing inputs, tool availability, parser coverage, and run feedback.
- Added the visible per-target Quick Start button and background Quick Start jobs
  with step status, command previews, parsed facts, and SSE updates.
- Added the first sessions layer: one-click WinRM, SSH, and RDP login handoff
  paired with non-interactive proof commands that establish access facts before
  recording live session state.
- Added OSCP-style Markdown report generation and the shared structured report
  context used by the web report interface.
- Added screenshot and evidence attachment support for per-target report material.
- Added playbooks as data (`ad-recon`, `web-recon`) with per-step command plans,
  shared runner/parser/store execution, and noisy-step approval gates.
- Added the Orange Cyberdefense 2025.03 AD pack and the sibling web pack exported
  from the prior obol methodology data.
- Added parser coverage for early nmap, NetExec, LDAP, SMB, curl/whatweb, SNMP,
  FTP, SSH, WinRM/RDP access proof, AS-REP/TGS material, NTLM dumps, BloodHound
  collection signals, web content discovery, vhosts, and Nikto candidate leads.
- Added the parser QA contract and a manifest-driven fixture corpus with positive,
  negative, and anti-overclaim cases.
- Added the Tools inventory with host detection, default Kali paths, install hints,
  manual path overrides, and web Tools page integration.

### Changed

- Replaced the older single-file `state.json` runtime store with SQLite as the
  source of truth; `state.json` remains an export/import/snapshot format.
- Made secrets visible by default in live operator surfaces while keeping the
  shareable debug package redacted by default.
- Tightened fact de-duplication to include scope so identical facts on different
  hosts are not silently dropped.
- Reworked the path graph into one shared projection used by terminal/report
  Mermaid output and the web phase-column SVG flow chart.
- Kept automatic enumeration conservative: Quick Start runs nmap first and then
  only safe service-aware baseline enumeration, with credential attacks, exploit
  probes, dumps, spraying, shell launchers, and privilege/loot actions outside the
  automatic starter lane.

### Fixed

- Fixed stale docs around parser confidence by documenting how parsers are created:
  hand-written, rule-based, fixture-backed, and mapped to the narrowest fact the
  output proves.
- Fixed nmap SNMP script parsing for final `|_` script lines so descriptions land
  correctly.
- Fixed stale run feedback by showing compact fact details for common parser
  payloads such as ports, services, titles, shares, banners, users, and redirects.
