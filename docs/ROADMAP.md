# Roadmap & status

Priority order. Item 1 is what the tool most needs to become usable on a live box.

## Done

- **Architecture: SQLite store + live SSE deltas + morphdom UI + debug package.**
  The durable store is SQLite (`obol/store.py`, `.obol/state.db`) so the terminal and
  web can both write without clobbering; the web SSE loop tails an `events` change
  feed and the browser patches the DOM with morphdom via delegated handlers; and
  `obol debug package` / `obol debug capture` bundle a review `.zip` (state, events,
  facts, ledger + raw output, report, tools/env, terminal renders, site snapshot, and
  optional screenshots). See `docs/ARCHITECTURE.md` and `docs/DEBUG.md`.
- **Vertical slice** (PR #1's base): fact model, planner, terminal board, read-only
  web view + mermaid path graph, `explain`, tests.
- **Multi-target engagement platform:** an app-managed engagement library
  (`obol/library.py`, `$OBOL_HOME`) of engagements, each holding many targets
  (`workspace.targets`, per-target fact scoping via `facts_for_target`). The web is
  a tabbed per-target console (Overview with an attack-chain bar + per-target path,
  a service-aware point-and-click Tools palette, Playbooks, a static Checklist,
  Findings, Evidence/screenshots, Commands), plus an engagement-wide map that
  stitches scope, targets, domains, services, and a **BloodHound** overlay
  (`obol/bloodhound.py`). Per-target findings and evidence roll up into the report.
  `obol engagement` / `obol target` manage it from the terminal.
- **Robust web surface (item 5, largely done):** localhost FastAPI app
  (`obol/webapp/`, optional `web` extra) that mirrors AND drives the one `.obol`
  store — run-from-site for actions and playbook steps through the shared
  `service.py`, real-time SSE sync across surfaces, a phase-column SVG flow chart
  from `graph.build_graph_model`, findings charts (vendored Chart.js), and the
  report as its main interface. See item 5 for the one remaining piece.
- **Orange AD pack** (30 Orange-derived actions plus 3 local nmap prelude actions)
  driving the planner; proof boundaries test-locked. See `docs/SOURCES.md`.
- **init robustness**: friendly error on an unwritable/`sudo`-owned directory;
  workspace-vs-source-tree guidance.
- **First real run loop slice**: scoped target workspaces, fixed-argv runner,
  dry-run, raw output capture under `.obol/runs/`, nmap-first TCP discovery,
  targeted `-Pn -sC -sV` follow-up from parsed ports, generic nmap/nxc/LDAP/AS-REP
  parsers, and key findings in the read-only web view.
- **OSCP report generation** (item 4): `obol report` narrated from the run ledger,
  facts, and evidence lineage, with secret redaction by default.
- **Playbooks — terminal slice** (item 5, first piece): named, ordered sequences of
  pack actions as data (`obol/playbooks/*.json`), run through the same
  runner/parser/store via `obol playbooks` / `obol playbook <name>[ --step N]`, with
  per-step `require_approval` gating. First playbook: `ad-recon`. Web
  run-from-site and the playbook path-map view are still pending under item 5.

## 0. Engagement-level discovery sweep + scope UI + host grouping (DONE)

An operator should be able to point obol at a network, sweep it, and watch
targets populate — names, services, and domain grouping filling in as
enumeration proceeds — without hand-adding a single host. Modeled on Pentest
Companion's auto-scan orchestrator (`tools/auto_orchestrator.py`: an nmap-first
pass, then a service→tool rule table drives follow-up enumeration) and its host
tooling (`docs/SOURCES.md §5`). Everything below still runs through the one
scope-enforced runner and the one store — no second engine.

The build sequence (each a reviewable PR):

- **(a) Scope in the web app — DONE.** `GET/POST/DELETE /api/scope` over
  `Workspace.scope`; the overview shows a Scope panel where the operator
  authorizes hosts and CIDR ranges. Scope is the runner's hard authorization
  gate (`obol/scope.py`), so it is also the precondition for a sweep: obol will
  only sweep a range the operator has put in scope. `normalize_scope_entry`
  keeps genuine CIDRs verbatim and reduces hosts/URLs/`host:port` to a bare host;
  a live target's own scope entry can't be removed out from under it.
- **(b) Engagement discovery sweep — DONE.** `obol/discovery.py`: an nmap
  host-discovery pass (`-sn` with TCP-SYN/ACK + ICMP + a UDP NetBIOS probe so
  ICMP-filtered AD hosts like Forest are still found — *not* a bare ping sweep)
  over an authorized scope range, run through the one scope-enforced runner. It
  parses live hosts and auto-creates a target for each via `ws.add_target`. The
  runner's new `scope_target` gate requires the swept range to be an authorized
  scope *entry* (an exact-entry check, stricter than host membership), so a sweep
  can never touch a range the operator has not scoped. Web: a **Sweep** button on
  each CIDR scope entry runs it as a background job (`POST /api/run/sweep`,
  `GET /api/sweep/jobs/{id}`); new targets stream into the page live over the
  existing `target_added` SSE feed. Terminal parity: `obol sweep <range>`.
- **(c) Per-host enumeration fan-out — DONE.** After discovery, the sweep runs
  the service-aware Quick Start baseline against each newly created host, one at a
  time, through the existing Quick Start engine (same runner/parser/store) — nmap
  service scan, then the nxc SMB/LDAP + safe baseline the packs gate. Each host's
  run is a normal Quick Start job, so its steps and facts stream to the page live;
  a re-sweep never re-enumerates existing targets. `POST /api/run/sweep` takes
  `enumerate` (default true; `false` = discovery only). This surfaced and fixed a
  real multi-target bug: `FactSet.add` deduped by `(kind, value)` and dropped one
  host's fact when two targets produced an identical baseline finding (e.g.
  `port:445`) — it now dedups by `(kind, scope, value)`, matching the store's key.
- **(d) Target enrichment + engagement map — DONE.** Parsers map nmap/nxc/LDAP
  hostname, FQDN, and domain output back to the host that produced it. Discovery
  also preserves rDNS names from `nmap -sn`. `Workspace` stores `hostname`,
  `fqdn`, and `domain` on each target, upgrades raw IP labels when identity is
  found, and preserves operator-provided labels. Store migration adds those
  target identity columns. The web groups targets by domain and the engagement
  map now populates from scans: authorized scope ranges link to matching targets,
  targets link to domains only when host-scoped evidence supports it, and open
  ports/services render as service nodes.
- **(e) Engagement-level run & findings view — DONE.** A dedicated **Activity**
  view (`GET /api/engagement/activity`) surfaces work at the *engagement* level,
  not just per-target: a **live run feed** of every sweep and per-host Quick Start
  job (in-flight and recent, with step progress), a **findings roll-up** that
  groups every proven fact across all hosts by category and tags each with the
  host (or domain) that produced it and its cited evidence, and a cross-host
  **command ledger**. It repaints on the same SSE change feed as the rest of the
  page, and starting a sweep drops the operator here to watch it run. Proof-bound
  like everywhere else (only `supported` facts, secrets redacted); the host filter
  chips read from per-host fact counts. The Quick Start job engine was already
  engagement-bound — this is the organization/aesthetic layer over it.
- **(f) Terminal parity for scope + scan — DONE.** `obol --help` now exposes the
  practical flow, with `obol help <command>`, `obol manual`, `obol --version`, and
  `obol info` for normal CLI discovery. `obol scope add` accepts multiple entries,
  `obol scope paste` extracts only valid IPs/CIDRs from messy copied text or
  stdin, and `obol scope rm` removes entries without pulling scope from live
  targets. `obol scan` sweeps every authorized scope entry and then runs the same
  nmap-first Quick Start baseline for scoped targets from the terminal. `obol
  overview` gives a compact terminal engagement view: scope, targets, identity,
  domain, access/phase, ports, and top next moves.

Non-negotiables this must respect: the sweep only touches authorized scope
(hard gate); discovery/enumeration facts stay proof-bound (a live host and its
open ports are *not* access, creds, or a foothold); one runner, one store; and
no "blocked/proves" language in the UI (roadmap "UX guardrails" below).

## 1. Expand parser coverage and service-specific playbooks (TOP PRIORITY)

`run` is no longer a pure stub, but execution is only real where parser coverage
exists. The current spine is:

- `obol init --target <ip>`
- quick nmap all-port discovery
- targeted `nmap -Pn -sC -sV -p {{nmap_ports}}`
- port/service facts unlock AD moves
- LDAP/389 leads to `nxc ldap` and `ldapsearch`

Next work should widen this carefully:

- **More service parsers — PARTLY DONE.** Generic parser coverage now includes SMB
  shares/sessions, WinRM/RDP/SSH/FTP service authentication, HTTP metadata
  (curl/whatweb), FTP/SSH banners, SNMP walk/check output, and common nmap service
  script findings for SSH host keys, FTP anonymous login, SNMP info, HTTP redirects,
  and technology fingerprints. Continue with exploitation-card success signals,
  privesc/pivot outputs, and more real-tool fixtures. Every parser must map output
  to the narrowest fact and include anti-overfit tests.
- **Better port-to-playbook gating.** The Orange AD pack now has a small exam-flow
  priority override for nmap → DC identify → anonymous LDAP → user enum. Extend
  that idea across web/privesc sibling packs without hardcoding box wins.
- **Parser fixtures from real tools: FIRST CORPUS DONE.** `docs/PARSER_QA.md`
  documents how parsers are written and judged. `tests/fixtures/parser/` now has
  a manifest-driven fixture corpus covering nmap metadata, curl/whatweb HTTP
  metadata, NetExec SSH/FTP auth, failed auth, SSH banner vs shell proof, SNMP
  timeout, and FTP named-login edge cases. Continue adding anonymized Forest and
  other lab outputs as golden regressions, but never as recipes. Fixture names
  should vary so tests prove shape recognition, not walkthrough memorization.
- **Service-specific next moves.** If `389` is open, prefer NetExec LDAP and
  ldapsearch. If `445` is open, prefer nxc SMB/null/guest/RID paths. If HTTP ports
  exist, unlock web enumeration once the web pack exists.

## 2. Exam-flow ranking beyond the first AD spine

The first nmap/LDAP flow has explicit ordering, but most priorities are still
derived from the produced fact's "value" in `scripts/import_orange_ad.js`. Add a
proper phase/flow model so recon and low-risk enumeration sort before high-value
but premature branches across every pack.

## 3. Sibling packs (web, privesc, pivoting, cracking, …)

Export the remaining prior-obol lanes into packs using the AD converter as the
template (`docs/SOURCES.md` §2). Order by OSCP value: `web` (23) and
`linux-privesc`/`windows-privesc` next, since OSCP is not AD-only. Each pack must
reuse the shared fact-kind namespace so cross-domain gating works (e.g. a web
foothold producing `foothold.linux` unlocks the privesc pack).

- **`web` (23) — DONE.** `obol/packs/orange_web_2025_03.json` via
  `scripts/import_orange_web.js`; the planner merges packs (`pack.load_packs`), so
  an HTTP port unlocks web recon after the nmap spine. Fact kinds are remapped onto
  the shared namespace and kept to their narrowest claim. Recon parsers
  (content discovery, vhosts, nikto) landed; the exploitation cards remain
  explain-only until their success-signal parsers exist.
- **`linux-privesc` (12) and `windows-privesc` (10) — DONE.**
  `obol/packs/orange_linux_privesc_2025_03.json` and
  `obol/packs/orange_windows_privesc_2025_03.json` via
  `scripts/import_orange_privesc.js`. A proven foothold unlocks OS-matched local
  enum; parsed `privesc.*` lead facts unlock the specific abuse cards they justify;
  admin/root/SYSTEM is recorded only from proof output. Privesc findings surface on
  host pages, engagement Activity, reports, and the escalation phase of the graph.
  Next pack lanes: `pivoting`, `cracking`, `shells`, `database`, and the remaining
  support lanes.

## 4. OSCP report generation

`obol report` narrated from the run ledger (`Workspace.runs`) + facts + lineage
(`Fact.source`). The activity ledger already preserves sequence, so the report
comes largely free. Reuse the single graph projection (`graph.py`) for the report's
path diagram. Output markdown first; the report must cite evidence (each claim →
the command/output that produced it) and must never present project metadata as
engagement proof.

## 5. Robust web surface — run-from-site, playbooks, path-map redesign

**LARGELY DONE.** The web view is now a real second surface (`obol/webapp/`, a
localhost FastAPI app behind the optional `web` extra), modeled on PentOS and
Pentest Companion (`docs/SOURCES.md`). It reuses the *same* scope-enforced runner +
parsers + `.obol` store as the terminal, via the shared `obol/service.py`.

- **Run from the site — DONE.** The web launches an action or playbook step by
  action id; the server fills the command from workspace facts and runs it through
  `service.run_action` (same runner/parser/store), so both surfaces reflect it.
  Secrets never travel to the browser. Localhost-bound + per-start access token.
- **Real-time — DONE.** `/api/events` (SSE) tails the store's `events` change feed and
  pushes *what changed* (new facts/runs/targets) — web- OR terminal-launched — as a
  JSON payload. The browser patches only the affected DOM with morphdom (vendored, no
  build step) via one delegated `data-act` handler, so a live refresh keeps scroll,
  focus, and charts. See `docs/ARCHITECTURE.md`.
- **Playbooks (both surfaces) — DONE.** The web renders each playbook's plan and
  runs steps through the shared service, with the same `require_approval` gate
  (a confirm on the web, a 409 from the API without approval).
- **Path-map redesign — DONE.** `graph.py` now emits a structured model
  (`build_graph_model`) with an engagement `phase` per node; the web draws it as an
  SVG flow chart grouped into phase columns (recon → enum → creds → access →
  escalate → loot) — the phase/lane progression the prior obol used. Mermaid
  (terminal/report) renders from the same model.
- **Findings charts + report interface — DONE.** Overview charts evidence by
  category and finding severity (Chart.js, vendored locally — no CDN); the Report
  view is the primary report interface (stat row, progress ladder, path, severity-
  badged next steps, evidence with lineage, timeline) with a Markdown download and
  a secrets toggle. `report.build_report_context` is the shared structured source.
- **Tool availability — DONE** (from Pentest Companion `kali_tools`/`tools_status`):
  `obol/tools.py` is a curated registry of the tools the packs invoke; the web Tools
  page scans the host (`which` + default Kali paths + shallow auto-locate), shows a
  found/total counter, greys out the missing with one-click Install (apt/pipx) or an
  add-path override, and runs any available tool against a chosen target. The runner
  resolves found/added tools so a "found" tool is guaranteed to launch.

## 6. Pivoting, sessions & tunnels (recursive segment mapping)

The lab-speed feature set, borrowed from the operator's Charon (`docs/SOURCES.md
§3` — learn from it, reimplement; do not copy code). Turns obol from a
single-segment enumerator into a **recursive network-segment mapper**: reach a
host, prove a shell, enumerate it, pivot, and re-run discovery *through* the pivot
— each tunnel a hop. Every step still runs through the one scope-enforced runner
and the one store, and stays proof-bound: a shell, a second NIC, and a reachable
subnet are each their own narrow fact.

**How §6, §7, and item 3 interlock (read this — build them aware of each other):**
these three are one milestone seen from three angles, joined by the access fact.
§6(a)'s login produces an `access.*`/`foothold.*` fact; that same fact (1) **gates
item 3**, the privesc packs, which only go live once you have a shell to escalate
from, and (2) is the precondition for §7's **flag capture**, which needs a shell to
read `proof.txt`/`root.txt`. §7's **engagement profile** (platform/exam type) in
turn colors §6 and item 3 — the machine_type nudges which login/privesc moves rank
first, and the platform says which flag a post-foothold enum should hunt. So the
natural build order is **§6(a) sessions → item 3 privesc → §7 flags**, and none of
them should invent its own notion of "you're on the box": they all read the one
access fact. Later §6 (host enum → multi-homed → tunnels → through-tunnel sweep)
then recurses the whole loop onto the next segment.

Two model decisions fixed up front:

- **Sessions and tunnels are LIVE STATE, not facts.** A tunnel can go down; a Fact
  is immutable proven evidence and must never flip. So an active session/tunnel is
  engagement runtime state carrying a status (connecting/up/down), **probed
  periodically** so the UI reflects reality; only the *discoveries* it leads to
  (`host.multihomed`, a reachable subnet) are facts. Never store a tunnel as a Fact.
- **A proven pivot AUTO-EXTENDS scope.** When a tunnel comes up exposing subnet X,
  obol auto-adds X to scope, **tagged** as pivot-authorized-via-tunnel-T (visibly
  distinct from operator-typed scope), then auto-sweeps it. The runner's hard scope
  gate is unchanged — it is auto-populated from a proven foothold, not bypassed.
  Exam-first default; a future "engagement mode" can propose-instead-of-commit for
  real client work where reachable ≠ authorized.

The build sequence (each a reviewable PR):

- **(a) Sessions layer + one-click login — DONE.** `obol/sessions.py`: a login
  registry (winrm/ssh/rdp) with, per kind, a non-interactive **proof** command and
  the interactive **login** command. `eligible_sessions` offers a login when a
  validated credential (a password, or an NT hash for pass-the-hash) + a reachable
  service exist; `open_session` runs the
  proof through the shared `service.run_action` (same runner/parser/scope gate/
  ledger), and only once the captured output establishes the access fact
  (`foothold.windows` via `nxc winrm -x whoami`, `foothold.linux` via `sshpass … ssh
  … id`, `rdp.authenticated`+`foothold.windows` via `nxc rdp`) does it record a
  **live session** (`Workspace.sessions`, a new SQLite table; status active/dead/
  closed) and hand back the ready-to-paste interactive command. `probe_session`
  re-runs the proof to refresh status (the manual form of the periodic probe). Two
  narrow proof parsers were added (ssh `uid=` → linux shell, `uid=0` → admin; `nxc
  rdp [+]` → rdp auth, `(Pwn3d!)` → admin), reusing the existing evil-winrm/exec
  parsers for WinRM. Terminal: `obol login [host] [--kind] [--method]`, `obol
  sessions`, `obol session probe|close|rm`. Web: the target Overview has an
  **Access & sessions** card (offer buttons + live sessions with the interactive
  command), `POST /api/run/login`, `/api/session/probe|close`, `DELETE
  /api/session`. The proof keeps facts the source of truth — the shell is proven by
  a captured command, never by the unparseable interactive handoff, and this module
  produces no facts of its own.
- **(a′) Pass-the-hash logins — DONE.** Hash-only logins (`-H`) close the AD
  endgame: a dumped SAM/NTDS NT hash (`hash.ntlm` entries) or a validated
  credential carrying an `nthash` logs in over WinRM (`nxc winrm -u u -H h` proof →
  `evil-winrm -u u -H h` handoff) — and over RDP via Restricted Admin — with no
  cracking. `eligible_sessions`/`open_session` auto-pick a password when one exists,
  else pass-the-hash; the operator can force either with `obol login --method
  password|pth` (web: the login `method`). Credential recording stays honest — a
  `user:<hash>` auth line is recorded as an `nthash` (`method: pth`), never
  mislabeled as a plaintext password (`parsers._add_authenticated_service`,
  evil-winrm `-H`). The chosen credential is pinned into the proof/login command via
  a template `context` override, so the exact hash is used rather than whichever
  credential sorts first. **Still open in (a):** penelope reverse-shell
  **listeners** (an async start-and-watch flow, not a credentialed login),
  tmux/new-terminal auto-spawn (v1 is guided handoff), and the automatic periodic
  probe loop (the manual `probe` exists).
- **(b) Unlocks the privesc pack — DONE.** The `access.*`/`foothold.*` fact from (a) gates
  the `linux-privesc`/`windows-privesc` sibling packs (item 3) for that host —
  login and privesc are two halves of one milestone. The first privesc build also
  added proof-bound `privesc.*` lead parsers and host/engagement visibility.
- **(c) Post-foothold host enum — DONE.** Once on the box, obol enumerates it (NICs,
  routes, ARP, DNS) through the non-interactive SSH/WinRM exec channel and maps the
  output to narrow, proof-bound facts (`host.interface/route/arp_neighbor/dns_server`,
  `host.multihomed`, `network.subnet_candidate`, `pivot.candidate`). A read-only
  projection (`obol/pivot.py`) lifts the multi-homed status + reachable adjacent
  subnets into a single pivot-candidate lead — each subnet tagged in/out of scope —
  shown on the web target Overview (Pivot candidates card), `obol overview`/`obol
  pivots`, the report per-target section, and a dedicated "Pivot candidates" category
  in the engagement findings roll-up. Stays a lead, never a working tunnel or an
  authorization. (Guided-paste for creds-less footholds is still to do.)
- **(d) Tunnels + route-aware runner — FIRST SLICE DONE.** `obol/tunnels.py` is the
  **tunnel registry** (modeled on `tools.py`/`sessions.py`): ligolo-ng, sshuttle,
  chisel, ssh `-D`, ssh `-L`, each carrying its transport (transparent vs SOCKS vs
  single-port forward), foothold OS, privilege, and setup command. Tunnels are live
  state (`Workspace.tunnels`, a SQLite `tunnels` table, a status that can flip), not
  facts. Opening one that exposes a subnet **auto-extends scope** to that subnet
  (pivot-authorized via the tunnel, retracted on removal unless a discovered target
  lives there) — the hard scope gate is auto-populated from a proven foothold, never
  bypassed. The runner is reachability-aware: `service.build_command` auto-prefixes
  `proxychains -q` for a host reachable only via a SOCKS tunnel and leaves a
  transparent L3 route (ligolo/sshuttle) or a directly-scoped host alone. Terminal
  (`obol tunnels`, `obol tunnel open|close|rm`) and web (`/api/run/tunnel`, tunnel
  section in the Pivot candidates card) both drive it. **Still open in (d):** the
  feasibility-aware auto-tunnel cascade, on-target tooling/egress preconditions as a
  gate, and staging the tunnel binary (§8); a tunnel's status defaults to up until
  the §6e health sweep confirms it.

  - **Auto-tunnel (the cascade + the guarantee).** Working name "auto-tunnel" (could
    also be "tunnel autopilot" / "best-effort pivot" — settle when built). Beyond
    picking a tunnel by hand, an auto mode walks the registry in preference order
    (ligolo → chisel → sshuttle → ssh `-L`/`-D` → …) and, for each, tries the variant
    feasible **here**, falling back on failure until one stands up AND passes a
    connectivity/health probe (the §6(e) through-tunnel discovery is that probe — a
    tunnel that maps no host is not "working"). It is **privilege-, tooling-, and
    egress-aware**: it reads the host's access fact (a plain `foothold.*` vs
    `access.admin`/`access.system`) and what is reachable/stageable to skip methods
    that cannot work here — e.g. an admin-only native route vs a userland SOCKS proxy,
    or a method whose binary isn't on the box and can't be staged. It retries other
    **ports** when a listener/port is refused, and if every standard route fails it
    drops to a **native last resort** built from whatever the shell has (powershell/
    cmd: `netsh interface portproxy` where admin, else a userland single-port relay).
    The contract: the operator gets *a* working path out, and obol reports the
    resulting tunnel's state (type, listener, exposed subnet/route, status) and
    **whether proxychains is needed**, with the exact usage spelled out. Honest
    caveat to keep in the UX: the worst-case native fallback may be a **single-port
    forward, not a full subnet route** — obol must say so, never imply a full pivot it
    didn't get. Interlocks with §8 (stage the chisel/ligolo binary when it isn't
    already on the target) and §6(e)/(f) (the health probe, and the tunnel display).
- **(e) Through-tunnel sweep (the recursion + health proof).** Once (d) is up and
  scope auto-extended, re-run the discovery sweep (0b/0c) **through** the tunnel. The
  scan technique is picked from the transport: SOCKS → `nmap -sT -Pn` (SOCKS carries
  only TCP connect; ICMP/UDP/SYN find nothing), ligolo → `-Pn` connect. This doubles
  as the tunnel health check — hosts returned prove it is up, an empty/timeout flags
  it down — and it recurses: new targets → login → pivot → sweep.
- **(f) Topology map + tunnel/session display.** The engagement map becomes a
  **topology of segments joined by tunnels** (scope range → its hosts → the
  multi-homed host → its tunnel → the next segment, recursively), and the live
  tunnel(s) show on the target/engagement screen: type, local listener, exposed
  subnet/route, status, and the proxychains flag. (This subsumes the engagement-map
  credential cleanup in "Known smaller issues" — representing hops is the real map
  upgrade.)

Non-negotiables this must respect: one runner, one store; scope stays a hard gate
(auto-populated, never bypassed); sessions/tunnels are live state, discoveries are
facts; login/tunnel behavior lives as pack data + the tunnel registry, never as
planner branching.

## 7. Engagement profile & flag awareness (platform-aware objectives)

Pick, on the engagement, **what kind** of box/lab/exam this is, so obol knows what
to hunt for, how to track progress, and how to frame the report. Modeled on Pentest
Companion (`docs/SOURCES.md §5`): its engagement carries an `exam_type` from a
preset table (OSCP/OSEP/OSED/CRTP/PNPT/CPTS/custom) with duration + passing score;
targets carry `machine_type` (standalone / AD DC / member / workstation) and
`local_flag`/`proof_flag`; and `EXAM_SLOTS` (initial access → privesc → local flag →
root/proof flag) track per-target progress.

For obol:

- **Engagement profile.** A platform/exam type on the engagement (HTB, OffSec/OSCP,
  TryHackMe, custom, …) that sets the flag names/formats to look for
  (`local.txt`/`proof.txt` vs `user.txt`/`root.txt` vs `THM{…}`), an optional
  scoring/points model, and an optional exam timer.
- **Target category.** A `machine_type` per target (standalone / AD DC / member /
  workstation / lab) that can also nudge exam-flow ranking (item 2).
- **Flag capture stays proof-bound — FIRST SLICE DONE.** When obol has a foothold
  (from §6), it hunts the flag files and, on **actually reading one**, records an
  objective fact (`objective.local_flag` / `objective.root_flag` /
  `objective.flag`, host-scoped, with the command that read it) — a captured flag
  is proof, not a checkbox. Landed: the `obol_flag_hunt_2026_09` pack
  (`flag-hunt-linux`/`flag-hunt-windows`, gated on a proven foothold + credential),
  the proof-bound parser (`obol/flags.py`), the `objective` finding category, and
  per-target captured-flag display on the web engagement screen. Still open: a
  configurable flag-name/format set driven by the engagement profile (below),
  hunting over a Penelope reverse shell / guided-paste channel (today it uses the
  SSH/WinRM proof channel), and the full per-target objective ladder (initial
  access → privesc → local → root) as a progress meter.

Keep obol's line: single-operator, local, terminal-first; reject Pentest Companion's
teams/auth/SaaS direction (`docs/SOURCES.md §5`).

## 8. Payload staging & tool provisioning (one-click move-material) — NEEDS DEEPER DISCUSSION

An operator constantly needs to move material onto a foothold (privesc binaries,
enum scripts, tunnel clients) and, less often, pull material back. This is the
Charon `tool_provider` idea (`docs/SOURCES.md §3`) applied to *staging*:

- **One-click upload/staging.** From a session/foothold (§6), push a chosen item to
  the target over whatever channel that host affords (smb / scp / a throwaway
  http-server / winrm copy), with the command built and the transfer tracked.
- **A Kali material cache.** obol locates and caches specific known items and their
  paths on the local Kali box (winPEAS/linPEAS, chisel/ligolo binaries, static
  binaries, common wordlists, …) so it can stage them on demand without the operator
  hunting for paths each engagement.
- **One-click download when missing.** If a cached item is not found locally, offer a
  one-click fetch from its known source, then cache it.

Interlocks with §6 (you stage *through* a session/tunnel) and item 3 (privesc
tooling is the most-staged material). A staged file on a host is engagement state,
not a fact. **Design intentionally deferred — the operator wants to discuss the
cache format, the trusted item list and sources, channel selection, and the
proof/scope posture in depth before this is built.**

## 9. Concurrency — bounded workers for independent scans & playbook branches

Today every run is serialized: the web server holds one in-process `_RUN_LOCK`
around each run, and a sweep enumerates its hosts **one at a time** (the per-host
Quick Start jobs run sequentially). Deliberately simple and safe, but slow when the
work is independent — a /24 sweep enumerating 20 live hosts, or a playbook whose
branches don't depend on each other, has no reason to run strictly serially. Certain
automatic scans and playbooks will want **additional workers/threads**.

The enhancement: a **bounded worker pool** for independent work, every non-negotiable
intact.

- **Only parallelize independent work.** Different targets are independent, and the
  store (SQLite WAL + idempotent, targeted, per-`(kind,scope,value)` writes) already
  lets concurrent writers to different hosts land without clobbering (`test_store`
  locks this). Within one playbook, ordered/dependent steps stay sequential —
  fact-gating already expresses the dependency (an action isn't eligible until its
  `requires` facts exist), so a scheduler can run all *currently-eligible,
  independent* actions at once and no more.
- **Bounded + configurable.** A max-workers cap (per engagement, sensible default) so
  obol doesn't hammer the network, the operator's box, or trip IDS on an exam. The
  cap is the knob; unbounded fan-out is never the default.
- **Finer-grained than one global lock.** The single `_RUN_LOCK` is the current
  serialization point; a pool replaces it with per-target (or per-resource) mutual
  exclusion so two runs against the *same* host still can't interleave, while runs
  against *different* hosts proceed in parallel. The scope gate still applies per run,
  unchanged.
- **The live feed already supports it.** The Activity view (0e) and the background-job
  map already render many concurrent jobs; today the sweep just doesn't create them
  concurrently. A pool makes several genuinely in-flight at once.

Interlocks: the discovery sweep (§0b/c) and the **through-tunnel sweep** (§6e) are the
biggest beneficiaries (many independent hosts); playbooks (item 5) gain parallel
independent branches with per-step approval preserved; and the auto-tunnel cascade
(§6d) can probe candidate methods/ports with bounded concurrency instead of strictly
in series. Parallelism changes *scheduling* only — never what counts as proven, never
what may be touched.

## 10. Credential-material harvesting (share/loot sweep + document OCR)

A real, thorough hunt for **credential material** in the files an engagement puts
in reach — SMB shares, a foothold's filesystem, and recovered `loot.files` —
returning **ranked likely candidates** the operator can validate, rather than a raw
grep dump. Inspired by the operator's Charon (`docs/SOURCES.md §3` — *learn from its
design, reimplement; do not copy its proprietary code*), which at one point could
sweep a share for secrets and even **OCR PDFs** to pull credentials out of scanned
documents. This is the loot/creds counterpart to the flag hunt (§7): once you can
reach files, the highest-value thing in them is usually the next credential.

Why obol should have it: credential reuse is the spine of OSCP/AD progress, and the
material is routinely sitting in `Passwords.xlsx`, a `web.config`, a
`unattend.xml`, a KeePass DB, a config backup, or a **scanned PDF** on an open
share. Today obol can *reach* those files (SMB shares via §5 tools, a foothold's
disk via §6, `loot.files`) but has no dedicated harvester that reads them, extracts
secrets, and ranks candidates.

Scope, each a reviewable PR and every non-negotiable intact:

- **Source enumeration (reach the files).** Drive the readable surface obol already
  proves: mount/spider authorized SMB shares (`smb.shares` + a validated
  credential, through the one scope-enforced runner — never a share obol hasn't
  proven reachable), a foothold's filesystem over the existing SSH/WinRM proof
  channel (§6), and already-recovered `loot.files`. Bounded and polite (size caps,
  extension/allowlist filters, worker cap per §9) so it does not exfiltrate a whole
  fileserver.
- **Content extraction — including PDF OCR.** A pluggable extractor set that reads
  text out of the high-signal formats: office/OpenDocument, config/XML/INI, scripts,
  `.kdbx`/credential stores (as *material*, not cracked), plain text, and **PDFs —
  text-layer first, then OCR (tesseract/ocrmypdf) for scanned/image-only PDFs**. OCR
  and every heavyweight extractor is an **optional extra** and degrades gracefully
  when the binary/library is absent (Charon's `tool_provider` degradation lesson,
  and obol's `tools.py` inventory + install hints already model this) — a missing
  OCR engine yields a "PDF not OCR'd, install X" note, never a crash or a silent gap.
- **Candidate detection + ranking (the product value).** Pattern/heuristic matching
  for passwords, API keys/tokens, private keys, connection strings, `user:pass`
  pairs, and known secret-bearing filenames — each candidate ranked by confidence
  (pattern strength × filename/context × proximity to a username) and **de-noised**
  so the operator gets a short list of *likely* credentials, not every base64 blob.
  Return candidates with their file, offset/context snippet, and detector.
- **Stays proof-bound (the obol line).** A harvested secret is **candidate
  material**, not a working credential — it maps to `credential.candidate` /
  `loot.files` (host- or share-scoped, citing the file + detector that found it),
  and only becomes `credential.available` when a login/proof run validates it (§6a's
  sessions layer is exactly that validator). Never record a found string as a proven
  credential; never claim access from a file read. The OCR/extraction confidence is
  detector metadata, not a `ProofState` upgrade.
- **Surfaces.** Candidates roll up in the engagement **Findings/loot** view and the
  report (with redaction honoring the existing secrets model — the debug package
  stays redacted by default), and feed the planner: a ranked `credential.candidate`
  naturally unlocks the validation/login moves that already gate on it. Keep it off
  the lean Overview (progressive-disclosure guardrail); a dedicated **Loot /
  credentials** view or tab is the home for the ranked list and per-file context.

Interlocks: §5 (SMB tools reach the shares), §6 (a foothold/session reaches the
disk; §6a validates a candidate into an available credential), §8 (staging is the
reverse direction — this *pulls* material to triage, §8 *pushes* tooling), and §9
(the sweep is embarrassingly parallel across files/shares under the worker cap).
Non-negotiables: only authorized, proven-reachable sources (hard scope gate);
harvested material is a candidate fact, never proven access; extraction/OCR is
optional and degrades, never a hard dependency; one runner, one store; and no raw
secret dumping on the lean surfaces.

## UX guardrails (product decision — keep these)

This is a fast OSCP-exam tool. The UI shows **only the live options that matter**:
no "blocked until X" list and no "proves / does not prove" language anywhere the
user sees. The fact-gating engine (`requires`/`produces`, `blocked_actions()`)
stays internal — it decides what's live; it is not surfaced. Do not reintroduce
blocked/proof panels in `board.py` or `web.py`.

**Progressive disclosure — keep the main screens lean (product decision).** As the
feature set grows (Activity, sessions, tunnels, staging, engagement profile), the
main **engagement Overview** must stay a fast, uncluttered summary — the most
important, most relevant state only (scope, targets, where-we-are, a compact map) —
with detail pushed into dedicated tabs/views. Precedents already set this shape: the
engagement-level run feed + findings roll-up + command ledger live in the **Activity
view**, not on Overview; and the per-target console is **tabbed**
(Overview/Tools/Playbooks/Checklist/Findings/Evidence/Commands). Prefer adding a new
tab/view over making an existing screen taller, and neither the engagement Overview
nor a target's Overview tab should require long scrolling to reach the primary
actions. Concrete application for §6: as sessions grow into tunnels + the auto-tunnel
cascade + staging, they belong in a dedicated per-target **Access / Pivot tab**
(with the live tunnel/session state and proxychains guidance), not piled onto the
target Overview — the Overview keeps only a compact "you're in / here's the pivot"
summary that links into it.

## Known smaller issues

- **Secrets show by default across the live surfaces now** (report, findings
  roll-up, command ledger, sessions, run outputs) — redaction is opt-in: the report
  view's "redact secrets" toggle and CLI `obol report --redact`. This is a
  deliberate product call for a single-operator localhost lab/exam console (see
  `webapp/server.py WEB_SHOW_SECRETS`). The shareable **debug package stays redacted
  by default** — it is an artifact meant to leave the box; `--include-secrets` opts
  in. ~~Remaining: an engagement-wide redact switch the whole SPA respects (the
  findings roll-up and command ledger have no per-view toggle yet).~~ **DONE.** One
  header toggle sends `include_secrets=0` on every read, carried to every payload
  builder via a per-request context, so the findings roll-up, command ledger,
  per-target findings, sessions, and report all honor the same switch.
- ~~**The engagement-map credential model is thin** (from ChatGPT's map PR #24): it
  creates only one credential node, attaches it to *every* foothold+ host, and
  falls back to an arbitrary domain when the credential has none.~~ **DONE.** The map
  now draws one node per distinct `(user, domain)` credential and a cred→host edge
  only where a fact ties them (a host-scoped credential fact or a session logged in
  as that user); a credential links only to its own domain. (§6(f)'s topology-map
  redesign will build on this.)
- ~~**Terminal parity for 0e:** an `obol findings` roll-up (and/or a richer `obol
  overview`) so the CLI operator gets the same cross-host, category-organized
  findings view the web Activity view added.~~ **DONE.** `obol findings` prints an
  engagement-wide, category-grouped, host/domain-tagged findings roll-up with source
  command lineage and optional redaction.
- ~~`run`'s "new facts" detail line is still sparse for port/service facts.~~
  **DONE.** CLI run feedback now uses compact fact summaries for ports, services,
  web titles, shares, banners, users, redirects, and other common parser payloads.
- ~~Exam-flow ranking (item 2) still surfaces some actions oddly (e.g. spraying
  ahead of roasting).~~ **PARTLY DONE.** Quiet AS-REP roasting now ranks above the
  noisy password spray off a user list (an importer exam-flow override). The broader
  phase/flow model (item 2) is still the real fix for ranking beyond this spine.
- ~~`obol web` (the static one-file snapshot) still embeds mermaid from a CDN, so its
  path graph is blank offline.~~ **DONE.** The static snapshot renders the shared
  graph model as inline SVG phase columns (`graph.build_graph_svg`) — no script, web
  font, or CDN — so its path graph works offline, matching the live `obol serve`
  surface.
- ~~The web surface loads the whole `.obol/state.json` per request (flat fact list,
  whole-file rewrites, single-target shape).~~ **DONE.** The store is now SQLite
  (`.obol/state.db`, `obol/store.py`): WAL, idempotent/targeted writes so the
  terminal and web can both write without clobbering, indexed fact queries, and an
  `events` change feed the web SSE loop tails to push payload deltas. `state.json`
  remains the export/report/snapshot/migration format. See `docs/ARCHITECTURE.md`.
