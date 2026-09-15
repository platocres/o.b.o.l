# Changelog

All notable changes to obol are recorded here. Agents must update this file
for every user-facing, code, pack, parser, runner, report, or documentation build.

## Unreleased

### Added

- Added the **web cruise surface** — a **Cruise control** card on the per-target Overview
  that brings `obol cruise` to the browser with full terminal parity. A ▶ Cruise button
  runs cruise (`POST /api/cruise`) and renders the whole pause briefing as a live panel:
  the **objective ladder** (§7), the **recap** (facts learned + the tools to install to
  unblock more), and the **checkpoint** — its ask (approve/manual/input), the "why", a
  command preview, and the risk — with an **Approve & run** button that runs the move
  through `POST /api/move/run` and re-cruises from the new state, the other moves waiting,
  and a pointer to Ingest/Assert for a checkpoint the operator handled by hand. Operator-
  sourced findings also render with an `op-run` / `op-attested` badge (Build 1). Locked by
  a `tests/test_webapp.py` case exercising `/api/cruise`, `/api/objectives`, `/api/ingest`,
  and `/api/assert` (including the objective-complete stop and 422s).

- Added the **per-target objective ladder** (`obol/objectives.py`, ROADMAP §7 promoted):
  initial access → privilege escalation → local flag → root flag, each rung reached
  **only by a proving fact** (a foothold, `access.admin`/`access.system`, or an
  `objective.*` flag capture — profile-aware about local vs root via `flags.py`) and
  carrying its evidence lineage. A projection over facts, not new state. It feeds the two
  consumers it was promoted for: **`obol cruise`'s goal function** — cruise now stops with
  `objective-complete` once the root objective is captured (an operator-attested root flag
  counts too, closing the resumable-handoff loop) instead of wandering past the win — and
  the **report** (a per-target Objectives line in the markdown, an `objectives` block in
  the report context, and the ladder shown in the cruise pause briefing). Terminal `obol
  objectives [host]` and web `GET /api/objectives`. Locked by `tests/test_objectives.py`
  (rungs reached only by facts, root-flag completion, single-flag-plus-privilege, the
  cruise objective-complete stop, operator-asserted completion, and the report carrying
  it). Still open: the §14 per-rung OSCP *proof requirement* (flag shown with host
  identity in one capture, screenshot attach/validate) riding on top of this ladder.

- Operator-sourced facts are now **visibly distinguished** everywhere they surface,
  closing the pillar III honesty loop end to end. A shared classifier
  (`ingest.fact_origin`) reads a fact's lineage from its `source` prefix —
  `operator-executed` (parsed from output the operator ran), `operator-attested` (a bare
  assertion), or `obol` (obol's own runner) — and it is surfaced in the OSCP markdown
  report (an `_(operator-attested)_` / `_(operator-executed)_` tag on the finding), the
  structured report context and per-target findings payloads (an `origin` field), the web
  findings tables and fact chips (an `op-run` / `op-attested` badge), and `obol findings`
  (an `[op]` / `[op-attested]` tag). A reviewer can always tell what obol proved from what
  the operator vouched for.

- Added the **cruise pause briefing** and **external-action ingestion** — the checkpoint
  UX and cruise-control **pillar III (resumable handoff)**, folded into one build so the
  pause and the way back in land together.
  - **Pause briefing** (`cruise.build_briefing`): every `obol cruise` stop now returns a
    rich briefing so the operator can decide what to do without reassembling context —
    **where you are** (phase / frontier / access), a **recap** (facts learned this run,
    and the specific tools to install to unblock more), and the **full checkpoint**: a
    *pure* command preview (it renders, never runs — reusing `build_command` /
    `sessions.build_login_command` / `tunnels.build_setup_command` / `exploits.plan_exploit`),
    the facts that **triggered** it, the **ask** (`approve` / `manual` / `input`), the
    **risk** (cleanup / scope note), the **resume** path, and the **other moves waiting**.
    Rendered in the terminal and returned by `POST /api/cruise`.
  - **Paste-and-parse** (`ingest.ingest_output`, `obol ingest`, `POST /api/ingest`): parse
    output from a command the operator ran themselves through obol's **same** parser
    pipeline (`parse_action_output` + local-enum + flags), so it earns the same proof-bound
    facts — stamped `operator:` lineage and recorded as an `external` ledger run, keeping
    the OSCP report complete across manual detours. Proof-bound: ambiguous prose proves
    nothing.
  - **Operator-attested assertion** (`ingest.assert_fact`, `obol assert`, `POST /api/assert`):
    the marked escape hatch when there is no parseable output — records a fact directly,
    stamped `operator-attested:` so its lineage stays honest and it is never mistaken for
    something obol proved. Honors an explicit scope and `ProofState`.
  This closes the cruise loop: obol drives the safe work, stops with a full briefing at
  each checkpoint, and the operator gets past what obol can't drive and re-enters from
  facts — "the operator did something outside obol" becomes "new facts arrived," and
  `obol cruise` continues. Locked by `tests/test_ingest.py` (parse-with-operator-lineage,
  proof-bound no-invention, the external ledger run, and marked/scoped/stated assertions)
  and briefing cases in `tests/test_cruise.py` (a pure login-command preview that never
  logs in, and the install-tools recap).

- Added **`obol cruise`** (`obol/cruise.py`) — supervised cruise control, **ROADMAP
  cruise-control pillar II**, the loop the whole spine was built for. `cruise(ws, host)`
  drives a target move by move: it runs the highest-ranked un-attempted **`auto`** move
  (recon/enum + the safe baseline) through `dispatch.run_move`, re-parses, re-ranks, and
  repeats — stopping at the first move that needs approval (`approve`/`manual`), which it
  hands back as a **checkpoint it never fires**, or when nothing safe remains (`done`), or
  at a step cap. It stands entirely on the three pieces already shipped
  (`moves.frontier_moves` + `dispatch.run_move` + `obol/autonomy.py`) and is **not a new
  engine** — every command still goes through the one scope-enforced runner/parser/store
  and the proof boundaries. Termination is guaranteed: each move runs **at most once** per
  cruise (a move that yields no new facts can't spin the loop), and a move that fails to
  run (e.g. a missing tool) is recorded and skipped, not fatal — so cruise degrades to the
  **resumable-handoff** rhythm (obol stops at friction; the operator fixes it or does the
  step by hand, re-ingests, and runs `obol cruise` again to continue). Terminal `obol
  cruise [host] [--max-steps N]` streams each step live and prints the stop reason +
  checkpoint; web `POST /api/cruise` returns the same result (synchronous under the run
  lock). Locked by `tests/test_cruise.py` (auto-only unattended execution, stopping at a
  checkpoint without firing the primitive, termination when nothing settles, and the
  no-target guard). Still open: a per-step live web view, objective-complete (§7 ladder)
  as an explicit stop, and an approve-and-continue flow.

- Added **move autonomy tiers** (`obol/autonomy.py`) — cruise-control's stop-contract as
  data, the last piece before the `obol cruise` loop. Every move (from
  `moves.frontier_moves`) now carries a tier saying how autonomous obol may be with it:
  **`auto`** (recon/enum + Quick Start's existing safe baseline — cruise auto-advances),
  **`approve`** (everything past the recon/enum boundary, plus the box-touching primitives
  login/enum/tunnel — a checkpoint that pauses for explicit approval), and **`manual`** (a
  privesc exploit — obol crafts and hands off, never fires). The classification is
  **data-driven, not a hardcoded lab rule** (AGENTS.md principle 10): a pack action's tier
  is an explicit `autonomy` field in its pack data if set, else derived from the shared
  phase model (`obol/phases.py`) and `quickstart.QUICKSTART_ACTION_IDS` — the boundary the
  ROADMAP already draws — and it is deliberately conservative (anything not clearly
  recon/enum defaults to `approve`, so cruise never auto-fires something unclassified).
  `dispatch.run_move` now **enforces the gate in one place**: an approve/manual move will
  not run unattended without approval (it returns a `needs-approval` checkpoint and
  touches nothing), while `obol do` treats the operator's explicit invocation as the
  approval and the web `POST /api/move/run` requires a real confirm. `Action` gained an
  optional `autonomy` field; `Move`/`GET /api/moves` expose the tier; `obol moves` tags
  each non-auto move (`· approve` / `· manual`). Locked by `tests/test_autonomy.py`
  (derivation, the Quick Start baseline as auto, explicit-override both directions, fixed
  primitive tiers, and the frontier carrying the tier) plus a `test_dispatch.py` gate case
  (an approve-tier login pauses without approval and runs with it).

- Added the **move execution handle** (`obol/dispatch.py`) — cruise-control **pillar
  I→II** bridge. `run_move(ws, id)` runs any frontier move (from `moves.frontier_moves`)
  by id through its **existing** shared primitive — `service.run_action` for a pack
  action, `sessions.open_session` for a login, `enumrun.run_enum` for enum run-and-rank,
  `tunnels.open_tunnel` for a pivot, `exploits.plan_exploit` to craft a privesc exploit —
  so there is now one uniform "run this move" call (the terminal, the web, and later the
  cruise loop all make it; the loop never branches per kind). It invents nothing: no new
  runner/parser/store, and it is **fact-gated on execution** — a move can only be run if
  the frontier currently *offers* it and (for a primitive needing input) it is *ready*,
  otherwise a clear error says what is missing. Each result carries an honest **posture**
  that seeds cruise's stop-contract: `ran` (a real command executed + facts ingested),
  `dry-run` (preview only), `handoff` (proof/record ran, here's the interactive command to
  launch — a login shell, a tunnel's setup), or `craft` (nothing executed, here's the
  command to review). Privesc **exploits are crafted, never auto-fired** by the dispatcher
  (the OSCP/manual posture); their execution stays on the dedicated `obol exploit --run`
  path. Terminal `obol do <id> [--dry-run] [--method/--subnet/--outcome]` and web
  `POST /api/move/run`, full parity. Locked by `tests/test_dispatch.py` (id parsing,
  the offered-and-ready execution gate, action dry-run vs. real run through the shared
  runner, a login's handoff with the access fact recorded, and exploit craft touching
  no state).

- Added the **unified move frontier** (`obol/moves.py`) — cruise-control **pillar I**,
  first slice. `frontier_moves(ws, host)` merges the packs' live actions
  (`pack.next_actions`) with the built-primitive offers — a session login (§6a), enum
  run-and-rank (§8), an applicable privesc exploit (§8), a pivot tunnel (§6d) — into ONE
  fact-gated, phase-ranked list of candidate `Move`s per host, so the primitives that
  used to live outside the ranked "next" list become first-class next moves. It reuses
  each layer's existing `eligible_*` function verbatim (**not** a second planner) and
  ranks the merged set by the same phase/frontier model the planner already uses
  (`obol/phases.py`): on-flow before premature, ready before waiting-on-one-input within a
  band. Stays proof-bound — logins are offered pre-foothold (that is how you *get* the
  foothold) but the escalate/pivot moves (enum/exploit/tunnel) only appear once a foothold
  is proven, an already-proven login is dropped from "next", and the module enumerates and
  ranks only (it runs nothing and produces no facts). Terminal `obol moves [host] [--all]`
  (ready moves by default; `--all` also lists moves waiting on one input, with the
  actionable reason) and web `GET /api/moves`, full parity. Locked by `tests/test_moves.py`
  (pack actions as dispatchable moves, a login becoming a ready/not-ready move, proven-login
  exclusion, foothold-gating of escalate moves, and the premature-below-on-flow ordering).
  This is the frontier `obol cruise` (pillar II) will drive; still open: folding it into
  `obol next`, the remaining primitives as moves, and a per-`Move` execution handle.

- Framed the **cruise-control spine** in `docs/ROADMAP.md` + `AGENTS.md` (North Star,
  planning/docs only — no code): obol's operator-in-control answer to Charon's one-button
  lab automation. The goal is Charon's reach *without* Charon's brittleness (it beat labs
  only by hard-coding around their walls and ended the run at any roadblock). Three
  pillars — **(I) unify the move space** (the built primitives — sessions, listeners,
  staging, enum, exploits, tunnels, flag capture — become fact-gated *candidate moves* in
  the one ranked frontier, alongside pack actions; the load-bearing PR, and the real home
  of §12's "typed step vocabulary"); **(II) cruise control** (`obol cruise`) — advance one
  real, scope-gated, proof-bound move at a time with a **stop-contract** (manual-required
  / noisy / ambiguous / failure / objective-complete) and the operator's foot on the
  brake, auto-driving recon/enum by default and checkpoint-gating everything past it;
  **(III) resumable handoff + external-action ingestion** — paste-and-parse (primary,
  through the same proof-bound parser) and operator-attested assertion (a marked escape
  hatch), so a roadblock is a graceful re-entry from facts, not the end of the run. Cruise
  control (a car feature, deliberately *not* "autopilot"/"copilot") keeps forward motion
  while your hands stay near the wheel and disengages the instant you tap the brake.
- Added `AGENTS.md` **principle 10 — no hard-coded lab wins (the anti-Charon rule):**
  methodology is universal (Orange-grounded, carried as data) or it is an operator
  handoff; never a box-specific planner branch, and never a manufactured fact/win/proof
  artifact to keep a run moving. Reworded the "one deliberate command at a time" identity
  line to embrace cruise control (each move is still exactly one inspectable, proof-bound,
  scope-gated command).
- Refolded ROADMAP **§12** (was "Phase playbooks & runbooks", the automation headline)
  into "**Named runbooks — a convenience over the cruise-control frontier**": a saved
  shortcut that seeds moves into the same frontier and `obol cruise` loop, never a second
  orchestrator. Promoted **§7's per-target objective ladder** to load-bearing (cruise
  control's goal function + the report's proof checklist). Added ROADMAP **§13 —
  automatic exploit repair** (bounded, data-driven, operator-approved, proof-bound;
  preparation-only in OSCP mode) and **§14 — report proof & screenshot handling** (OSCP
  proof rules as profile data, obol-generated compliant proof blocks, operator-screenshot
  attach/guide/validate, a pre-submission proof validator, and a no-forgery guardrail).

- Added the **engagement profile** (ROADMAP §7, first slice): an engagement now
  carries a platform/exam type that decides **which flag file names and value
  formats the post-foothold flag hunt looks for**, instead of the hunt being
  hard-wired to one lab's conventions. A new `obol/profile.py` holds the preset
  table — **Hack The Box** (`user.txt`/`root.txt`, hash-shaped), **OffSec/OSCP**
  (`local.txt`/`proof.txt`), **TryHackMe** (`user.txt`/`root.txt`/`flag.txt`,
  brace-shaped), **CTF** (`flag.txt`/`flag`, brace/UUID), and **Custom** (obol's
  full defaults) — each mapping a filename to its objective slot (local/root) and
  listing the accepted value formats (`brace`/`hex32`/`hex64`/`uuid`/`token`). The
  operator can also override the flag names/formats directly. The profile is
  engagement-level operator configuration (stored in the store's `meta`, on
  `Workspace.profile`), **not a fact**: it never relaxes a proof boundary — a
  captured flag is still recorded only when a file was actually read and its
  content matches a *configured* format (`flags.extract_flag_value` and
  `parse_flag_output` are now profile-driven, falling back to the full defaults
  when no profile is set). The flag-hunt pack no longer hardcodes filenames: the
  Linux `find -iname …` fragment and the Windows `-Include …` list come from new
  `{{flag_inames_linux}}`/`{{flag_names_windows}}` command tokens
  (`board.command_context`), each validated to safe filename characters so an
  override can never inject shell/find syntax. Full terminal + web parity: `obol
  profile [show|list|set <platform> [--flag-names …] [--flag-formats …]]`, and
  `GET/POST /api/profile` plus a compact profile chip + picker on the web Scope
  card and the resolved config on `/api/meta` and `/api/overview`. Locked by
  `tests/test_profile.py` (preset resolution, alias/unknown fallback, format
  gating, profile-driven hunt, filename-safe tokens, persistence) with CLI and web
  parity tests. Still open in §7: target `machine_type`, a scoring/points model, an
  exam timer, and the full per-target objective ladder (initial access → privesc →
  local → root) as a progress meter.

- Added **Manual Web-Exploitation Success-Signal Parsers v2** (ROADMAP item 1 / §11):
  the remaining explain-only Orange web cards now record proof-bound facts from a
  hand-driven curl's *output shape*, each mapped to its narrowest fact and
  test-locked against overclaim.
  - **NoSQL injection** (`nosql-injection`) → `web.nosqli_confirmed`, recorded only
    when **both** an operator payload (`[$ne]`, `{"$ne":…}`) is in the request **and**
    an authentication-success shape is in the response (a `success`/`token` flag, or a
    session cookie paired with a redirect to a logged-in area). A bypassed application
    login is *web-app* authorization — never OS `access.admin`, a plaintext credential,
    or a shell.
  - **JWT attacks** (`jwt-attacks`): a recovered HMAC signing secret (jwt_tool
    "is the CORRECT key", a hashcat `token:secret` crack) → `web.jwt_secret` plus a
    `credential.candidate` of kind `jwt_signing_secret` — candidate *material* that
    forges tokens, not a user's plaintext login or OS access; and a forged token
    accepted (an `alg:none`/tampered token answered with an admin/authenticated
    response) → `web.authz_bypass` (a web authorization bypass, not OS `access.admin`).
  - **Insecure deserialization / Tomcat WAR deploy / Jenkins script console**
    (`deserialization`, `tomcat-deploy`, `jenkins-access`) share the command-output
    proof shape, so they now feed the existing `web.cmdi_confirmed` parser with a
    distinct `method` — confirmed from captured `uid=…`/`nt authority\system` output,
    never promoted to a caught interactive shell, a foothold, or admin/SYSTEM.
  Wired friendly labels (`pack.friendly`), phase mapping (`phases.py`: the confirmed
  web-RCE/bypass kinds rank in *escalate*, a recovered JWT secret in *creds*), added
  golden fixtures to the manifest corpus, and a `tests/test_web_exploit_parsers_v2.py`
  suite with positive and anti-overclaim cases (an operator payload with no success,
  a valid login with no operator, a rejected forged token, a decode-only JWT run, a
  reflected-but-not-executed payload). Still explain-only, as follow-ups: IDOR, XSS,
  WordPress, and XXE's remaining branches.
- Roadmap: added **§12 Phase playbooks & runbooks** — a design for phase-scoped, one-click,
  context-suggested runbooks per target, with all playbooks browsable/selectable in a
  dedicated site section and full terminal parity. Builds on the item-2 phase model
  (frontier ranks the suggestions) and orchestrates the already-built primitives
  (sessions, listeners, staging, tunnels) via a generalized typed playbook step — not a
  second engine. Planning only; no code yet. See `docs/ROADMAP.md §12`.
- Added the **engagement phase/flow ranking model** (ROADMAP item 2): the planner now
  ranks live actions by the shared phase model (recon → enum → creds → access →
  escalate → loot) *relative to each target's current frontier*, instead of by a bare
  scalar priority. A new `obol/phases.py` houses the one phase taxonomy (previously
  buried in `graph.py`, now imported by both the planner and the map so ranking and
  layout can never disagree); `graph.py` re-exports its old names. `next_actions`
  buckets each live action by how far it reaches **past the target's frontier** (the
  furthest phase reached, plus one) and orders by priority within a bucket — so a
  premature high-value branch (a loot secrets-dump or a BloodHound collect that becomes
  eligible mid-enumeration) sorts **below** the recon/enum you should finish first,
  while a deliberately low-priority recon step (a slow UDP sweep) never leapfrogs the
  real next move. The frontier is per-factset, so each host ranks by its own progress,
  and the same action re-ranks as the engagement advances (an escalate move is
  premature before a foothold, on-flow after one). Actions may carry an optional
  `phase` in pack data to correct a card the derivation misplaces, with no planner
  branching. Locked by `tests/test_phase_ranking.py`; the AS-REP-before-spray and
  content-discovery-before-jwt orderings now hold structurally, not by hand-tuned
  priority coincidence.
- Added **Manual Web-Exploitation Success-Signal Parsers** (ROADMAP item 1): the
  curl-driven Orange web cards (LFI, command injection, manual SQLi, SSRF) that
  were explain-only now record proof-bound facts from the *output shape* a
  hand-driven exploit produces — the OSCP-relevant path, since the exam forbids
  automated exploiters like sqlmap. `web.lfi_confirmed` + `loot.files` (and
  `web.source` for a `php://filter` source read) fire only on real file content
  (`/etc/passwd` shape, a Windows ini, or base64 that decodes to PHP source), never
  a reflected payload or a page that merely mentions a path; `web.cmdi_confirmed`
  fires only on captured command output (`uid=…`/`nt authority\system`) for command
  injection, SSTI RCE, web shells, and an executing uploaded shell
  (`web.upload_confirmed`); `web.sqli_confirmed` fires on a real DBMS error
  signature (MySQL/MariaDB/Oracle/PostgreSQL/MSSQL/SQLite) from a manual quote/UNION,
  complementing the existing SQLMap path; and `web.ssrf_confirmed` fires on internal
  cloud-metadata content, recording leaked cloud keys as `credential.candidate`
  material. Proof boundaries held and test-locked: web command execution is **not**
  a caught interactive shell or admin/SYSTEM (even `uid=0`), a disclosed
  `/etc/passwd` yields no credential, a SQL error is not a dump, and leaked keys are
  candidate material until validated. The fixture corpus adds positive and
  anti-overclaim cases for each, plus a `tests/test_web_exploit_parsers.py` suite.
- Added **AD Abuse Success-Signal Parser Coverage v1**: outputs from `bloodyAD`,
  Impacket addcomputer/RBCD/getST, NetExec LAPS, and gMSA hash dumping now produce
  proof-bound facts for object-control paths, added computer accounts, Kerberos
  ticket material, LAPS password candidates, and gMSA NTLM hash material. These
  parsers deliberately do **not** turn control-path edits, tickets, LAPS reads, or
  machine/gMSA material into admin/SYSTEM access, footholds, or validated login
  credentials until a later command proves that access. The parser fixture corpus
  now includes AD-abuse positive and anti-overclaim cases.
- Added **Parser Coverage + Fixture Corpus v3**: SQLMap output now records
  confirmed SQL injection, database names/tables, database credential-material
  candidates, and SQLMap webshell context without claiming OS admin/root/SYSTEM or
  validated credentials; exposed `.git`/`git-dumper` output now records `web.source`
  plus source-code secret candidates without converting them into usable credentials.
  The manifest-driven parser corpus now includes real-shaped fixtures for NetExec
  SAM dumps, secretsdump/NTDS domain loot, BloodHound collection vs. attack-path
  analysis, SQLMap database/webshell output, git-dumper source recovery, and
  Linux/Windows privesc enum leads. `db.databases` / `db.tables` facts have friendly
  labels and report grouping so database evidence surfaces cleanly.
- Completed the pivoting milestone (§6d/e/f) on top of the staging layer:
  - **Auto-tunnel cascade (§6d).** `tunnels.auto_tunnel` walks a feasibility-ordered
    cascade (ligolo → sshuttle → chisel → ssh `-D` → ssh `-L` → native `netsh
    portproxy`) that is **privilege-, OS-, credential-, and tooling-aware** — a method
    whose binary obol can neither find nor fetch, or that needs admin/creds it lacks,
    is skipped with a reason. For the chosen transport obol **stages its binary via the
    §8 transfer layer, confirms the stage landed, records the on-target path +
    verification on the tunnel, and points the setup command at that staged path** (a
    generic mechanism for any tunnel tool, driven by `_TUNNEL_MATERIAL`). Falls through
    on failure down to a native last resort, and is honest that the fallback is a
    single-port forward, not a full subnet route. `feasible_cascade` exposes the dry
    plan. `obol tunnel auto` + `GET /api/tunnel/cascade`, `POST /api/run/tunnel/auto`.
  - **Through-tunnel sweep (§6e).** `discovery.run_tunnel_sweep` re-runs discovery
    *through* a tunnel with a transport-appropriate technique (SOCKS/forward →
    `proxychains -q nmap -sT -Pn`; transparent → `nmap -sT -Pn`), adds any live host as
    a target (the recursion), and **doubles as the health proof** — hosts answering flip
    the tunnel to `up`, an empty result to `down`. `parse_hosts_with_open_ports` keeps
    only hosts with an open port (a bare `-Pn` report line is not proof of life).
    `obol tunnel sweep <id>` + `POST /api/run/tunnel/sweep`.
  - **Topology map (§6f).** `graph.build_topology` projects the engagement as network
    **segments joined by tunnel hops** — scope range → its hosts (foothold/session
    flagged) → the pivot host → its tunnel (transport/status/proxychains/staged binary
    path) → the exposed segment, with pivot-authorized segments marked distinct from
    operator scope. `obol topology` + `GET /api/topology`, and the tunnels/auto-tunnel/
    sweep controls on the web Access / Pivot tab.
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

### Fixed

- **Parser quality audit — proof-boundary and false-positive fixes** (from a
  full read-only audit of every parser in `obol/parsers.py`, including the newly
  merged AD-abuse parsers):
  - **AlwaysInstallElevated** no longer fires from noise. It now parses the actual
    per-hive `reg query` DWORD and records the lead only when **both** the HKLM and
    HKCU policy values are set; a safe `0x0/0x0` host (previously flagged whenever
    two stray `1`s appeared anywhere in the transcript) is no longer a false lead.
  - **`host.os_family` is no longer promoted from a bare WinRM port.** An open
    5985/5986 is a `host.os_hint` only — OMI and other WS-Man servers run on Linux,
    so os_family (which drives OS-specific action filtering) now requires a Windows
    banner/CPE, matching the RDP-port behavior and the PARSER_QA "strong evidence"
    rule.
  - **A successful `guest` LDAP bind is no longer recorded as `ad.anonymous_bind`**
    (authenticated-as-guest is a different primitive than a null/anonymous bind).
  - **Anonymous-bind detection is command-shape-driven, not action-id-driven:** an
    operator who edits the anon-enum action to pass a real username no longer has
    the result mislabeled as an anonymous bind.
  - **SUID candidates** now come from a `find -perm` search or an actual `rws`
    setuid mode line, not from every bare path in a linpeas dump that merely
    mentions "SUID". **Local-secret candidates** now require a value-bearing
    assignment or a private-key header, not a bare `secret`/`password` keyword.
  - **Weak service permissions** now require a service-specific access right
    (`SERVICE_CHANGE_CONFIG`, …) or a writable ACE granted to a low-privilege
    principal, instead of any `(F)`/`(M)` token on any admin-owned file.
  - **John cracked credentials** are recorded only from real `--show` output (a
    `N password hashes cracked` footer), not from the `Loaded N password hashes`
    preamble, and each row's password is validated.
  - Added `tests/test_parser_audit_fixes.py` (21 misleading-output regressions,
    each of which would have caught its finding), plus positive/negative coverage
    for the previously-untested `nxc rdp` parser and boundary locks for the
    AD-abuse addcomputer/gMSA parsers.

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
