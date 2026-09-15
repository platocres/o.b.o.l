# obol — agent entrypoint

Read this first, then [`CHANGELOG.md`](CHANGELOG.md) (what has already shipped),
[`docs/SOURCES.md`](docs/SOURCES.md) (where the methodology and reference code
live), and [`docs/ROADMAP.md`](docs/ROADMAP.md) (what to build next). For the state/sync/render internals see
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md); for the review bundle see
[`docs/DEBUG.md`](docs/DEBUG.md). The same contract applies to any coding agent
(Claude, ChatGPT, etc.). `CLAUDE.md` points here.

## Naming — "obol local" vs "obol web" (canonical, use these terms)

From this point forward, agents MUST distinguish the two projects by these names:

- **obol local** — THIS repo (`platocres/o.b.o.l`), *O.B.O.L — Offensive Box
  Operations Ledger*. The terminal-first, on-box operator tool that *runs* an
  engagement (executes tools, ingests evidence, keeps the ledger). Also fine:
  "o.b.o.l".
- **obol web** — the OLDER project at `platocres/obol`: the browser-based, static
  methodology planning app that obol local mines for its packs (see
  `docs/SOURCES.md §2`).

When the user says "obol local" they mean this repo; "obol web" means
`platocres/obol`. Never conflate them.

Note on the docs' tone: some earlier "always keep it read-only / zero-dependency"
caution was over-conservative. o.b.o.l is a real, dependency-using tool (the web
surface uses FastAPI); the "zero-dependency" ideal belonged to the *web* Obol, not
here. The non-negotiables below (facts discipline, scope enforcement, one store,
UX guardrails) still hold; blanket "never add a dependency / keep the web read-only"
statements do not.

## What obol is

An **evidence-driven OSCP operator companion**. Terminal-first, PentOS-style shell
subcommands. The operator drives one deliberate command at a time — or hands obol the
wheel with **cruise control** (`obol cruise`) and lets it advance the engagement move by
move, foot near the brake. Either way obol keeps a conservative model of what has
actually been **proven**, executes exactly one real, scope-gated, proof-bound command per
move, and recommends (or, in cruise, takes) the next best action from that model. Built
for the OSCP exam: the terminal scrollback is the operator's evidence log.

**What makes it different** from the tools it learns from (see `docs/SOURCES.md`):
a **fact-gated decision model** — actions are gated on proven facts (each carrying
a `ProofState`) instead of a stateless service→tool map, so the moves it surfaces
are the ones that actually matter *now*. The gating is an internal engine detail;
the UI shows clean, ranked **live options only** — it does NOT lecture users with
"proves / does not prove" or "blocked until X" text (a deliberate product
decision: this is a fast OSCP-exam tool). And **one state, multiple synced
views**: the terminal and a localhost web surface both drive the engagement over
one store (either can launch a scope-enforced run; the web updates in real time),
and an OSCP report is narrated from the same fact/run ledger.

## The North Star — cruise control (operator-in-control automation)

The sibling tool **Charon** (`docs/SOURCES.md §3`) can drive a whole lab end to end —
enumerate, foothold, privesc, stage/run/**repair** exploits, catch its own reverse shell,
pivot, and grab the flags — from one button. But it was **brittle**: it beat a lab only
by hard-coding around that lab's walls after many rounds (it learned no universal
lesson), and a single roadblock ended the run. obol's aim is Charon's reach **with the
operator in control and without the brittleness**:

- **Automate the universal 80–90%.** obol drives the methodologically universal, boring
  work (enumerate, stage, run the standard moves, hunt flags, capture everything for the
  report) as far as the facts allow on each phase — and it **never hard-codes a
  lab-specific win**. When methodology runs out it hands off; it does not special-case a
  box to get past a wall (principle 10 below).
- **Cruise control, not autopilot.** `obol cruise` advances the engagement one real,
  scope-gated, proof-bound move at a time and **stops itself at every checkpoint** — a
  manual-required exploit (OSCP forbids automating it, so obol stages + crafts + hands it
  off, never fires it), a noisy/risky step, a genuine fork, or a failure. The operator
  keeps a foot on the brake: step, skip, take the wheel, or stop at any moment. Nothing is
  a hidden chain — every move is an inspectable command that writes the one ledger. Cruise
  control (a 1950s car feature) keeps forward motion while your hands stay near the wheel
  and disengages the instant you tap the brake; that is the whole contract.
- **Resumable handoff — the operator fills the gaps.** obol will never account for every
  curveball, and it does not have to. When it gets stuck, the operator steps outside obol,
  does the thing by hand, and **re-enters from facts**: paste the tool output and obol
  parses it through the same proof-bound pipeline, or assert an operator-attested fact
  (always visibly distinguished from obol-run evidence). Because facts are the one
  interface and the planner runs off facts, "the operator did something outside obol" is
  just "new facts arrived" — the frontier re-ranks and cruise resumes. This is the seam
  Charon never had.

The build sequence for this is the **cruise-control spine** in `docs/ROADMAP.md` (pillars:
unify the move space → cruise control with a stop-contract → resumable handoff +
external-action ingestion), with automatic exploit repair (§13) and report proof &
screenshot handling (§14) alongside.

## The non-negotiable principles (the "always/never")

1. **Facts are the source of truth.** Nothing is true unless a `Fact` records it,
   scoped to exactly what the evidence supports, with a `ProofState`
   (`supported`/`refuted`/`inconclusive`) and the command that produced it. An
   action **never records more than the facts it actually establishes** — a WinRM
   login yields *authenticated user*, not *admin*; an AS-REP hash is *crackable
   material*, not *a credential*. Preserve this when you add parsers: map output
   to the narrowest supported fact, prefer no fact over a convenient one. **This
   discipline is internal** — it drives which options are live; it is NOT surfaced
   as proof/blocked language in the UI (see the differentiator note above).
2. **Methodology is data, not code.** Actions live in `obol/packs/*.json` and are
   loaded by the planner. Add methodology by adding pack entries, **never** by
   putting box-specific or branch-specific logic in the planner.
3. **Terminal and web are both actors over one shared state.** Either surface may
   launch a run through the same shared service (`service.run_action`) — one runner,
   one parser, one `.obol` store. Run-from-site has landed: the web triggers a run by
   action id, the server fills the command from workspace facts, and the same scope
   gate applies. **Secrets are shown by default** on this surface — it is a
   single-operator localhost lab/exam console, so passwords/hashes/tickets appear in
   commands, fact values, and login commands unless the operator opts into redaction
   (the report's "redact secrets" toggle, `obol report --redact`); the one artifact
   that stays redacted-by-default is the shareable **debug package**, because it is
   meant to leave the box. Do **not** reintroduce redact-by-default on the live
   surfaces (`webapp/server.py WEB_SHOW_SECRETS`). The store is **SQLite**
   (`.obol/state.db`, `obol/store.py`) precisely because both surfaces are separate
   processes writing the same engagement — WAL + idempotent, targeted writes let a
   terminal `obol run` and a run-from-site both land instead of clobbering each other
   (a whole-file `state.json` rewrite could not). Both surfaces stay synced in real
   time: the web SSE loop tails the store's `events` change feed and pushes *what
   changed*. The web is localhost-only and token-gated. Never create a second state
   store or a second runner for the web. `state.json` survives only as the
   export/import/migration format (report, `obol web` snapshot, debug package). See
   `docs/ARCHITECTURE.md`.
4. **Scope enforcement is mandatory for the runner** (`obol/scope.py`,
   `obol/runner.py`). It may only touch an authorized target — a hard gate, not a
   noise tier — and it applies equally to terminal-, web-, and playbook-launched
   runs. **Playbooks** are named, ordered sequences of pack actions, stored as
   data, runnable from terminal and web, with per-step approval for noisy/risky
   steps (see `docs/ROADMAP.md`, modeled on Pentest Companion).
5. **The path graph is projected once** (`graph.py` → `build_graph_model`) and
   rendered to every surface — terminal/report as mermaid (`build_mermaid`), the web
   as an SVG flow chart grouped by engagement phase — so surfaces never disagree.
6. **Tool/action contract** (inherited from the prior obol): an action is only
   "real" when it generates realistic commands (no fabricated seed values),
   ingests output as evidence, respects proof boundaries, and carries operator
   guidance. A card that only renders is not implemented.
7. **OSCP posture:** print to scrollback, never a full-screen live dashboard;
   degrade to plain text when `rich` is absent.
8. **Licensing:** Orange-derived packs are GPL-3.0 and kept as distinct,
   attributed data components (`obol/packs/NOTICE.md`). Do not fold pack contents
   into differently-licensed core code.
9. **Changelog discipline:** every meaningful build updates `CHANGELOG.md`.
   Add an `Unreleased` entry for code, parser, pack, runner, report, web, CLI,
   test, or documentation changes before handing work back. The test suite checks
   this for non-trivial repo changes, so do not leave the changelog as future work.
10. **No hard-coded lab wins (the anti-Charon rule).** obol's methodology is universal
    (Orange-grounded, carried as pack/profile **data**) or it is an operator handoff —
    **never** a box-specific branch in the planner to get past a particular wall. Charon
    sprawled precisely because it special-cased labs and learned no universal lesson; obol
    must not repeat it. When the packs' methodology runs out, obol stops and hands off (the
    resumable-handoff pillar above) and re-enters from whatever facts come back —
    obol-parsed or operator-attested. Never manufacture a fact, a win, or a proof artifact
    (a screenshot included) to keep a run moving; the honest lineage of every fact
    (obol-run vs. operator-supplied) is preserved and surfaced.

## Architecture / module map

```
obol/
  facts.py       Fact + ProofState + FactSet (the source of truth)
  library.py     engagement library: many engagements under an app-managed base dir
                 ($OBOL_HOME); create/list/active-select (the web + `obol engagement`)
  store.py       SQLite persistence for one engagement (.obol/state.db): WAL,
                 idempotent/targeted writes (facts by content hash, runs by id,
                 sessions by id) so terminal + web can both write without clobbering,
                 and an `events` change feed the web SSE loop tails (session_added/
                 updated/removed included). See docs/ARCHITECTURE.md.
  workspace.py   an engagement's in-memory model over store.py: targets, per-target
                 fact view, scope, inputs, run ledger, evidence attachments, checklist
                 ticks, BloodHound summary, and live sessions (add_session/close/probe
                 — pivot/login state with a status, NOT facts). ws.facts.add()/record_run() mutate memory;
                 save() reconciles to SQLite. to_payload()/apply_payload() are the
                 JSON interchange (report/snapshot/debug/migration). find_workspace()
                 walks up like git; has_state() detects state.db or a legacy state.json
  bloodhound.py  tolerant SharpHound/BloodHound export parser -> domain overlay facts
  tools.py       tool inventory: curated registry of the packs' tools + detection
                 (which/default Kali paths/auto-locate), overrides in tools.json,
                 install hints; the runner resolves found/added tools through it
  vulnmatch.py   fingerprint -> probable-exploit matcher (§15b): matches a host's
                 service/version/OS/web fingerprint against packs/known_exploits_*.json
                 (EternalBlue, vsftpd 2.3.4, Shellshock, Samba usermap, ProFTPD, Drupalgeddon,
                 DirtyCow/DirtyPipe, PrintNightmare, …) → ranked candidate leads recorded as
                 exploit.candidate facts (proof-bound: a version match is a LEAD, never
                 confirmed-vulnerable). Flows through the same points as any exploit: a move
                 (exploit:vuln:<key>, manual — the exam floor), dispatch craft, the provision
                 cache. `obol vulns`, GET /api/vulns. Records candidates after each service
                 scan (service.run_action hook). Vendors no exploit code
  pack.py        Action model + planner (next_actions / blocked_actions /
                 apply_action) + load_pack(); friendly() names fact kinds
  packs/         methodology packs as DATA (+ NOTICE.md attribution)
    orange_ad_2025_03.json   nmap prelude + 30 Orange AD actions
    orange_web_2025_03.json  23 Orange web-lane actions (recon parsers live;
                             exploitation cards explain-only)
    orange_linux_privesc_2025_03.json   12 Linux privesc actions
    orange_windows_privesc_2025_03.json 10 Windows privesc actions
    known_exploits_2026_09.json         fingerprint -> known remote/kernel exploit registry
                                        (DATA for vulnmatch.py; not an action pack — cites
                                        CVE/EDB, vendors no code)
  playbook.py    named, ordered sequences of pack actions as data; renders a
                 command plan and runs one step through the shared service.run_action
                 (same runner/parser/store), with per-step require_approval gating
  playbooks/     playbooks as DATA (+ NOTICE.md): ad-recon.json, web-recon.json
  board.py       terminal render (rich + plain fallback); {{token}} templating;
                 explain view shows the full card (hypothesis, commands, refs)
  scope.py       target normalization + exact/CIDR scope checks
  runner.py      fixed-argv runner; timeout, dry-run, raw output capture;
                 scope_target gates a range/discovery run on an authorized entry
  discovery.py   engagement discovery sweep: nmap host discovery over an authorized
                 scope range (through the one runner) -> live hosts -> auto-created
                 targets, then the web fans out the Quick Start baseline onto each
                 new host. Scaffolding, not Orange methodology; stays proof-bound
  service.py     run -> parse -> record -> save; the ONE path both surfaces call
                 (target=... pins a run to a host); eligible_actions = tool palette
  pivot.py       pivot-candidate projection (§6c): lifts the parsed host.multihomed/
                 network.subnet_candidate/pivot.candidate lead facts into one "where
                 to pivot next" view (multi-homed status + candidate adjacent subnets,
                 each tagged in/out of scope) for the target/engagement/report surfaces.
                 Read-only; never mutates scope or state
  tunnels.py     tunnels layer (§6d): a registry of pivot transports (ligolo/sshuttle/
                 chisel/ssh -D/-L) with each transport (transparent/socks/portforward)
                 + OS + setup command; tunnels are LIVE STATE (Workspace.tunnels, a
                 status that can flip), NOT facts. Opening one auto-extends scope to
                 its subnet (pivot-authorized, never a bypass); route_prefix() makes
                 the runner reachability-aware (proxychains -q for SOCKS-only hosts)
  sessions.py    sessions layer (§6a): one-click login (winrm/ssh/rdp) PAIRED with a
                 non-interactive proof run through service.run_action — the captured
                 output establishes the access fact (facts stay the source of truth),
                 then a live SESSION is recorded (Workspace.sessions, status flips) and
                 the interactive command handed off. A login registry (like tools.py);
                 produces no facts of its own. eligible_sessions/open_session/probe
  parsers.py     evidence parsers; generic nmap/nxc/LDAP output -> narrow facts
  graph.py       facts+actions -> per-target graph model + mermaid (one projection);
                 build_engagement_graph stitches scope, targets, domains, services,
                 and BloodHound overlay from evidence-backed links
  report.py      OSCP markdown report + build_report_context (per-target rollup +
                 evidence + engagement graph, structured for the web)
  web.py         self-contained read-only static HTML snapshot (`obol web`)
  debug.py       `obol debug package` / `obol debug capture`: bundles state, events,
                 facts, ledger + raw run output, report, tools/env, terminal renders,
                 site snapshot, and optional PNG screenshots into a review .zip
  screenshots.py optional headless-browser (Playwright or system chromium) PNGs for
                 the debug package; degrades to text-only. See docs/DEBUG.md
  webapp/        live localhost web surface (`obol serve`) — optional [web] extra
    server.py      FastAPI over the engagement library: engagements/targets CRUD,
                   per-target bundle, run-from-site, evidence + BloodHound upload,
                   engagement activity (live jobs + cross-host findings roll-up +
                   command ledger), token gate, SSE change-feed real-time (deltas)
    static/        vanilla-JS SPA rendered with morphdom (DOM is patched, not torn
                   down) and one delegated data-act handler: engagement overview,
                   targets, tabbed target view (Overview/Tools/Playbooks/Checklist/
                   Findings/Evidence/Commands), Activity (engagement-level live run
                   feed + findings roll-up), attack path, report; vendored
                   chart.umd.min.js + morphdom-umd.min.js (no CDN, no build step)
  profile.py     engagement profile (§7): platform/exam presets (HTB/OSCP/THM/CTF/
                 custom) that decide which flag file NAMES + value FORMATS the flag
                 hunt looks for, plus the objective slot mapping. Operator config on
                 Workspace.profile (stored in the store's `meta`), NOT a fact — it
                 narrows what the hunt reads, never relaxing a proof boundary; drives
                 flags.py and the {{flag_inames_linux}}/{{flag_names_windows}} tokens
  seed.py        Forest demo fixture (post-nmap facts)
  moves.py       the unified move frontier (cruise-control pillar I): merges the packs'
                 live actions (pack.next_actions) with the built-primitive offers
                 (login/enum/exploit/tunnel, each via its own eligible_* fn) into ONE
                 fact-gated, phase-ranked list of candidate moves per host. Enumerates
                 and ranks only (never runs, produces no facts); the frontier `obol
                 cruise` will drive. `frontier_moves(ws, host)` -> [Move]. Move kinds:
                 action / login / enum / exploit / tunnel / sweep (a through-tunnel sweep
                 of a live pivot — the §6e recursion, offered once per tunnel)
  dispatch.py    move execution handle (cruise pillar I->II): run_move(ws, id) runs one
                 frontier move by id through its existing shared primitive
                 (service.run_action / sessions / enumrun / tunnels / exploits) — the
                 uniform "run this move" call obol cruise will make, so the loop never
                 branches per kind. Fact-gated (a move must be offered+ready to run) and
                 posture-tagged (ran/dry-run/handoff/craft — the stop-contract seed);
                 exploits are crafted, never auto-fired
  autonomy.py    move autonomy tiers (cruise stop-contract): how autonomous obol may be
                 with a move — auto (recon/enum + Quick Start's safe baseline), approve
                 (past that boundary + box-touching primitives login/enum/tunnel), manual
                 (a privesc exploit — craft, never fire). Data-driven (an explicit pack
                 `autonomy` overrides the phase/quickstart derivation), conservative by
                 default; dispatch.run_move enforces it as the approval gate. autonomy.decide
                 (ws, kind, base_tier, tool) is the ONE policy gate for the OSCP-exam vs
                 HTB/lab separation — resolves each move to auto/ask/never from reach
                 (local prep vs target-touching) × mode (exam/lab/default, from the §7
                 profile) × operator per-kind override. Exam floor (uncrossable): automated
                 exploiters = never, an exploit RUN is never auto (craft + hand off). Read
                 by dispatch/cruise/moves; visible + settable via `obol autonomy [set …]`,
                 GET/POST /api/autonomy
  cruise.py      obol cruise — supervised cruise control (pillar II) + the pause
                 briefing. The loop over moves.frontier_moves + dispatch.run_move +
                 autonomy: runs the highest-ranked un-attempted AUTO move, re-ranks,
                 repeats, and STOPS at the first approve/manual move (never fires it) or
                 when nothing safe remains. Each move runs at most once (always
                 terminates); a failed move is recorded and skipped, not fatal. On every
                 stop it builds a rich BRIEFING (build_briefing): where-you-are, a recap
                 (learned facts + tools to install), and the full checkpoint — a PURE
                 command preview, the facts that triggered it, the ask (approve/manual/
                 input), the risk, the resume path, and the other moves waiting. `obol
                 cruise --all` cruises EVERY in-scope target breadth-first (the §6
                 recursion across segments, re-reading the target list so a just-swept
                 segment's hosts get cruised too); `--sweep` elevates through-tunnel sweeps
                 of already-opened pivots to auto so cruise carries into the pivoted
                 segment (opening a tunnel still asks). Not a new engine. `obol cruise
                 [host] [--all] [--sweep]`
  objectives.py  per-target objective ladder (§7): initial access → privesc → local flag
                 → root flag, each rung reached only by a proving fact (foothold/access.*/
                 objective.* — profile-aware via flags.py) and carrying its evidence. Read
                 by obol cruise (its goal function — stop at the root objective) AND the
                 report (the objective/proof checklist). A projection over facts, not new
                 state. `obol objectives [host]`, GET /api/objectives
  follow.py      followed sessions (§15c): obol follows you through a MANUAL login it does
                 not perform. `obol follow -- <cmd>` runs your interactive tool in a logged
                 PTY and parse_transcript() live-parses it into operator-session: facts (no
                 copy-paste); tail_penelope_logs() ingests penelope's own session logs;
                 capture_screenshot() grabs a REAL desktop screenshot at a proof moment
                 (never a forgery), degrading when no display/tool. Reach = the operator's
                 own session, never crosses a proof boundary
  ingest.py      external-action ingestion (pillar III): the way back into cruise after
                 the operator does something by hand. ingest_output() paste-and-parses
                 operator-supplied tool output through the SAME parser pipeline (proof-
                 bound, stamped operator: lineage, run flagged external); assert_fact()
                 records an operator-attested fact directly (stamped operator-attested:)
                 as the marked escape hatch. Invents no parser/fact kind. `obol ingest`,
                 `obol assert`; add_credential() is the `obol cred add` front door — a
                 hand-found password/NT hash becomes credential.available and unlocks
                 login/tunnels/flags
  cli.py         subcommands: init / engagement / target / profile / scope / scan /
                 overview / moves / do / cruise / autonomy / objectives / ingest / assert /
                 cred / vulns / follow / install / next / explain / run / playbook(s) / sweep / login /
                 sessions / session / facts / report / serve / web / debug, plus
                 help/manual/version/info
  quickstart.py  shared nmap-first Quick Start action order + terminal runner used
                 to keep CLI scan behavior aligned with the web Quick Start flow
scripts/
  import_orange_ad.js   converter: old-obol lanes.js AD lane -> pack JSON
  import_orange_web.js  converter: old-obol lanes.js web lane -> pack JSON
  import_orange_privesc.js converter: old-obol lanes.js privesc lanes -> pack JSON
tests/
  test_pack.py      pack loads, proof boundaries, gating, seed unlocks chain
  test_parsers.py   parser proof boundaries; no walkthrough-name hardcoding
  …                 also store, service, playbook, report, graph, tools, webapp,
                    multitarget, web-pack/parser, and AD-path-expansion suites
```

**Fact-kind namespace** (adopted from the prior obol, used across packs & seed):
`ad.*` (dc_candidate, domain_known, base_dn, user_list, anonymous_bind,
graph.collected, attack_paths, control_paths, trusts, computer_added),
`hash.*` (asrep, tgs, ntlm, krbtgt, tgt), `credential.*` (candidate, available,
plaintext, ntlm_hash, certificate, admin), `kerberos.tickets`, `access.*`
(admin, system, desktop, shell), `foothold.windows`, `foothold.linux`,
`loot.ntds`, `*.reachable` (ldap/smb/kerberos/winrm/http…), `host.*`
(up, hostname, fqdn, domain, os_hint, os_family, kernel, arch — host identity,
OS awareness, and post-foothold local enum, host-scoped;
they enrich a target's label + domain grouping and the engagement map),
`privesc.*` (proof-bound local privilege-escalation leads such as sudo rights,
SUID candidates, dangerous capabilities, Windows privileges, weak service paths;
lead facts unlock abuse paths but do not prove admin/root/SYSTEM),
`winrm.authenticated` / `rdp.authenticated` (a validated interactive login — the
proof behind a §6a session; the shell itself is `foothold.windows`/`foothold.linux`/
`access.shell`), `persistence.*`, and `port:NNN`.
(`access.shell` is an OS-agnostic interactive shell — e.g. a reverse shell
caught by penelope; `foothold.linux` is its Linux counterpart to
`foothold.windows`, forward-looking for the privesc packs.)

## What is BUILT vs STUBBED (read before you build)

**Built & working:** the fact model; the planner (fact-gating, priority ranking,
blocked-with-reason); the Orange AD, web, and Linux/Windows privesc packs; the terminal board;
`explain` (full Orange card — genuinely useful as a live command reference);
the OSCP markdown report (`obol report`); the live web surface (`obol serve`) —
overview with findings charts, the phase-column flow chart, run-from-site for
actions and playbook steps through the shared service, and the report as its main
interface, all updating in real time via SSE; target/scope
persistence; a fixed-argv runner with timeout, dry-run, raw output capture under
`.obol/runs/`; and the first generic parsers for nmap port/service output,
NetExec LDAP/SMB, ldapsearch naming contexts, LDAP user output, and AS-REP hashes.
The first live path is intentionally nmap-first: `obol init --target <ip>` unlocks
fast TCP open-port discovery, parsed ports unlock targeted `-Pn -sC -sV`, and AD
ports/services then unlock the preferred `nxc ldap {{target}} -u '' -p ''` path.

**PARTIAL — this is still the main gap:** execution exists, but parser coverage is
only a narrow first slice. `obol run N` now executes the selected command variant,
saves raw stdout/stderr, parses supported facts, and refuses to invent facts when
no parser matches. Most Orange actions still need parsers before they are fully
real. Do **not** restore the old simulated behavior where `run` blindly records an
action's declared `produces`; that was only a scaffold. A port fact is not a win:
`389/tcp open` may unlock LDAP actions, but it does not prove anonymous bind,
users, credentials, access, or privilege.

**Still missing:** parser coverage across the rest of the Orange AD/web/privesc
packs, remaining sibling packs (pivoting/cracking/shells/database/…), command-composer/preflight controls for the
point-and-click web runner, richer target/input management, and Charon-style
tool-provider/degradation behavior.

## Run / test / regenerate

```bash
pip install -e ".[all]"           # rich + web extras; core has no hard deps
# work in an ENGAGEMENT directory, not the source checkout:
mkdir -p ~/labs/box && cd ~/labs/box && obol init --demo && obol next
obol serve                        # live web surface (needs the [web] extra)
pip install -e ".[test]"          # pytest + FastAPI TestClient for the web tests
python3 -m pytest tests/ -q       # from the repo root
obol debug package                # bundle a review .zip (see docs/DEBUG.md)
pip install -e ".[debug]"         # optional: Playwright for PNG screenshots
# target slice:
mkdir -p ~/labs/box && cd ~/labs/box && obol init --target 10.10.10.10
obol run 1 --dry-run              # preferred first command: nmap -Pn -p- --open
# regenerate the AD pack from the prior obol's data (needs that repo cloned):
node scripts/import_orange_ad.js /path/to/platocres-obol/data/lanes.js \
  > obol/packs/orange_ad_2025_03.json
```

## Working agreements

- Land work as PRs against `main` (repo owner merges).
- Keep the fact/pack contracts above intact; add tests for behavior changes.
- The prior obol (`platocres/obol`), Charon (`platocres/charon`), and PentOS
  (`kaldox/pentos`) are **separate repos** — add them to the session when you need
  their source (see `docs/SOURCES.md`).
