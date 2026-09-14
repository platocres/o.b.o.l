# Next build queue after OSCP report v1

## Shipped: SQLite store, live SSE deltas, morphdom UI, debug package

An architecture pass replaced the single `state.json` with a SQLite store
(`obol/store.py`, `.obol/state.db`) so the terminal and web can both write the same
engagement without clobbering (WAL + idempotent, targeted writes); `state.json`
stays as the export/report/snapshot/migration format. The web SSE endpoint now tails
the store's `events` change feed and pushes *what changed*, and the SPA patches the
DOM with vendored **morphdom** through one delegated `data-act` handler (no full
re-render, no build step). New `obol debug package` / `obol debug capture` bundle a
review `.zip` for AI-agent review, including terminal + site PNG screenshots when a
headless browser is present. See `docs/ARCHITECTURE.md` and `docs/DEBUG.md`.

## Shipped: live web feedback, facts, composer, and Quick Start

PR #17 shipped point-and-click run feedback and the target **Useful facts** memory
panel. PR #18 shipped the command composer/preflight layer plus a visible
per-target **Quick Start** button that runs nmap first and then safe service-aware
enumeration, including nxc-first AD/SMB checks.

## Current build: Quick Start Orchestrator + Parser Expansion v1

Quick Start should feel alive, not like one long blocking request. This build turns
Quick Start into a background job with a live step timeline:

- start immediately and return a job id;
- show queued / running / success / failed / skipped / blocked for each step;
- show the exact command for each running/completed step;
- show facts parsed and stored per step and in the aggregate result;
- tick the existing SSE stream when job state changes so the page updates without
  refresh;
- bind the job to the engagement it started in, even if the operator changes the
  active engagement later.

Parser expansion for this build focuses on the safe baseline tools Quick Start
runs: nmap service/script output, nxc SMB/LDAP banners and shares, ldapsearch
naming contexts/users, ffuf/feroxbuster/gobuster/dirb web paths, vhost hits, and
nikto candidate leads. These facts must remain proof-bound: no exploit, credential,
admin, or foothold fact is created from basic enumeration output.

This queue exists so agents do not drift after each build lands.

## 1. Playbook data model and dry-run runner — DONE

A playbook is a named, ordered list of evidence-gathering steps, stored as data
(`obol/playbooks/*.json`) alongside the packs. Each step names an existing pack
action by id; running a step goes through the exact same command templating, scope
enforcement, runner (`runner.run_command`), parser (`parsers.parse_action_output`),
and `.obol` store as `obol run`. No second runner and no second state store —
`cli._run_action` is the single shared execution path.

Shipped slice (`obol/playbook.py`, `obol/board.render_playbook`, CLI):

- `obol playbooks` lists available playbooks.
- `obol playbook <name>` renders the exact command plan (executes nothing).
- `obol playbook <name> --step N` runs one step through `run_command`; `--dry-run`
  previews just that step's command.
- Steps can mark `require_approval: true` for noisy or risky actions; such a step
  refuses to run without `--approve`.
- The ledger records `playbook`/`playbook_step` lineage per run.
- First playbook: `ad-recon` — nmap quick scan, targeted nmap, DC identify,
  anonymous LDAP, SMB/RID user enum (the RID-brute step is approval-gated).

Follow-ups worth doing next on playbooks:

- Add a second playbook (e.g. SMB-first null/guest/shares) once an SMB-heavy slice
  is worthwhile.
- Consider an opt-in `--run-all` that walks the whole sequence, pausing at
  `require_approval` steps — deliberately left out of the first slice to keep
  execution one deliberate step at a time.

## 2. Web run-from-site

Add localhost-only POST endpoints to execute one selected command variant through
the same runner and parsers used by `obol run`.

Rules:

- Bind only to `127.0.0.1`.
- No remote execution API.
- No separate state format.
- No bypass around scope validation.
- Web should be a second surface over the same operator loop, not SaaS.

## 3. HTTP pack export — DONE

Exported the old-obol web lane into a sibling pack (`obol/packs/orange_web_2025_03.json`,
23 actions) via `scripts/import_orange_web.js`. The planner now merges packs
(`pack.load_packs`), so an HTTP port from the nmap spine unlocks the web recon
actions.

Shipped slice:

- HTTP/HTTPS reachability already came from nmap parsing (`http.reachable`); the
  web pack consumes it.
- Fact kinds remapped onto the shared namespace (`web.reachable → http.reachable`,
  `shell.reverse → access.shell`) with narrowest-claim fixes (WordPress user enum
  is `web.users`, not `ad.user_list`).
- Parsers for content discovery (gobuster/feroxbuster/ffuf/dirb), virtual hosts,
  and nikto findings — each mapping to `web.content_map` / `web.vhost` /
  `exploit.candidate`, with anti-overfit tests and 404s excluded.
- Findings stay candidate/context; no parser claims a confirmed vuln, foothold, or
  access from recon output.
- A `web-recon` playbook (content discovery → nikto → vhost) demonstrates
  cross-pack playbook resolution.

Follow-ups worth doing next on web:

- Parsers for the exploitation cards' success signals (sqlmap `--dbs`/`--os-shell`,
  git-dumper source, whatweb/curl tech + titles) so those cards become executable.
- A phase/flow model (item 4 / roadmap item 2) so web recon and AD recon interleave
  sensibly when both surfaces are open.

## 4. Path-map phase redesign

Move the path map away from a raw dependency DAG and toward a phase/lane layout:
Recon, Enumeration, Credentials, Access, Privilege, Loot, Report.

Do not reintroduce blocked branches into the user-facing board or web view.

## Current build addition: Command Composer + Quick Start

The web surface should make point-and-click execution explain itself before and
after every command:

- each command variant carries a preflight result from the same command renderer
  the shared runner uses;
- missing facts or operator inputs are shown inline, with promptable values saved
  into the engagement input store;
- missing binaries resolve against the Tools inventory before Run is enabled;
- shell pipelines/redirection are treated as copy/manual handoff, not silent web
  execution;
- parser coverage is visible before a run, and successful runs still show the
  facts actually parsed and stored in real time;
- each target card and target header exposes a **Quick Start** button;
- Quick Start runs the nmap spine first, then re-evaluates the new facts to run
  only safe baseline enumeration unlocked by the target's exposed services;
- nxc is preferred for the AD/SMB baseline where pack variants support it;
- credential attacks, exploit probes, dumps, shell launchers, spraying, and
  privilege/loot actions stay out of the automatic starter lane;
- dry-run remains a lower-level CLI/backend compatibility feature, not a primary
  website control.
