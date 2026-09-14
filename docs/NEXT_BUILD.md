# Next build queue after OSCP report v1

## Current build addition: live web run feedback + target fact memory

Point-and-click execution should not feel like a black box. When the web launches
an action or playbook step, the target page should immediately show a run-result
panel with:

- running / dry-run / success / failed / timeout status;
- the exact redacted command that was attempted;
- return code, duration, and raw evidence paths;
- every new fact parsed and stored from the command output;
- a small stdout/stderr preview when a command fails or produces no parsed facts.

Each target overview should also show a grouped **Useful facts** memory panel built
from the same fact store: target state, ports/services, directory/domain context,
credentials and hashes, access, web leads, and loot/review material. This is both
operator working memory and report source material. It must update via the existing
SSE state refresh, with no manual page refresh and no second state store.

The next larger build remains the **Command Composer + Run Preflight v1**: structured
inputs/toggles for the commands, parser-support indicators, missing-tool warnings,
missing-variable warnings, approval gates, and copy/dry-run/run controls.

This queue exists so agents do not drift after the report build lands.

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
