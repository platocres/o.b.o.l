# Next build queue after OSCP report v1

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

## 3. HTTP pack export

Export the old-obol web lane into a sibling pack so HTTP ports unlock real web
recon actions after the nmap spine.

Minimum useful slice:

- HTTP/HTTPS reachability already exists from nmap parsing.
- Add gobuster/ffuf/nikto/whatweb/curl actions as data.
- Add parsers for titles, status-code discoveries, interesting files, vhosts, and
  directory hits.
- Keep findings as candidate/context until exploitation or authenticated access is
  actually proven.

## 4. Path-map phase redesign

Move the path map away from a raw dependency DAG and toward a phase/lane layout:
Recon, Enumeration, Credentials, Access, Privilege, Loot, Report.

Do not reintroduce blocked branches into the user-facing board or web view.
