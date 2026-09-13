# Roadmap & status

Priority order. Item 1 is what the tool most needs to become usable on a live box.

## Done

- **Vertical slice** (PR #1's base): fact model, planner, terminal board, read-only
  web view + mermaid path graph, `explain`, tests.
- **Orange AD pack** (30 actions) exported from the prior obol and driving the
  planner; proof boundaries test-locked. See `docs/SOURCES.md`.
- **init robustness**: friendly error on an unwritable/`sudo`-owned directory;
  workspace-vs-source-tree guidance.

## 1. Make `obol run` real — runner + parser + target config (TOP PRIORITY)

Today `run` is stubbed (`pack.apply_action` just records declared `produces`; no
execution, no parsing, no target beyond the fixture). This item turns obol from a
planner+reference into an executor. Build it as one or two PRs:

- **Target/scope config.** `obol init --target <ip/host>` (already parses
  `--target`; wire it through), plus `obol scope add <ip|cidr>`. Persist scope in
  the workspace. **Scope enforcement is a hard gate** (AGENTS.md principle 4): the
  runner refuses any target not in scope. Model this on Charon's authorization
  manifest and PentOS's runner (`docs/SOURCES.md`) — reimplement, don't copy
  Charon.
- **Runner.** A safe executor: fixed argv (no shell by default), timeout, raw
  output saved under `.obol/`, dry-run. PentOS `runners/base.py` is the MIT
  reference. Fill the `{{token}}` command templates from facts/scope
  (`board.command_context` already does token fill).
- **Parsers = where the proof contract is enforced under execution.** Each parser
  maps real tool output to the **narrowest** supported fact. Start with the LDAP
  family (nxc `--users` / ldapsearch / windapsearch) so `obol run` on the anon-LDAP
  action produces a *real* `ad.user_list` with actual usernames. Add a parser test
  that feeds known Forest output and asserts it does **not** over-claim (e.g. a
  user list is not a credential). This is the single most important discipline to
  get right — auto-ingest is where "it ran" tries to become "it worked."
- Wire `run` to: fill command → scope-check → execute → save raw → parse → record
  facts (with real values + `source`) → recompute board.

## 2. Exam-flow ranking

Priorities are currently derived from the produced fact's "value" in
`scripts/import_orange_ad.js`, so a few actions sort oddly (e.g. Kerberos
Ticket-Hygiene ahead of Anonymous LDAP Enumeration on a fresh DC). Add a phase/flow
weighting so enumeration sorts first for OSCP flow. Small change; can ride with
item 1 or stand alone.

## 3. Sibling packs (web, privesc, pivoting, cracking, …)

Export the remaining prior-obol lanes into packs using the AD converter as the
template (`docs/SOURCES.md` §2). Order by OSCP value: `web` (23) and
`linux-privesc`/`windows-privesc` next, since OSCP is not AD-only. Each pack must
reuse the shared fact-kind namespace so cross-domain gating works (e.g. a web
foothold producing `linux.shell` unlocks the privesc pack).

## 4. OSCP report generation

`obol report` narrated from the run ledger (`Workspace.runs`) + facts + lineage
(`Fact.source`). The activity ledger already preserves sequence, so the report
comes largely free. Reuse the single graph projection (`graph.py`) for the report's
path diagram. Output markdown first; the report must cite evidence (each claim →
the command/output that produced it) and must never present project metadata as
engagement proof.

## 5. Robust web surface — run-from-site, playbooks, path-map redesign

The web view should become a real second surface (still localhost-only), modeled
on PentOS and Pentest Companion (`docs/SOURCES.md`). Depends on item 1's runner.

- **Run from the site.** Let the user launch an action's command from the web
  page; it goes through the *same* scope-enforced runner + parser as the terminal,
  writes to the *same* `.obol` store, and both surfaces reflect it. Do not add a
  second state store or a second runner. This needs the current stdlib
  `http.server` to grow small POST endpoints (or move to a tiny FastAPI/Flask app
  like PentOS's) — keep it localhost-bound and never expose execution off-box.
- **Playbooks (both surfaces).** A playbook is a named, ordered list of steps,
  each `{label, action/tool, args_extra?, require_approval?}`, stored as data
  alongside packs. Run live or dry-run; pause for approval before noisy/risky
  steps; propagate creds from workspace facts into steps. Pentest Companion's
  `tools/playbook_engine.py` (`BUILTIN_PLAYBOOKS`, daemon-thread step runner,
  approval + dry-run + credential propagation) is the reference design — learn
  from it, don't copy (it's a separate project). Playbooks let a user get back a
  useful batch of evidence in one move and present it neatly.
- **Path-map redesign.** Keep the map (users like it) but make it clearer. The
  current `graph.py` is a light top-down declutter (path walked + live moves, no
  blocked branches). The reference for "much more straightforward" is the prior
  **platocres/obol** path view — study how it lays out the methodology path
  (phase/lane progression rather than a dependency DAG) and match that feel. This
  likely means adding a phase/stage to pack actions and grouping the map by it.
- **Tool availability** (nice-to-have, from Pentest Companion `kali_tools` /
  `tools_status`): show which referenced tools are installed on the box.
- Live refresh (poll or manual). Keep it simple for a single local user.

## Known smaller issues

- Graph layout is spaghetti-ish with many blocked-but-near actions shown.
- `run`'s "new facts" detail line was written for the old fixture's rich values;
  with the Orange pack most produced facts have empty `{}` values until item 1
  gives parsers real ones.
