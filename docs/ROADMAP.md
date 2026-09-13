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

## 5. Web view refinements

The mermaid graph gets busy at the full frontier. Options: rank-group by phase,
collapse settled chains, or filter to the near frontier more aggressively. Add
live refresh (poll or manual) if desired — keep it read-only and localhost-only.

## Known smaller issues

- Graph layout is spaghetti-ish with many blocked-but-near actions shown.
- `run`'s "new facts" detail line was written for the old fixture's rich values;
  with the Orange pack most produced facts have empty `{}` values until item 1
  gives parsers real ones.
