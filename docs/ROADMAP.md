# Roadmap & status

Priority order. Item 1 is what the tool most needs to become usable on a live box.

## Done

- **Vertical slice** (PR #1's base): fact model, planner, terminal board, read-only
  web view + mermaid path graph, `explain`, tests.
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

## 1. Expand parser coverage and service-specific playbooks (TOP PRIORITY)

`run` is no longer a pure stub, but execution is only real where parser coverage
exists. The current spine is:

- `obol init --target <ip>`
- quick nmap all-port discovery
- targeted `nmap -Pn -sC -sV -p {{nmap_ports}}`
- port/service facts unlock AD moves
- LDAP/389 leads to `nxc ldap` and `ldapsearch`

Next work should widen this carefully:

- **More service parsers.** Add generic parsers for SMB share/session output,
  WinRM validation, HTTP enumeration, FTP/SSH banners, SNMP, and common nmap NSE
  script findings. Every parser must map output to the narrowest fact and include
  anti-overfit tests.
- **Better port-to-playbook gating.** The Orange AD pack now has a small exam-flow
  priority override for nmap → DC identify → anonymous LDAP → user enum. Extend
  that idea across web/privesc sibling packs without hardcoding box wins.
- **Parser fixtures from real tools.** Use Forest and other lab outputs as golden
  regressions, but never as recipes. Fixture names should vary so tests prove
  shape recognition, not walkthrough memorization.
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
on PentOS and Pentest Companion (`docs/SOURCES.md`). It reuses the *same*
scope-enforced runner + parsers + `.obol` store as the terminal.

- **Run from the site.** Let the user launch an action's command from the web
  page; it goes through the same runner/parser and writes the same store, so both
  surfaces reflect it. This needs the current stdlib `http.server` to grow small
  POST endpoints (or move to a tiny FastAPI/Flask app like PentOS's) — keep it
  localhost-bound; never expose execution off-box. Do not add a second runner or
  a second state store.
- **Playbooks (both surfaces).** A playbook is a named, ordered list of steps,
  each `{label, action_id, cmd?, args_extra?, require_approval?}`, stored as data
  alongside packs. Run live or dry-run; pause for approval before noisy/risky
  steps; creds propagate from workspace facts via the shared command context.
  Pentest Companion's `tools/playbook_engine.py` is the reference (learn, don't
  copy). Playbooks get a useful batch of evidence back in one move and present it
  neatly. **The terminal side has landed** (`obol/playbook.py`, `ad-recon`); the
  web still needs to render the plan and run steps once run-from-site exists.
- **Path-map redesign.** Keep the map (users like it) but make it clearer. The
  current `graph.py` is a light top-down declutter (path walked + live moves, no
  blocked branches). The reference for "much more straightforward" is the prior
  **platocres/obol** path view — study how it lays out the methodology path
  (phase/lane progression rather than a dependency DAG) and match that feel; this
  likely means adding a phase/stage to pack actions and grouping the map by it.
- **Tool availability** (from Pentest Companion `kali_tools`/`tools_status`): show
  which referenced tools are installed. Live refresh (poll or manual) — simple.

## UX guardrails (product decision — keep these)

This is a fast OSCP-exam tool. The UI shows **only the live options that matter**:
no "blocked until X" list and no "proves / does not prove" language anywhere the
user sees. The fact-gating engine (`requires`/`produces`, `blocked_actions()`)
stays internal — it decides what's live; it is not surfaced. Do not reintroduce
blocked/proof panels in `board.py` or `web.py`.

## Known smaller issues

- `run`'s "new facts" detail line is still sparse for port/service facts.
- The web view has key findings + a path map, but is not yet the final OSCP-style
  evidence report.
- Exam-flow ranking (item 2) still surfaces some actions oddly (e.g. spraying
  ahead of roasting).
