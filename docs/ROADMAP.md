# Roadmap & status

Priority order. Item 1 is what the tool most needs to become usable on a live box.

## Done

- **Vertical slice** (PR #1's base): fact model, planner, terminal board, read-only
  web view + mermaid path graph, `explain`, tests.
- **Multi-target engagement platform:** an app-managed engagement library
  (`obol/library.py`, `$OBOL_HOME`) of engagements, each holding many targets
  (`workspace.targets`, per-target fact scoping via `facts_for_target`). The web is
  a tabbed per-target console (Overview with an attack-chain bar + per-target path,
  a service-aware point-and-click Tools palette, Playbooks, a static Checklist,
  Findings, Evidence/screenshots, Commands), plus an engagement-wide attack path
  that stitches targets to the shared domain and a **BloodHound** overlay
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

- **`web` (23) — DONE.** `obol/packs/orange_web_2025_03.json` via
  `scripts/import_orange_web.js`; the planner merges packs (`pack.load_packs`), so
  an HTTP port unlocks web recon after the nmap spine. Fact kinds are remapped onto
  the shared namespace and kept to their narrowest claim. Recon parsers
  (content discovery, vhosts, nikto) landed; the exploitation cards remain
  explain-only until their success-signal parsers exist. Next lanes:
  `linux-privesc` / `windows-privesc`.

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
- **Real-time — DONE.** `/api/events` (SSE) watches the state file and pushes a tick
  on any change — web- OR terminal-launched — so every open page refreshes itself.
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
- **Tool availability — STILL PENDING** (from Pentest Companion
  `kali_tools`/`tools_status`): show which referenced tools are installed, with a
  simple manual/poll refresh. This is the main remaining web item.

## UX guardrails (product decision — keep these)

This is a fast OSCP-exam tool. The UI shows **only the live options that matter**:
no "blocked until X" list and no "proves / does not prove" language anywhere the
user sees. The fact-gating engine (`requires`/`produces`, `blocked_actions()`)
stays internal — it decides what's live; it is not surfaced. Do not reintroduce
blocked/proof panels in `board.py` or `web.py`.

## Known smaller issues

- `run`'s "new facts" detail line is still sparse for port/service facts.
- Exam-flow ranking (item 2) still surfaces some actions oddly (e.g. spraying
  ahead of roasting).
- `obol web` (the static one-file snapshot) still embeds mermaid from a CDN, so its
  path graph is blank offline. The live `obol serve` surface is fully offline
  (vendored Chart.js, SVG flow chart); porting the static snapshot onto
  `build_graph_model`'s SVG renderer would close the gap.
- The web surface loads the whole `.obol/state.json` per request — fine for a single
  box / the exam, but see the state-model note before scaling to large multi-host
  engagements (flat fact list, whole-file rewrites, single-target shape).
