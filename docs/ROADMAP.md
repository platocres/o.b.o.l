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

## 5. Web view refinements

The mermaid graph gets busy at the full frontier. Options: rank-group by phase,
collapse settled chains, or filter to the near frontier more aggressively. Add
live refresh (poll or manual) if desired — keep it read-only and localhost-only.

## Known smaller issues

- Graph layout is spaghetti-ish with many blocked-but-near actions shown.
- `run`'s "new facts" detail line is still sparse for port/service facts.
- The web view now has key findings, but it is still a simple mirror, not the final
  OSCP-style evidence report.
