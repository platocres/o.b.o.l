# Changelog

All notable changes to obol are recorded here. Agents must update this file
for every user-facing, code, pack, parser, runner, report, or documentation build.

## Unreleased

### Added

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

### Changed

- Local privilege escalation leads now unlock their matching abuse cards without
  claiming admin/root/SYSTEM unless command output explicitly proves it.
- Parser fixture expectations now include OS facts where the existing transcripts
  already contain strong OS evidence.

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
