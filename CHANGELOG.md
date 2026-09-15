# Changelog

All notable changes to obol are recorded here. Agents must update this file
for every user-facing, code, pack, parser, runner, report, or documentation build.

## Unreleased

### Added

- Added post-foothold flag capture: a thorough, non-interactive search for the
  well-known flag files (`user.txt`, `root.txt`, `local.txt`, `proof.txt`,
  `flag.txt`) run through the existing SSH/WinRM proof channel once a foothold is
  proven (`flag-hunt-linux`, `flag-hunt-windows` in the new
  `obol_flag_hunt_2026_09` pack), gated on a proven foothold + credential and
  routed through the one runner/parser/store path.
- Added a proof-bound flag parser (`obol/flags.py`) that records an `objective.*`
  fact (`objective.local_flag` / `objective.root_flag` / `objective.flag`,
  host-scoped) only when a flag file was actually read and its content looks like a
  real flag (hex, brace-format, or a lone short token), citing the command that
  captured it — a captured flag is proof, not a checkbox.
- Added an `objective` finding category so captured flags appear in the engagement
  findings roll-up, the report, and the evidence-by-category chart.
- Added per-target captured-flag display on the web engagement screen: each target
  card shows a flag count pill and the captured flag values, fed by a new `flags`
  list in the per-target report rollup.
- Added flag-capture parser regressions covering local/root capture, Windows
  marker output, action-id scoping, empty/unreadable output, non-flag filenames,
  de-duplication, value-extraction boundaries, and the per-target rollup.

- Added post-foothold host/network enumeration actions for Linux and Windows
  footholds, gated on proven shell/session facts and routed through the existing
  runner/parser/store path.
- Added `sshpass` to the tool inventory so Linux post-foothold SSH enum actions
  have install/preflight parity with the rest of the Tools page.
- Added pivot-candidate parsing for Linux `ip`/resolver output and Windows
  `ipconfig`/`route`/`arp`/`netstat` output, producing narrow facts for interfaces,
  IPs, routes, neighbors, DNS servers, listening sockets, multi-homed hosts, and
  candidate adjacent subnets without claiming a working tunnel.
- Added parser regressions for Linux and Windows local network enumeration and
  pivot-candidate overclaim boundaries.
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
- Added pass-the-hash logins to the sessions layer: a dumped SAM/NTDS NT hash
  (`hash.ntlm` entries) or a validated credential carrying an `nthash` now logs in
  over WinRM (`nxc winrm -H` proof → `evil-winrm -H` handoff) and RDP via Restricted
  Admin, with no cracking. `eligible_sessions`/`open_session` auto-pick a password
  when one exists and otherwise fall back to pass-the-hash, preferring an
  Administrator hash and skipping machine accounts and `krbtgt`.
- Added `obol login --method password|pth` and a web login `method` so the operator
  can force either auth method; the web Access & sessions card surfaces
  "pass-the-hash".

### Changed

- Local privilege escalation leads now unlock their matching abuse cards without
  claiming admin/root/SYSTEM unless command output explicitly proves it.
- Validated-credential recording is now hash-aware: a `user:<hash>` NetExec auth
  line or an `evil-winrm -H` login is recorded as an `nthash` (`method: pth`) rather
  than mislabeled as a plaintext password, and the chosen credential is pinned into
  session proof/login commands via a template `context` override so the exact hash
  is used instead of whichever credential sorts first.
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
