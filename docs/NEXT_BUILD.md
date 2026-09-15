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

## Shipped: Quick Start Orchestrator + Parser Expansion v1

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

## Shipped: scan-populated engagement map + target enrichment v1

The overview map now fills from the same evidence as the terminal workflow:
nmap discovery keeps rDNS identity, nmap/nxc/LDAP parsers emit host-scoped
hostname/FQDN/domain facts, the target record persists that identity, and the web
groups hosts by domain. The engagement graph now renders authorized scope ranges,
discovered targets, evidence-backed domain links, open service nodes, and the
BloodHound overlay without inventing host-to-host relationships from shared
domain facts alone.

## Shipped: terminal parity for scope, scan, help, and overview

The terminal now matches the web's engagement-control surface more closely:
`obol --help` and `obol manual` teach the real operator flow; `obol info` and
`obol version` provide normal app diagnostics; `obol scope add` handles multiple
entries; `obol scope paste` extracts only valid IPs/CIDRs from messy pasted text
or stdin; `obol scan` sweeps every authorized scope entry and then runs the same
nmap-first Quick Start baseline against scoped targets; and `obol overview`
summarizes scope, target identity, domains, ports, access/phase, and top moves in
terminal scrollback.

## Shipped: engagement-level Activity view (run feed + findings roll-up)

Closed out the last piece of item 0 (0e): a dedicated **Activity** view over
`GET /api/engagement/activity`. It answers "what is happening across the whole
engagement" rather than one target at a time:

- **Live run feed** — every sweep and per-host Quick Start job, in-flight and
  recent, with per-step progress. It reuses the existing background-job map and the
  same SSE change feed, so it repaints as commands complete; starting a sweep now
  drops the operator on this view to watch discovery + enumeration stream in.
- **Findings roll-up** — every `supported` fact across all hosts, grouped by
  category (target/service/AD/credential/…), each tagged with the host (or domain)
  that produced it and its cited evidence, with per-host filter chips. Proof-bound
  and secret-redacted like the report; no new fact kinds, no second store.
- **Command ledger** — the cross-host run history (the per-target Commands tab, but
  engagement-wide), each entry tagged with its host or sweep range.

This is the organization/aesthetic layer the roadmap called for — the job engine
was already engagement-bound; nothing about the runner, parsers, or store changed.

## Shipped: sessions layer §6a (one-click login) + secrets shown by default

The first brick of the pivoting feature (`docs/ROADMAP.md §6`). `obol/sessions.py`
offers a one-click login (winrm/ssh/rdp) when a validated password credential + a
reachable service exist. Interactive tools don't fit the capture-and-parse runner,
so each login is PAIRED WITH A NON-INTERACTIVE PROOF run through the shared
`service.run_action`; only once the captured output establishes the access fact
(`foothold.windows`/`foothold.linux`/`rdp.authenticated`) is a LIVE SESSION recorded
(`Workspace.sessions`, a new SQLite table with an active/dead/closed status) and the
interactive command handed off. `probe_session` re-runs the proof to refresh status.
Two narrow proof parsers landed (ssh `uid=`, `nxc rdp [+]`), reusing evil-winrm/exec
for WinRM. Terminal `obol login/sessions/session`; web Access & sessions card +
`/api/run/login` etc. Facts stay the source of truth — the module produces none of
its own. See ROADMAP §6(a) for what's still open (pass-the-hash, penelope listeners,
auto-spawn, the automatic probe loop).

Alongside it, a product decision: **secrets are shown by default across the live
surfaces** (report, findings roll-up, ledger, sessions, run outputs) — redaction is
opt-in (report "redact secrets" toggle, `obol report --redact`, `WEB_SHOW_SECRETS`).
The shareable debug package stays redacted by default.

## Shipped: Parser Coverage v2 + terminal findings roll-up

The evidence engine now recognizes more of the safe, high-signal baseline output
operators see immediately after nmap/Quick Start:

- nmap service/script output now lands proof-bound reachability and metadata facts
  for SSH, FTP, RDP, DNS, SNMP, HTTP redirects/generators, SSH host keys, SNMP
  system info, and anonymous FTP.
- NetExec auth parsing now covers SSH/FTP/RDP as service authentication without
  overclaiming shells, admin, or footholds. WinRM/RDP still use the existing access
  proof rules; SSH only becomes a Linux foothold when command output proves a shell
  (`uid=`/`id`).
- curl/whatweb output now records HTTP responses, redirects, server headers, titles,
  and web technology fingerprints as context only.
- SNMP walk/check output records reachable SNMP, community proof, and system info;
  FTP/SSH banners land as banner facts.
- CLI run feedback now prints compact fact details, and `obol findings` provides
  terminal parity with the web Activity findings roll-up: category-grouped,
  host/domain-tagged findings with evidence source lines and optional redaction.

Boundary kept: these parsers produce context, reachability, service authentication,
or candidate material only. They do not invent vulnerabilities, credentials,
footholds, admin, or loot from banner/metadata output.

## Shipped: Parser QA fixture corpus v1

Parser behavior now has a checked-in QA spine:

- `docs/PARSER_QA.md` documents how parsers are created, what they may claim, what
  they must not claim, and how fixture confidence should be interpreted.
- `tests/fixtures/parser/manifest.json` defines positive, negative, and
  anti-overclaim cases over anonymized, real-shaped outputs.
- `tests/test_parser_fixtures.py` runs every fixture through `parse_action_output`
  and asserts expected fact kinds, selected payload values, source lineage, refuted
  failures, and forbidden higher-value claims.
- The first corpus covers nmap service/script metadata, curl/whatweb HTTP
  metadata, NetExec SSH/FTP auth, failed auth, SSH banner vs shell proof, SNMP
  timeout, and FTP named-login edge cases.

The fixture suite also caught and fixed an nmap SNMP parser gap for `|_` final
script lines, which is exactly the kind of regression this corpus is meant to
surface.

## Shipped: Host OS awareness + changelog discipline

Enumeration now records OS evidence as facts instead of leaving OS as an unused
target field. Parsers emit `host.os_hint` for clues and `host.os_family` only from
strong, non-conflicting evidence, such as nmap/NetExec OS strings, SNMP
descriptions, WinRM/RDP/SSH proof output, or Penelope shell metadata. Unknown OS
stays permissive; once a target is proven Linux or Windows, wrong-platform actions
are filtered out of next moves and tool palettes. The OS family is shown in terminal
overview, web target cards, target overview, engagement map subtitles, Useful
facts, and reports.

The repo now has a backfilled `CHANGELOG.md`, `AGENTS.md` directs agents to read
and update it, and the test suite includes a changelog enforcement check for
meaningful code/docs changes.

## Current build: Post-foothold privesc packs v1

Linux and Windows privilege-escalation lanes now load as sibling Orange-derived
packs. A proven foothold unlocks the OS-matched local enumeration card; parsed
local enum facts (`privesc.sudo_rights`, `privesc.suid_candidate`,
`privesc.capability`, `privesc.windows_privilege`,
`privesc.always_install_elevated`, weak service path facts, and related leads)
unlock the specific abuse cards they justify. The packs stay proof-bound: lead
facts do not become admin/root/SYSTEM, and privileged access is recorded only when
command output proves `uid=0`/root or `nt authority\system`.

Privesc facts are first-class findings. They appear in each host's Useful Facts and
Findings tables, in the engagement Activity roll-up under **Privilege escalation**,
in reports, and in the path graph's escalation phase.

## Shipped: Parser Coverage + Fixture Corpus v3

The parser QA spine now covers higher-value, post-baseline output shapes without
weakening proof boundaries:

- NetExec SAM dumps and secretsdump/NTDS output land `hash.ntlm`,
  `credential.candidate`, `hash.krbtgt`, and `loot.ntds` only when the transcript
  supports those exact claims; they never become plaintext credentials or access.
- BloodHound collection and BloodHound path analysis are separated: a collection
  archive proves `ad.graph.collected`, while explicit path-analysis text proves
  `ad.attack_paths`.
- SQLMap output can now prove confirmed SQLi, database names/tables, database
  credential-material candidates, and SQLMap webshell context. It still does not
  prove OS privilege, lateral access, or validated credentials.
- Exposed Git recovery (`/.git/HEAD` / `git-dumper`) records `web.source` and
  source-code secret candidates without converting a found string into a working
  credential.
- The fixture manifest adds real-shaped positive and anti-overclaim cases for all
  of the above plus Linux/Windows privesc enum leads.

## Shipped: AD Abuse Success-Signal Parser Coverage v1

The AD abuse cards now have a first success-signal parser slice beyond roast/crack
and lateral-exec basics:

- `bloodyAD` / DACL-style output can record `ad.control_paths` when the transcript
  shows writable rights or a successful group/owner/GenericAll change.
- Impacket addcomputer output records `ad.computer_added` plus candidate
  machine-account material, without turning it into a validated login.
- RBCD writes and getST output record `ad.control_paths` and `kerberos.tickets`
  without claiming host admin until a service accepts the ticket and command output
  proves it.
- NetExec LAPS and gMSA hash output record LAPS password candidates and
  `credential.ntlm_hash` material without creating blanket admin access or
  host-scoped login offers for the wrong target.

The fixture corpus now locks these boundaries with AD-abuse positive and
anti-overclaim cases.

## Queued next (designed, not yet built)

Captured in `docs/ROADMAP.md` so agents don't have to rediscover them:

- **Parser coverage (ROADMAP item 1, still important).** v3 covers the biggest
  post-baseline gaps: NXC/SAM/NTDS material, BloodHound collection vs. path
  analysis, SQLMap success signals, git-dumper source recovery, and privesc leads.
  The AD-abuse success-signal slice now covers ACL writes, addcomputer/RBCD/getST,
  LAPS, and gMSA material. Continue with more real fixtures from operator runs,
  tunnel/proxy failure transcripts, Rubeus/TGT capture output, trust/SCCM support
  branches, and exploit-card success signals that still lack proof-bound parsers.
- **Pivoting continues (ROADMAP §6 c–f).** §6(a) sessions and item 3 privesc packs
  shipped. Next is post-foothold host/network enum (`host.multihomed`) → one-click
  tunnels + route-aware runner (auto-proxychains for SOCKS, transparent for ligolo)
  → auto-extend scope → through-tunnel sweep (recursion + health proof) → topology
  map.
- **Engagement profile & flag awareness (ROADMAP §7).** Platform/exam type + per-
  target `machine_type` + proof-bound flag capture. Interlocks with §6 and item 3
  (see the ROADMAP §6 interlock note). Mines Pentest Companion (`docs/SOURCES.md §5`).
- **Payload staging & tool provisioning (ROADMAP §8) — needs deeper discussion.**
  One-click upload/staging to a foothold, a Kali material cache (locate/cache/upload),
  and one-click download of missing items. Deferred pending a design conversation.
- **Remaining found-items** in ROADMAP "Known smaller issues": the engagement-map
  credential fix and an engagement-wide redact switch for the findings/ledger
  surfaces.

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
