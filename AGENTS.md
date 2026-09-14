# obol — agent entrypoint

Read this first, then [`docs/SOURCES.md`](docs/SOURCES.md) (where the methodology
and reference code live) and [`docs/ROADMAP.md`](docs/ROADMAP.md) (what to build
next). The same contract applies to any coding agent (Claude, ChatGPT, etc.).
`CLAUDE.md` points here.

## What obol is

An **evidence-driven OSCP operator companion**. Terminal-first, PentOS-style shell
subcommands. The operator drives one deliberate command at a time; obol keeps a
conservative model of what has actually been **proven** and recommends the next
best action from that model. Built for the OSCP exam: the terminal scrollback is
the operator's evidence log.

**What makes it different** from the tools it learns from (see `docs/SOURCES.md`):
a **fact-gated decision model** — actions are gated on proven facts (each carrying
a `ProofState`) instead of a stateless service→tool map, so the moves it surfaces
are the ones that actually matter *now*. The gating is an internal engine detail;
the UI shows clean, ranked **live options only** — it does NOT lecture users with
"proves / does not prove" or "blocked until X" text (a deliberate product
decision: this is a fast OSCP-exam tool). And **one state, multiple synced
views**: the terminal drives, a web page mirrors it (and, planned, can drive it
too), and an OSCP report is narrated from the same fact/run ledger.

## The non-negotiable principles (the "always/never")

1. **Facts are the source of truth.** Nothing is true unless a `Fact` records it,
   scoped to exactly what the evidence supports, with a `ProofState`
   (`supported`/`refuted`/`inconclusive`) and the command that produced it. An
   action **never records more than the facts it actually establishes** — a WinRM
   login yields *authenticated user*, not *admin*; an AS-REP hash is *crackable
   material*, not *a credential*. Preserve this when you add parsers: map output
   to the narrowest supported fact, prefer no fact over a convenient one. **This
   discipline is internal** — it drives which options are live; it is NOT surfaced
   as proof/blocked language in the UI (see the differentiator note above).
2. **Methodology is data, not code.** Actions live in `obol/packs/*.json` and are
   loaded by the planner. Add methodology by adding pack entries, **never** by
   putting box-specific or branch-specific logic in the planner.
3. **Terminal and web are both actors over one shared state.** Either surface may
   launch a run through the same scope-enforced runner; both stay synced through
   the single `.obol` store (the web is localhost-only). The web is read-only
   today; running-from-site is planned — until it lands, keep the web read-only.
   Never create a second state store for the web.
4. **Scope enforcement is mandatory for the runner** (`obol/scope.py`,
   `obol/runner.py`). It may only touch an authorized target — a hard gate, not a
   noise tier — and it applies equally to terminal-, web-, and playbook-launched
   runs. **Playbooks** are named, ordered sequences of pack actions, stored as
   data, runnable from terminal and web, with per-step approval for noisy/risky
   steps (see `docs/ROADMAP.md`, modeled on Pentest Companion).
5. **The path graph is projected once** (`graph.py`) and rendered to every surface
   (terminal board, web mermaid, report), so surfaces never disagree.
6. **Tool/action contract** (inherited from the prior obol): an action is only
   "real" when it generates realistic commands (no fabricated seed values),
   ingests output as evidence, respects proof boundaries, and carries operator
   guidance. A card that only renders is not implemented.
7. **OSCP posture:** print to scrollback, never a full-screen live dashboard;
   degrade to plain text when `rich` is absent.
8. **Licensing:** Orange-derived packs are GPL-3.0 and kept as distinct,
   attributed data components (`obol/packs/NOTICE.md`). Do not fold pack contents
   into differently-licensed core code.

## Architecture / module map

```
obol/
  facts.py       Fact + ProofState + FactSet (the source of truth)
  workspace.py   .obol/state.json load/save; find_workspace() walks up like git
                 target/scope/input persistence; raw run ledger paths
  pack.py        Action model + planner (next_actions / blocked_actions /
                 apply_action) + load_pack(); friendly() names fact kinds
  packs/         methodology packs as DATA (+ NOTICE.md attribution)
    orange_ad_2025_03.json   nmap prelude + 30 Orange AD actions
  board.py       terminal render (rich + plain fallback); {{token}} templating;
                 explain view shows the full card (hypothesis, commands, refs)
  scope.py       target normalization + exact/CIDR scope checks
  runner.py      fixed-argv runner; timeout, dry-run, raw output capture
  parsers.py     evidence parsers; generic nmap/nxc/LDAP output -> narrow facts
  graph.py       facts+actions -> mermaid path graph (the single projection)
  web.py         read-only localhost web view (findings + path graph)
  seed.py        Forest demo fixture (post-nmap facts)
  cli.py         subcommands: init / next / explain / run / scope / facts / serve / web
scripts/
  import_orange_ad.js   converter: old-obol lanes.js AD lane -> pack JSON
tests/
  test_pack.py      pack loads, proof boundaries, gating, seed unlocks chain
  test_parsers.py   parser proof boundaries; no walkthrough-name hardcoding
```

**Fact-kind namespace** (adopted from the prior obol, used across packs & seed):
`ad.*` (dc_candidate, domain_known, base_dn, user_list, anonymous_bind,
graph.collected, attack_paths, control_paths, trusts, computer_added),
`hash.*` (asrep, tgs, ntlm, krbtgt, tgt), `credential.*` (candidate, available,
plaintext, ntlm_hash, certificate, admin), `kerberos.tickets`, `access.*`
(admin, system, desktop), `foothold.windows`, `loot.ntds`, `*.reachable`
(ldap/smb/kerberos/winrm/http…), and `port:NNN`.

## What is BUILT vs STUBBED (read before you build)

**Built & working:** the fact model; the planner (fact-gating, priority ranking,
blocked-with-reason); the Orange AD pack (30 actions); the terminal board;
`explain` (full Orange card — genuinely useful as a live command reference);
the read-only web view with key findings + the mermaid path graph; target/scope
persistence; a fixed-argv runner with timeout, dry-run, raw output capture under
`.obol/runs/`; and the first generic parsers for nmap port/service output,
NetExec LDAP/SMB, ldapsearch naming contexts, LDAP user output, and AS-REP hashes.
The first live path is intentionally nmap-first: `obol init --target <ip>` unlocks
fast TCP open-port discovery, parsed ports unlock targeted `-Pn -sC -sV`, and AD
ports/services then unlock the preferred `nxc ldap {{target}} -u '' -p ''` path.

**PARTIAL — this is still the main gap:** execution exists, but parser coverage is
only a narrow first slice. `obol run N` now executes the selected command variant,
saves raw stdout/stderr, parses supported facts, and refuses to invent facts when
no parser matches. Most Orange actions still need parsers before they are fully
real. Do **not** restore the old simulated behavior where `run` blindly records an
action's declared `produces`; that was only a scaffold. A port fact is not a win:
`389/tcp open` may unlock LDAP actions, but it does not prove anonymous bind,
users, credentials, access, or privilege.

**Still missing:** report generation, richer target/input management, parser
coverage across the rest of the Orange AD pack, sibling packs (web/privesc/etc.),
and Charon-style tool-provider/degradation behavior.

## Run / test / regenerate

```bash
pip install -e ".[rich]"          # rich optional; obol degrades without it
# work in an ENGAGEMENT directory, not the source checkout:
mkdir -p ~/labs/box && cd ~/labs/box && obol init --demo && obol next
python3 -m pytest tests/ -q       # from the repo root
# target slice:
mkdir -p ~/labs/box && cd ~/labs/box && obol init --target 10.10.10.10
obol run 1 --dry-run              # preferred first command: nmap -Pn -p- --open
# regenerate the AD pack from the prior obol's data (needs that repo cloned):
node scripts/import_orange_ad.js /path/to/platocres-obol/data/lanes.js \
  > obol/packs/orange_ad_2025_03.json
```

## Working agreements

- Land work as PRs against `main` (repo owner merges).
- Keep the fact/pack contracts above intact; add tests for behavior changes.
- The prior obol (`platocres/obol`), Charon (`platocres/charon`), and PentOS
  (`kaldox/pentos`) are **separate repos** — add them to the session when you need
  their source (see `docs/SOURCES.md`).
