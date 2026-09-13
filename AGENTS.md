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
a **proof-gated decision model** — facts with an explicit `ProofState`, actions
gated on facts, and honest *negative space* ("blocked until X") — instead of a
stateless service→tool map. And **one state, three views**: the terminal drives,
a read-only web page mirrors, and (planned) an OSCP report is narrated from the
same fact/run ledger.

## The non-negotiable principles (the "always/never")

1. **Facts are the source of truth.** Nothing is true unless a `Fact` records it,
   scoped to exactly what the evidence supports, with a `ProofState`
   (`supported`/`refuted`/`inconclusive`) and the command that produced it. An
   action **never proves more than the facts it produces** — a WinRM login proves
   *authenticated user*, never *admin*; an AS-REP hash is *crackable material*,
   never *a credential*. Preserve this when you add parsers: map output to the
   narrowest supported fact, prefer no fact over a convenient one.
2. **Methodology is data, not code.** Actions live in `obol/packs/*.json` and are
   loaded by the planner. Add methodology by adding pack entries, **never** by
   putting box-specific or branch-specific logic in the planner.
3. **The terminal is the only actor.** The web view is read-only and
   localhost-only; it never executes anything. State drift is thereby impossible.
4. **Scope enforcement is mandatory for the (future) runner.** It may only touch
   an authorized target. This is a hard gate, not a noise tier.
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
  pack.py        Action model + planner (next_actions / blocked_actions /
                 apply_action) + load_pack(); friendly() names fact kinds
  packs/         methodology packs as DATA (+ NOTICE.md attribution)
    orange_ad_2025_03.json   30 AD actions (the first real pack)
  board.py       terminal render (rich + plain fallback); {{token}} templating;
                 explain view shows the full card (hypothesis, commands, refs)
  graph.py       facts+actions -> mermaid path graph (the single projection)
  web.py         read-only localhost web view (findings + path graph)
  seed.py        Forest demo fixture (post-nmap facts)
  cli.py         subcommands: init / next / explain / run / facts / serve / web
scripts/
  import_orange_ad.js   converter: old-obol lanes.js AD lane -> pack JSON
tests/
  test_pack.py   pack loads, proof boundaries, gating, seed unlocks chain
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
the read-only web view with the mermaid path graph; 7 passing tests.

**STUBBED — this is the main gap:** *execution*. `obol run N` calls
`pack.apply_action`, which just records the action's declared `produces` as facts.
It does **NOT** execute the command, does **NOT** parse real output, and there is
**no target/IP configuration** beyond the Forest fixture, **no scope enforcement**,
and **no report generation**. The findings show empty `{}` values because they are
simulated, not ingested. Making `run` real is the top roadmap item.

## Run / test / regenerate

```bash
pip install -e ".[rich]"          # rich optional; obol degrades without it
# work in an ENGAGEMENT directory, not the source checkout:
mkdir -p ~/labs/box && cd ~/labs/box && obol init --demo && obol next
python3 -m pytest tests/ -q       # from the repo root
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
