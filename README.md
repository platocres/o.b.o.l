# obol

**Evidence-driven OSCP operator companion.** Proven facts in, honest next actions out.

obol keeps a conservative model of what you have actually *proven* about a target,
recommends the next best action from that model, shows the exact command (which you
run), ingests the result, and updates the picture — while staying brutally honest
about what has and hasn't been proven. It is built for the OSCP exam: you drive, one
deliberate command at a time, and every command lands in your terminal scrollback as
documentation.

## The loop

Shell subcommands, each independently re-runnable (no hidden state, no full-screen
dashboard — the transcript is your evidence log):

```
obol init --demo          # seed a workspace (HTB Forest, post-nmap)
obol next                 # proven facts · ranked next actions · blocked paths
obol explain 1            # the command + what it proves / does NOT prove
obol run 1                # run it, ingest the result, record new facts
obol next                 # recompute from the new facts
obol serve                # read-only web view (findings + path graph) on localhost
```

## Design: one state, three views

```
        fact / evidence store  (.obol/state.json — single source of truth)
        ▲ writes        │ reads            │ reads
   terminal loop     web view (read-only)   OSCP report
   (the only actor)  findings + path graph  (narrated from the ledger)
```

- **The fact layer is the point.** Nothing is "true" unless a `Fact` records it,
  scoped to exactly what the evidence supports, with a `ProofState`
  (`supported` / `refuted` / `inconclusive`) and the command that produced it.
  A WinRM login proves *authenticated user*, never *admin*; an AS-REP hash is
  *crackable material*, never *a credential*.
- **Actions are methodology branches expressed as data** — `requires` (what facts
  unlock them), `produces` (what a run can prove), and what they do *not* prove.
  The planner only ranks unlocked actions and explains blocked ones.
- **The path graph is projected once** (`graph.py`) and rendered identically to the
  terminal board, the web view, and the report — so the surfaces never disagree.
- **The web view is a read-only mirror**, localhost-only; it never executes anything.

## Status

First vertical slice. The methodology pack in `pack.py` is a small hardcoded HTB
Forest chain — a **placeholder** for the real foundation: the Orange-Cyberdefense
2025.03 AD atomic units and the OSCP web/privesc branches to be exported from the
prior obol data layer into fact-gated action packs (kept a distinct, attributed
component). Execution is stubbed — `run` applies each action's declared `produces`
in place of a real runner + parser, so the loop advances against the Forest fixture.

## Install

Requires Python 3.10+. Pick one:

```bash
# 1) clone — NOT with sudo (a root-owned checkout can't write obol's state)
git clone https://github.com/platocres/o.b.o.l.git && cd o.b.o.l

# 2a) install with pipx (recommended — isolated, puts `obol` on your PATH)
pipx install ".[rich]"

# 2b) or a plain user install
pip install --user ".[rich]"

# 2c) or an editable dev install (for hacking on obol itself)
pip install -e ".[rich]"
```

`rich` is optional — obol degrades to clean plain text without it (`pip install .` works too).

### Try it in 20 seconds

obol keeps its state (`.obol/`) in the **current directory**, so run it from an
engagement directory you own — not the source checkout:

```bash
mkdir -p ~/labs/forest && cd ~/labs/forest
obol init --demo     # seed the HTB Forest walkthrough (post-nmap)
obol next            # proven facts · ranked next actions · blocked paths
obol run 1           # run the top action, ingest it, update facts
obol next            # recompute — repeat until rooted
obol serve           # read-only web view at http://127.0.0.1:8765
```

### Run without installing

Point `PYTHONPATH` at the checkout, but still work in a lab directory:

```bash
git clone https://github.com/platocres/o.b.o.l.git      # no sudo
OBOL="$PWD/o.b.o.l"
mkdir -p ~/labs/forest && cd ~/labs/forest
PYTHONPATH="$OBOL" python3 -m obol init --demo && PYTHONPATH="$OBOL" python3 -m obol next
```
