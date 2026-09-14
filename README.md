# O.B.O.L — Offensive Box Operations Ledger

**Evidence-driven OSCP operator companion.** Proven facts in, honest next actions out.

> **This is "Local Obol"** — the terminal-first, on-box operator tool in this repo
> (`platocres/o.b.o.l`). It is the local companion to **Obol**, the browser-based
> planning app at **[platocres/obol](https://github.com/platocres/obol)**. Where the
> web Obol plans methodology in a static, browser-local app, Local Obol *runs the
> engagement*: it executes commands, ingests real evidence, and keeps the ledger.
> Throughout the docs, "local obol" (or "o.b.o.l") means this project; "the web
> Obol" / "obol site" means the `platocres/obol` app.

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
obol init --target IP     # or start a real scoped target workspace
obol next                 # proven facts · ranked next actions · blocked paths
obol explain 1            # first real target move is nmap open-port discovery
obol run 1                # run it, ingest ports/services, record new facts
obol run 1 --cmd 2        # choose a different command variant from the card
obol next                 # recompute from the new facts
obol playbooks            # named, ordered action sequences (e.g. AD initial recon)
obol playbook ad-recon    # show the command plan; --step N runs one step
obol report               # OSCP-style markdown report from the evidence ledger
obol serve                # live web surface on localhost (mirrors AND drives the ledger)
```

## The web surface

`obol serve` starts a localhost web console (needs the `web` extra —
`pip install ".[web]"`) that is a real second surface over the *same* `.obol`
workspace, not a separate app:

- **Overview** — stat tiles, an engagement-progress ladder, findings charted by
  category and severity, and a live activity feed.
- **Flow & next** — the path drawn as a phase-column flow chart (recon → enumerate →
  credentials → access → escalate → loot) plus the ranked next moves, each runnable
  from the page.
- **Run from the site** — launching an action or a playbook step goes through the
  *same* scope-enforced runner, parser, and store as the terminal; the browser
  triggers by action id, so the server fills the command from workspace facts and
  secrets never travel to the browser. Noisy steps still require approval.
- **Real-time** — every page updates itself the instant the ledger changes, whether
  the change came from the web or from a terminal `obol run` (Server-Sent Events on
  the state file).
- **Report** — the OSCP report rendered as the primary report interface, with a
  one-click Markdown download and a secrets-redaction toggle.

It binds to `127.0.0.1` and gates every API call with a per-start token printed in
the terminal. Keep it local — the web can launch tools.

## Design: one state, synced surfaces

```
        fact / evidence store  (.obol/state.json — single source of truth)
        ▲ writes  ▲ writes          │ reads
   terminal loop   web surface       OSCP report / web report
   (obol run …)    (run from site)   (narrated from the ledger)
        └──────────┴─ one scope-enforced runner · parser · store ─┘
```

- **The fact layer is the point.** Nothing is "true" unless a `Fact` records it,
  scoped to exactly what the evidence supports, with a `ProofState`
  (`supported` / `refuted` / `inconclusive`) and the command that produced it.
  A WinRM login proves *authenticated user*, never *admin*; an AS-REP hash is
  *crackable material*, never *a credential*.
- **Actions are methodology branches expressed as data** — `requires` (what facts
  unlock them), `produces` (what a run can prove), and what they do *not* prove.
  The planner only ranks unlocked actions and explains blocked ones.
- **The path graph is projected once** (`graph.py` → `build_graph_model`) and rendered
  identically to the terminal board (mermaid), the web flow chart (SVG), and the
  report — so the surfaces never disagree.
- **Terminal and web are both actors over one state**, localhost-only; either can
  launch a run, and both go through the single scope-enforced runner and `.obol`
  store, so they stay in lockstep in real time.

## Status

First executable slice. The Orange-Cyberdefense 2025.03 AD pack is loaded as a
fact-gated methodology pack, and `obol run` now has a scoped, fixed-argv runner
with dry-run, raw output capture, and the first generic evidence parsers for
`nmap`, `nxc`, LDAP, and AS-REP output.

The current live path is intentionally narrow but real: configure a target, run a
quick all-port nmap scan, let obol parse open ports, run a targeted `-Pn -sC -sV`
scan against those ports, then let the resulting facts unlock service-specific
moves. For AD, finding `389`/LDAP leads into the NetExec-first DC/LDAP smoke test
and anonymous LDAP enumeration. Most Orange actions still need dedicated parsers
before they can be considered fully executable; until then, `obol explain` is the
command reference and `obol run` will save raw evidence without inventing facts.

Beyond AD, a **web pack** (Orange 2025.03 web lane, 23 actions) loads as a sibling
pack: an HTTP port from the nmap spine unlocks content discovery, nikto, and
virtual-host recon, with parsers that record discovered surface as candidate
context — never a confirmed vuln or foothold. Packs share one fact-kind namespace,
so cross-domain gating works.

**Playbooks** bundle a flow into one deliberate move: a playbook is a named,
ordered list of pack actions stored as data. `obol playbook ad-recon` (or
`web-recon`) renders the exact command plan; `obol playbook <name> --step N` runs
one step through the *same* scope-enforced runner, parser, and `.obol` store as
`obol run` (no second engine). Noisy steps are marked `require_approval` and refuse
to run without `--approve`.

## Install

Requires Python 3.10+. Pick one:

```bash
# 1) clone — NOT with sudo (a root-owned checkout can't write obol's state)
git clone https://github.com/platocres/o.b.o.l.git && cd o.b.o.l

# 2a) install with pipx (recommended — isolated, puts `obol` on your PATH)
pipx install ".[all]"

# 2b) or a plain user install
pip install --user ".[all]"

# 2c) or an editable dev install (for hacking on obol itself)
pip install -e ".[all]"
```

Extras: `rich` (nicer terminal output), `web` (the `obol serve` web surface), and
`all` (both). The terminal core has no hard dependencies, so `pip install .`
also works and degrades to clean plain text; `pip install ".[web]"` adds the web
console.

### Try it in 20 seconds

obol keeps its state (`.obol/`) in the **current directory**, so run it from an
engagement directory you own — not the source checkout:

```bash
mkdir -p ~/labs/forest && cd ~/labs/forest
obol init --demo     # seed the HTB Forest walkthrough (post-nmap)
obol next            # proven facts · ranked next actions · blocked paths
obol run 1           # run the top action, ingest it, update facts
obol next            # recompute — repeat until rooted
obol serve           # live web console (open the tokenized URL it prints)
```

For a real scoped target:

```bash
mkdir -p ~/labs/box && cd ~/labs/box
obol init --target 10.10.10.10
obol next
obol explain 1       # first command is the fast all-port nmap scan
obol run 1 --dry-run # inspect the command without touching the target
obol run 1           # execute, save raw output, parse open ports
obol next            # now the targeted -sC -sV scan should be next
```

If a later command needs operator-provided paths or values, persist them with
`--set`:

```bash
obol run 3 --set userlist=users.txt --set hashfile=asrep.hashes
```

### Run without installing

Point `PYTHONPATH` at the checkout, but still work in a lab directory:

```bash
git clone https://github.com/platocres/o.b.o.l.git      # no sudo
OBOL="$PWD/o.b.o.l"
mkdir -p ~/labs/forest && cd ~/labs/forest
PYTHONPATH="$OBOL" python3 -m obol init --demo && PYTHONPATH="$OBOL" python3 -m obol next
```
