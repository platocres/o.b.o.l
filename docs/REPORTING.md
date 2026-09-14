# Reporting

`obol report` writes an OSCP-style markdown report from the same workspace state
used by the terminal board and the local web view.

The report is not a separate notes system. It is a projection of the same
workspace state the terminal and web read from the SQLite store
(`.obol/state.db`; `state.json` is the export/snapshot format, see
[`ARCHITECTURE.md`](ARCHITECTURE.md)):

- workspace facts (`Workspace.facts`)
- `Workspace.runs` activity ledger entries
- `Fact.source` evidence lineage
- raw stdout/stderr paths saved by `obol run`
- the shared `graph.py` path projection

## Usage

From an engagement directory with an initialized obol workspace:

```bash
obol report
```

By default, this writes:

```text
report.md
```

To write somewhere else:

```bash
obol report --out reports/forest.md
```

## Secret handling

Reports redact passwords, hashes, tickets, cpassword values, and obvious secret
fields by default. This makes the first draft safer to open, copy, or share while
reviewing evidence quality.

For private exam notes where the recovered secret itself needs to be recorded:

```bash
obol report --include-secrets
```

Use that only when the output file is staying private.

## What the report includes

- Executive summary: target, scope, parsed ports, domain, credential state, and
  access state.
- Activity timeline: every recorded `obol run`, command, return code, parsed fact
  kinds, and raw output paths.
- Evidence-backed findings: every fact with scope, state, value, and source.
- Recommended next actions: the current planner output with the first command for
  each action.
- Evidence path diagram: the same Mermaid path graph used by the web view.

## Proof boundaries

The report narrates facts. It does not turn project metadata, action `produces`
fields, or command intent into engagement proof.

Examples:

- A cracked password can appear as a credential fact, but it does not prove shell
  access or admin by itself.
- SMB or LDAP authentication can appear as authenticated service access, but it
  does not prove a Windows foothold.
- WinRM authentication can prove a foothold, but not admin unless the output also
  supports admin.
- BloodHound collection proves graph collection, not attack paths, unless explicit
  analysis output is present.

That is the whole point of obol: the report should be useful because the evidence
model is disciplined, not because it flatters the operator.
