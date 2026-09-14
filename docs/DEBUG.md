# Debug packages

When you start testing obol against real boxes, `obol debug` bundles everything an
AI agent (or teammate) needs to review a run into a single self-describing `.zip`.

## One-shot package

```bash
obol debug package                 # → .obol/debug/obol-debug-<ts>.zip
obol debug package --out ~/reviews # choose the output directory
obol debug package --include-secrets   # unredact report.md (still sensitive!)
obol debug package --no-screenshots     # text-only, skip PNGs
```

Contents:

| File | What it is |
|------|-----------|
| `README.md` / `manifest.json` | Orientation for a reviewer + counts, versions, schema |
| `state.json` | Full engagement export (facts, targets, runs, evidence metadata) |
| `events.jsonl` | The store change feed — what happened, in order |
| `facts.json` | Facts grouped per target, with proof state and lineage |
| `ledger.json` + `runs/` | The run ledger and the raw stdout/stderr of every run |
| `report.md` | The OSCP report (secrets redacted unless `--include-secrets`) |
| `tools.json` | Tool-availability scan on this host |
| `env.json` | obol / Python / platform / pack versions |
| `terminal/` | Plain-text `obol next` and `obol facts` (terminal scrollback) |
| `site/index.html` | Offline web-console snapshot |
| `screenshots/` | PNGs of a terminal-styled view and the web console (when a browser is available) |

## Screenshots during a live run

`obol debug capture` snapshots on a timer while a test runs, so the package shows the
engagement evolving (a folder per tick under `timeline/`):

```bash
obol debug capture --interval 30            # every 30s until Ctrl-C, then bundle
obol debug capture --interval 20 --count 10 # ten snapshots
obol debug capture --duration 600           # snapshot for ten minutes
```

To screenshot the **real** web console (charts, graph, live panels) rather than the
offline snapshot, point it at a running `obol serve`:

```bash
obol serve                                   # note the tokenized URL it prints
obol debug package --url http://127.0.0.1:8765 --token <token-from-banner>
```

## Screenshot engines (optional, graceful)

Screenshots are a bonus — the text bundle is complete without them. obol picks, in
order:

1. **Playwright** — `pip install "obol[debug]" && playwright install chromium`.
2. **A system Chromium/Chrome** driven headless (`chromium`, `google-chrome`, …).
3. **Neither** — screenshots are skipped and `manifest.json` records why.

## Handling

`report.md` is redacted by default, but `runs/` holds verbatim tool output and may
contain secrets regardless. Treat the whole package as sensitive.
