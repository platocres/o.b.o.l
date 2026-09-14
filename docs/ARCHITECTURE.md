# Architecture notes — state, sync, and rendering

This records three architectural decisions taken together, and why. They change
*plumbing* only: the fact model, the single scope-enforced runner, the one-graph
projection, and the UX guardrails are all unchanged. obol local is on-box and
localhost-only, so it does not carry the web Obol's "static, zero-dependency,
browser-local" constraints — but it does keep two of its own: **offline** (no CDN,
no runtime network) and **no build step** (the web surface ships as vendored assets
inside the pip wheel). Every decision below respects those.

## 1. State: SQLite, not a single `state.json`

**Problem.** Two surfaces write the same engagement — the terminal loop (`obol run`)
and the web surface (run-from-site) — in *separate processes*. The old store was one
`.obol/state.json`, rewritten whole on every mutation (`json.dumps` + `write_text`).
That is unsafe two ways:

- **Lost updates.** Both processes do read-modify-write of the whole file. A
  concurrent terminal `obol run` and a run-from-site clobber each other; the
  in-process lock in the web server does nothing across processes.
- **Torn reads.** `write_text` is not atomic, and the SSE loop `stat()`-ed the same
  file — a read between truncate and write sees a partial/empty file.

Plus a flat fact list scanned O(n) per request and a single-target-shaped schema.

**Decision.** The durable store is **SQLite** (`obol/store.py`, `.obol/state.db`),
stdlib `sqlite3` — no new dependency, still one inspectable local file.

- **WAL mode + busy-timeout:** many readers, one writer at a time, writers
  serialized (they wait, they don't lose data).
- **Targeted, idempotent writes (`Store.reconcile`):** facts are inserted by content
  hash, runs by generated id, so two processes appending different rows both land;
  only rows this session explicitly removed are deleted. No whole-table rewrite, so
  no clobber.
- **A real change feed:** an append-only `events` table records what changed. The
  web SSE loop tails it (below) instead of polling a file mtime.

**Kept in memory, exactly as before.** `Workspace` still loads the whole engagement
into a plain domain model; `ws.facts.add(...)`, `ws.record_run(...)`,
`ws.add_target(...)` mutate memory and persist nothing until `save()`. `save()`
reconciles the model into SQLite. So callers and tests are unchanged.

**Run-level concurrency (today, and where it's going).** The store is safe for
concurrent writers (WAL, targeted idempotent writes), but *runs* are currently
serialized: the web server holds one in-process `_RUN_LOCK` around each run, and a
sweep enumerates hosts one at a time. This is intentional and simple. The planned
step up is a **bounded worker pool** that parallelizes only *independent* work
(different targets; currently-eligible, non-dependent playbook branches), replacing
the single lock with per-target mutual exclusion and keeping the scope gate per run.
See `docs/ROADMAP.md §9`.

**JSON stays — as interchange.** `state.json` remains the format for the OSCP report,
the offline `obol web` snapshot, the debug package, and migration: an existing
`.obol/state.json` is read on first load and written to SQLite on the next `save()`.
`Workspace.to_payload()` / `export_json()` / `apply_payload()` are the seam.

**Trade-offs.** Last-writer-wins on small mutable singletons (a target's notes, the
active target) — acceptable, and still far better than clobbering the whole file.
Facts and runs are append-only truth and never lost.

## 2. Sync: payload-carrying SSE deltas, not an mtime tick

**Before.** `/api/events` polled `state.json`'s mtime once a second and pushed a
contentless tick; the browser reacted by re-fetching everything and rebuilding the
whole view.

**Now.** `/api/events` tails the store's `events` table for the active engagement and
pushes JSON describing *what changed* (new facts / runs / targets / evidence). An
engagement switch sends `{reset:true}`. Quick Start job progress (in-memory, not in
the store) rides along as a `qs` version the client uses to refetch the running job.
The browser can patch just the affected panels and show a precise toast
("+2 facts · 1 run") instead of a blind full refresh. Terminal-driven changes reach
the browser the same way — this is validated end-to-end (a terminal `add_target`
appears in the page within the poll interval).

## 3. Rendering: morphdom + event delegation, not innerHTML teardown

**Before.** Each render did `container.innerHTML = html`, destroyed and recreated the
charts, then re-attached every event listener with `querySelectorAll(...)
.addEventListener(...)`. A live refresh reset scroll, blew away focus and half-typed
input, and flickered the charts.

**Now.** Every view builder returns an HTML string; `render()` **morphs** it into the
DOM with **morphdom** (vendored, ~12 KB UMD, no build step). The morph preserves
untouched nodes — scroll position, focus, in-flight inputs, and live `<canvas>`
charts (skipped in `onBeforeElUpdate`, then updated in place). Interaction is fully
**delegated**: one document-level `click`/`change` handler dispatches on `data-act`,
so re-rendering never rebinds (and never double-binds) listeners. This deletes the
per-render wiring functions and is the "simpler, more maintainable, popular-tools"
half of the change.

**Why not React/Vue + a bundler?** They would drag a Node build toolchain into a
Python tool and break the offline / no-build / ships-in-the-wheel constraints for no
gain at this surface's size. morphdom gives reactive-feeling updates as a single
vendored file.

## Validation

`tests/test_store.py` locks the concurrency (two writers, no clobber), idempotency,
change-feed, and legacy-migration behavior. The web surface (morphdom render,
delegated interaction, and live SSE propagation of a terminal-side change) is
exercised headlessly against a real server. `tests/test_debug.py` covers the debug
package; see `docs/DEBUG.md`.
