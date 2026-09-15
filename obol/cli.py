"""obol command-line surface.

Deliberately shell subcommands (PentOS-style), not an in-process REPL: every
action is independently re-runnable and leaves an explicit command in the
scrollback, which is what OSCP documentation needs. The loop is the human
running `obol next` -> `obol run N` -> `obol next` again.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import (__version__, board, discovery, enumrun, exploits, library, listeners,
               provision, quickstart, service, sessions, staging, tunnels)
from .facts import Fact, ProofState
from .pack import friendly, load_packs, next_actions
from .pivot import engagement_pivots, pivot_summary
from .runner import RunnerError
from .scope import extract_ip_scope_entries, normalize_scope_entry, target_in_scope
from .seed import seed_forest
from .service import ActionError
from .sessions import SessionError
from .tunnels import TunnelError
from .workspace import Workspace, find_workspace


def _load_or_exit() -> Workspace:
    """Resolve the working engagement: a `.obol` in the current directory tree, else
    the active engagement in the app-managed library."""
    ws = find_workspace() or library.resolve_active()
    if ws is None:
        print("no obol workspace here. run `obol init`, or `obol engagement new <name>`.",
              file=sys.stderr)
        raise SystemExit(1)
    return ws


def _pick(ws: Workspace, n: int):
    facts = ws.facts_for_target(ws.target) if ws.target else ws.facts
    actions = next_actions(facts)
    if not 1 <= n <= len(actions):
        print(f"no next action #{n}. `obol next` lists {len(actions)}.", file=sys.stderr)
        raise SystemExit(1)
    return actions[n - 1]


def _apply_input_overrides(ws: Workspace, values: list[str]) -> None:
    for row in values:
        if "=" not in row:
            print(f"--set expects KEY=VALUE, got {row!r}", file=sys.stderr)
            raise SystemExit(1)
        key, value = row.split("=", 1)
        key = key.strip()
        if not key:
            print("--set key cannot be empty", file=sys.stderr)
            raise SystemExit(1)
        ws.set_input(key, value.strip())


def _version_text() -> str:
    return f"obol {__version__}"


def _workspace_or_none() -> Workspace | None:
    return find_workspace() or library.resolve_active()


def _print_info() -> None:
    ws = _workspace_or_none()
    print(_version_text())
    if ws is None:
        print("workspace: none")
        print("start:     obol engagement new <name>")
        return
    print(f"workspace: {ws.root}")
    print(f"name:      {ws.name}")
    print(f"target:    {ws.target or '-'}")
    print(f"scope:     {len(ws.scope)} entr{'y' if len(ws.scope) == 1 else 'ies'}")
    print(f"targets:   {len(ws.targets)}")
    print(f"facts:     {len(ws.facts.facts)}")
    print(f"runs:      {len(ws.runs)}")
    print("web:       obol serve")


def _manual_text() -> str:
    return """obol manual

Core loop
  obol engagement new "HTB Lab"      create an engagement
  obol scope add 10.10.10.0/24       authorize a lab range
  obol scan                          sweep every scope entry, then Quick Start hosts
  obol overview                      show scope, hosts, ports, and next moves
  obol findings                      show cross-host findings with evidence refs
  obol target use 10.10.10.5         switch active target
  obol next                          show next moves for the active target
  obol explain 1                     show the exact command choices
  obol run 1                         run, parse, store facts, and update next moves
  obol serve                         open the localhost web console over the same store
  obol report                        write the OSCP-style report

Scope
  obol scope list
  obol scope add 10.10.10.5 10.10.10.7 10.10.10.0/24
  obol scope paste "hosts: 10.10.10.5, bad text, 10.10.10.0/24"
  cat notes.txt | obol scope paste
  obol scope rm 10.10.10.5

Scanning
  obol scan                          scan every current scope entry
  obol scan 10.10.10.0/24            authorize and scan that range
  obol scan --extract "10.10.10.5 junk 10.10.10.0/24"
  obol scan --no-enumerate           discovery only
  obol scan --new-only               Quick Start only newly discovered targets
  obol sweep 10.10.10.0/24           sweep one range and Quick Start new hosts

Help and diagnostics
  obol --help
  obol help <command>
  obol --version
  obol info
"""


def cmd_help(args) -> None:
    parser = build_parser()
    topic = getattr(args, "topic", "")
    if topic:
        parser.parse_args([topic, "--help"])
    parser.print_help()


def cmd_manual(args) -> None:
    print(_manual_text().rstrip())


def cmd_version(args) -> None:
    print(_version_text())


def cmd_info(args) -> None:
    _print_info()


def _add_scope_values(ws: Workspace, values: list[str], *, extract_only: bool = False) -> tuple[list[str], list[str], list[str]]:
    added: list[str] = []
    existing: list[str] = []
    rejected: list[str] = []
    candidates = extract_ip_scope_entries(" ".join(values)) if extract_only else values
    for value in candidates:
        norm = normalize_scope_entry(value)
        if not norm:
            rejected.append(value)
            continue
        before = set(ws.scope)
        stored = ws.add_scope(norm)
        if stored in before:
            existing.append(stored)
        else:
            added.append(stored)
    return added, existing, rejected


def _read_scope_paste(args) -> str:
    chunks: list[str] = []
    if getattr(args, "file", None):
        chunks.append(Path(args.file).read_text())
    if getattr(args, "text", None):
        chunks.append(" ".join(args.text))
    if not chunks and not sys.stdin.isatty():
        chunks.append(sys.stdin.read())
    return "\n".join(chunks)


def _print_scope_result(added: list[str], existing: list[str], rejected: list[str]) -> None:
    for value in added:
        print(f"added scope: {value}")
    for value in existing:
        print(f"already scoped: {value}")
    for value in rejected:
        print(f"ignored: {value}")
    if not (added or existing or rejected):
        print("no valid scope entries found")


def cmd_init(args) -> None:
    cwd = Path.cwd()
    ws = Workspace(cwd)
    if ws.exists():
        print(f"workspace already initialized at {ws.dir}")
        return
    # A workspace is an engagement directory, not the code checkout. Warn (don't
    # block) if someone runs `init` inside the obol source tree.
    if (cwd / "obol" / "pack.py").exists() and (cwd / "pyproject.toml").exists():
        print("note: this looks like the obol source tree — obol keeps its state in the\n"
              "      current directory. Prefer an engagement dir: "
              "`mkdir -p ~/labs/box && cd ~/labs/box`.", file=sys.stderr)
    if args.demo:
        seed_forest(ws)
        msg = "initialized demo workspace (HTB Forest, post-nmap)."
    else:
        ws.target = args.target or ""
        if ws.target:
            ws.add_scope(ws.target)
            ws.facts.add(Fact("target.configured", f"host:{ws.target}", {"target": ws.target}, source="obol init --target"))
        msg = "initialized empty workspace."
    try:
        ws.save()
    except OSError as e:
        print(f"error: cannot create the workspace at {ws.dir}\n  {e}\n"
              "Pick a directory you can write to. If you cloned with `sudo`, the checkout\n"
              "is root-owned — re-clone without sudo (or chown it) and run obol from a\n"
              "normal directory you own.", file=sys.stderr)
        raise SystemExit(1)
    print(msg)
    print("next: obol next")


def cmd_next(args) -> None:
    ws = _load_or_exit()
    if getattr(args, "all", False):
        board.render_overview(ws)
    else:
        board.render_board(ws)


def cmd_overview(args) -> None:
    board.render_overview(_load_or_exit())


def _move_extra(m) -> str:
    """A short trailing hint for a move line (who/what, not a full card)."""
    d = m.detail or {}
    if m.kind == "login" and d.get("user"):
        return f"  {(d.get('method') or '').strip()} {d['user']}".rstrip()
    if m.kind == "exploit" and d.get("lead"):
        return f"  ({d['lead']})"
    if m.kind == "tunnel" and d.get("transport"):
        return f"  {d['transport']}"
    if m.kind == "enum" and not d.get("cached"):
        return "  (will fetch/stage)"
    return ""


def cmd_moves(args) -> None:
    from . import moves as moves_layer
    from .phases import PHASES, frontier_index
    ws = _load_or_exit()
    host = args.host or ws.target
    if not host:
        print("no active target. add one with `obol target add <ip>` or pass a host.",
              file=sys.stderr)
        raise SystemExit(1)
    all_moves = moves_layer.frontier_moves(ws, host)
    ready = [m for m in all_moves if m.ready]
    waiting = [m for m in all_moves if not m.ready]
    tf = ws.facts_for_target(host)
    print(f"\nmoves on {host}  (frontier: {PHASES[frontier_index(tf)]})")
    if not ready and not (args.all and waiting):
        print("  (no live moves yet — run `obol scan` or gather more evidence)\n")
        return
    if ready:
        print("\n  ready now:")
        for m in ready:
            gate = "" if m.autonomy == "auto" else f"  · {m.autonomy}"
            print(f"    [{m.kind:7}] {m.label:38} {m.phase:9}{gate}{_move_extra(m)}")
    if args.all and waiting:
        print("\n  waiting on input:")
        for m in waiting:
            print(f"    [{m.kind:7}] {m.label:38} {m.phase:9}  — {m.reason}")
    elif waiting:
        print(f"\n  {len(waiting)} more need one input — see them with `obol moves --all`.")
    print()


def cmd_do(args) -> None:
    from . import dispatch
    ws = _load_or_exit()
    host = args.host or ws.target
    if not host:
        print("no active target. add one with `obol target add <ip>` or pass a host.",
              file=sys.stderr)
        raise SystemExit(1)
    params = {}
    for k in ("method", "subnet", "outcome"):
        v = getattr(args, k, "")
        if v:
            params[k] = v
    try:
        # a direct `obol do` is the operator's explicit choice — that is the approval for
        # an approve-tier move (the unattended cruise loop is what pauses instead).
        res = dispatch.run_move(ws, args.id, host=host, dry_run=args.dry_run,
                                approve=True, params=params)
    except dispatch.DispatchError as exc:
        print(f"cannot run {args.id!r}: {exc}", file=sys.stderr)
        raise SystemExit(1)
    tag = {"ran": "ran", "dry-run": "preview", "handoff": "handoff",
           "craft": "crafted", "needs-approval": "needs approval"}.get(res["posture"], res["posture"])
    print(f"\n[{tag}] {res['label']}")
    if res.get("summary"):
        print(f"  {res['summary']}")
    if res.get("command"):
        print(f"  $ {res['command']}")
    if res.get("added"):
        print(f"  facts: {', '.join(res['added'])}")
    if res["posture"] in ("handoff", "craft"):
        print("  (obol prepared this — you launch/verify it, then `obol moves` for the next)")
    print()


def cmd_cruise(args) -> None:
    from . import cruise as cruise_layer
    ws = _load_or_exit()
    auto_kinds = frozenset({"sweep"}) if args.sweep else frozenset()

    def on_step(step):
        mark = "+" if step.ok else "x"
        print(f"  {mark} [{step.kind}] {step.label} — {step.summary}")

    if args.all:
        if not ws.targets:
            print("no targets to cruise. add one with `obol target add <ip>` or run a scan.",
                  file=sys.stderr)
            raise SystemExit(1)
        sweep_note = " (auto-sweeping open pivots)" if args.sweep else ""
        print(f"\ncruising the engagement — every in-scope target{sweep_note}\n")

        def on_host(entry, res):
            lead = {"checkpoint": "checkpoint", "done": "done", "objective-complete": "COMPLETE",
                    "blocked": "blocked", "max-steps": "paused"}.get(entry["stop_reason"], entry["stop_reason"])
            cp = entry.get("checkpoint")
            tail = f" → {cp['ask']}: {cp['label']}" if cp else ""
            print(f"  {entry['host']:16} [{lead}] ran {entry['ran']}{tail}")

        eng = cruise_layer.cruise_engagement(ws, max_steps=args.max_steps,
                                             auto_kinds=auto_kinds, on_host=on_host, on_step=None)
        s = eng.to_dict()["summary"]
        print(f"\ncruised {s['cruised']} target(s): {s['checkpoints']} at a checkpoint, "
              f"{s['complete']} complete.")
        opens = [e for e in eng.hosts if e.get("checkpoint")]
        if opens:
            print("\nyour checkpoints:")
            for e in opens:
                cp = e["checkpoint"]
                print(f"  {e['host']:16} [{cp['ask']}] {cp['label']}  → obol do {cp['id']} {e['host']}")
        print()
        return

    host = args.host or ws.target
    if not host:
        print("no active target. add one with `obol target add <ip>` or pass a host.",
              file=sys.stderr)
        raise SystemExit(1)
    print(f"\ncruising {host} — running safe (auto) moves, stopping at the first checkpoint\n")
    res = cruise_layer.cruise(ws, host, max_steps=args.max_steps, auto_kinds=auto_kinds, on_step=on_step)
    if not res.ran:
        print("  (no auto moves to run)")
    _print_briefing(res)


def _print_briefing(res) -> None:
    b = res.briefing or {}
    pos = b.get("position", {})
    recap = b.get("recap", {})
    cp = b.get("checkpoint")
    lead = {"checkpoint": "stopped at a checkpoint", "done": "cruise complete",
            "blocked": "stopped", "max-steps": "paused", "no-target": "stopped",
            "objective-complete": "objective complete"}.get(res.stop_reason, "stopped")
    print(f"\n== cruise briefing ==")
    if pos:
        acc = ", ".join(pos.get("access") or []) or "no foothold yet"
        print(f"  where: phase {pos.get('phase','?')} · frontier {pos.get('frontier','?')} · access: {acc}")
    obj = b.get("objectives") or {}
    if obj.get("total"):
        nxt = (obj.get("next") or {}).get("label")
        rungs = " → ".join(("[x]" if r["reached"] else "[ ]") + r["label"] for r in obj.get("rungs", []))
        tail = " · COMPLETE" if obj.get("complete") else (f" · next: {nxt}" if nxt else "")
        print(f"  objective: {obj['reached']}/{obj['total']}  {rungs}{tail}")
    if recap.get("learned"):
        print(f"  learned: {', '.join(recap['learned'])}")
    if recap.get("install"):
        print(f"  blocked on missing tools: {', '.join(recap['install'])} "
              f"(install, then `obol cruise` for more)")
    print(f"\n{lead}: {res.message}")
    if cp:
        print(f"\n  checkpoint [{cp.get('ask','')}]: {cp.get('label','')}")
        if cp.get("why"):
            print(f"    why:  {cp['why']}")
        if cp.get("command"):
            print(f"    cmd:  {cp['command']}")
        if cp.get("risk"):
            print(f"    risk: {cp['risk']}")
        for line in cp.get("resume", []):
            print(f"    {line}")
    opts = [o for o in b.get("options", []) if not cp or o["id"] != cp.get("id")]
    if opts:
        print(f"\n  other moves waiting:")
        for o in opts:
            gate = "" if o["autonomy"] == "auto" else f" · {o['autonomy']}"
            miss = "" if o["ready"] else f" — {o['reason']}"
            print(f"    - {o['label']} [{o['kind']}{gate}]{miss}")
    print(f"\n  ran {res.ran_ok} move(s).\n")


def cmd_autonomy(args) -> None:
    from . import autonomy
    ws = _load_or_exit()
    if getattr(args, "action", "show") == "set":
        if not args.kind or not args.decision:
            print("usage: obol autonomy set <kind> <auto|ask|never|clear>", file=sys.stderr)
            raise SystemExit(1)
        ws.set_autonomy(args.kind, args.decision)
        ws.save()
        print(f"autonomy override: {args.kind} = {args.decision}")
        return
    pol = autonomy.effective_policy(ws)
    print(f"\nautonomy · mode: {pol['mode']}  (profile decides; exam = uncrossable floor)")
    print("  local prep (cache / listener / craft) always runs; target-touching follows this:\n")
    for r in pol["kinds"]:
        print(f"    {r['kind']:10} {r['reach']:7} → {r['decision']}")
    if pol["overrides"]:
        print(f"\n  operator overrides: {pol['overrides']}")
    if pol["disallowed_tools"]:
        print(f"  disallowed automated exploiters (exam): {', '.join(pol['disallowed_tools'])}")
    print("\n  set with: obol autonomy set <kind> <auto|ask|never|clear>\n")


def cmd_objectives(args) -> None:
    from . import objectives
    ws = _load_or_exit()
    host = args.host or ws.target
    if not host:
        print("no active target. add one with `obol target add <ip>` or pass a host.",
              file=sys.stderr)
        raise SystemExit(1)
    p = objectives.progress(ws, host)
    done = " · COMPLETE" if p["complete"] else ""
    print(f"\nobjectives · {host}  ({p['reached']}/{p['total']}{done})")
    for r in p["rungs"]:
        mark = "[x]" if r["reached"] else "[ ]"
        line = f"  {mark} {r['label']}"
        if r["reached"] and r["evidence"]:
            line += f"   ← {_trim(r['evidence'])}"
        print(line)
    print()


def cmd_ingest(args) -> None:
    from . import ingest
    ws = _load_or_exit()
    text = ""
    if args.file:
        try:
            text = Path(args.file).read_text()
        except OSError as exc:
            print(f"cannot read {args.file!r}: {exc}", file=sys.stderr)
            raise SystemExit(1)
    else:
        text = sys.stdin.read()
    if not text.strip():
        print("no output to ingest (pass --file or pipe output on stdin).", file=sys.stderr)
        raise SystemExit(1)
    res = ingest.ingest_output(ws, text, action_id=args.action, target=args.target, note=args.note)
    if res["added"]:
        print(f"ingested — recorded {len(res['added'])} operator-sourced fact(s): "
              f"{', '.join(res['added'])}")
    else:
        print(f"ingested {res['parsed']} parse hit(s), no new facts "
              "(nothing the output shape proves, or already known).")
    print("run `obol cruise` to continue.")


def cmd_assert(args) -> None:
    from . import ingest
    ws = _load_or_exit()
    value = {}
    for pair in args.set or []:
        if "=" in pair:
            k, v = pair.split("=", 1)
            value[k.strip()] = v.strip()
    try:
        res = ingest.assert_fact(ws, args.kind, value=value, scope=args.scope,
                                 target=args.target, note=args.note, state=args.state)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
    where = res["scope"] or "(engagement)"
    if res["added"]:
        print(f"asserted (operator-attested): {res['kind']} on {where} [{res['state']}].")
    else:
        print(f"already recorded: {res['kind']} on {where}.")
    print("run `obol cruise` to continue.")


def cmd_explain(args) -> None:
    ws = _load_or_exit()
    board.render_command(_pick(ws, args.n), ws)


def _run_action(ws, action, *, command_index, timeout, dry_run, allow_shell,
                args_extra="", ledger_extra=None):
    """Terminal wrapper over the shared run service (`service.run_action`).

    The service is the one runner/parser/store path — the web run-from-site surface
    calls the same function. Here we only add scrollback output; on a bad command
    variant or a runner refusal we exit with a clear message.
    """
    try:
        cmd, _tool = service.build_command(
            action, ws, command_index=command_index, args_extra=args_extra
        )
    except ActionError as exc:
        print(f"{exc}", file=sys.stderr)
        raise SystemExit(1)
    print(f"\n$ {cmd}")
    try:
        outcome = service.run_action(
            ws, action,
            command_index=command_index, timeout=timeout,
            dry_run=dry_run, allow_shell=allow_shell,
            args_extra=args_extra, ledger_extra=ledger_extra,
        )
    except RunnerError as exc:
        print(f"\nerror: {exc}", file=sys.stderr)
        raise SystemExit(1)

    added = outcome.added
    if outcome.dry_run:
        print("\ndry run only — command was not executed and no facts were ingested.")
    elif added:
        print(f"\n{board.SYM_OK} ingested — new facts:")
        for f in added:
            detail = _value_summary(f.value)
            print(f"   + {f.kind}" + (f"  ({_trim(detail, 100)})" if detail else ""))
    else:
        print("\n(no new facts parsed — raw output was still saved)")
    return outcome.result, added


def cmd_run(args) -> None:
    ws = _load_or_exit()
    _apply_input_overrides(ws, args.set)
    action = _pick(ws, args.n)
    _run_action(
        ws, action,
        command_index=max(0, args.cmd - 1),
        timeout=args.timeout,
        dry_run=args.dry_run,
        allow_shell=args.allow_shell,
    )
    print("\nnext: obol next")


def cmd_playbooks(args) -> None:
    from . import playbook
    pbs = playbook.list_playbooks()
    if not pbs:
        print("no playbooks available.")
        return
    print("\nplaybooks:")
    for pb in pbs:
        print(f"  {pb.name:14} {pb.title}")
        if pb.description:
            print(f"  {'':14} {pb.description}")
    print("\nplan a playbook: obol playbook <name>")
    print("run one step:    obol playbook <name> --step N [--approve]")


def cmd_playbook(args) -> None:
    from . import playbook
    ws = _load_or_exit()
    _apply_input_overrides(ws, args.set)
    try:
        pb = playbook.load_playbook(args.name)
    except FileNotFoundError:
        names = ", ".join(p.name for p in playbook.list_playbooks()) or "(none)"
        print(f"no playbook named {args.name!r}. available: {names}", file=sys.stderr)
        raise SystemExit(1)
    try:
        steps = playbook.resolve_steps(pb, load_packs())
    except KeyError as exc:
        print(f"playbook {pb.name!r} references unknown pack action {exc}", file=sys.stderr)
        raise SystemExit(1)

    # No --step: plan view only. This never executes anything.
    if args.step is None:
        board.render_playbook(pb, steps, ws)
        return

    n = args.step
    if not 1 <= n <= len(steps):
        print(f"playbook {pb.name!r} has {len(steps)} step(s); no step #{n}.", file=sys.stderr)
        raise SystemExit(1)
    step, action = steps[n - 1]
    if step.require_approval and not args.approve and not args.dry_run:
        print(f"step {n} ({step.label}) is marked require_approval — it is noisy or intrusive.")
        print("re-run with --approve to execute it, or --dry-run to preview the command.")
        raise SystemExit(2)

    _run_action(
        ws, action,
        command_index=max(0, (step.cmd or 1) - 1),
        timeout=args.timeout,
        dry_run=args.dry_run,
        allow_shell=args.allow_shell,
        args_extra=step.args_extra,
        ledger_extra={"playbook": pb.name, "playbook_step": n},
    )
    if not args.dry_run and n < len(steps):
        print(f"\nnext: obol next   ·   continue: obol playbook {pb.name} --step {n + 1}")
    else:
        print("\nnext: obol next")


def cmd_facts(args) -> None:
    ws = _load_or_exit()
    for f in sorted(ws.facts.facts, key=lambda x: x.kind):
        print(f"  {f.state.value:12} {f.kind:28} {f.value}")


def _trim(text: str, limit: int = 160) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _value_summary(value: dict) -> str:
    if not value:
        return ""
    if "port" in value:
        bits = [f"{value.get('port')}/{value.get('protocol', 'tcp')}"]
        if value.get("service"):
            bits.append(str(value["service"]))
        if value.get("version"):
            bits.append(str(value["version"]))
        return " ".join(bits)
    for key in ("count", "status", "reason", "community", "identity", "user", "name", "domain", "fqdn", "banner"):
        if key in value and value[key] not in ("", None):
            return f"{key}={value[key]}"
    for key in ("ports", "users", "shares", "paths", "vhosts", "titles", "headers", "banners", "locations", "files"):
        if key not in value:
            continue
        items = value[key]
        if key == "shares" and isinstance(items, list):
            items = [row.get("name", "") for row in items if isinstance(row, dict)]
        if isinstance(items, list):
            shown = ", ".join(str(item) for item in items[:6])
            if len(items) > 6:
                shown += f", +{len(items) - 6}"
            return shown
    if "items" in value and isinstance(value["items"], list):
        items = []
        for item in value["items"][:6]:
            if isinstance(item, dict):
                items.append(f"{item.get('name')}={item.get('value')}")
            else:
                items.append(str(item))
        suffix = f", +{len(value['items']) - 6}" if len(value["items"]) > 6 else ""
        return ", ".join(items) + suffix
    return json.dumps(value, sort_keys=True)


def cmd_findings(args) -> None:
    from .report import _CATEGORY_ORDER, _fact_category, _redact_value, redact_command

    ws = _load_or_exit()
    include_secrets = not args.redact
    host_labels = {t["host"]: (t.get("label") or t["host"]) for t in ws.targets}
    rows = []
    for fact in ws.facts.facts:
        if fact.state is not ProofState.SUPPORTED and not args.include_refuted:
            continue
        category = _fact_category(fact.kind)
        if args.category and category != args.category:
            continue
        scope = fact.scope or ""
        host = scope[5:] if scope.startswith("host:") else ""
        if args.host and host != args.host:
            continue
        if scope.startswith("domain:"):
            origin = scope[7:]
        elif host:
            origin = host_labels.get(host, host)
        else:
            origin = "engagement"
        value = _redact_value(fact.value, include_secrets=include_secrets)
        rows.append((category, origin, fact.kind, fact.state.value, value, fact.source or ""))

    rows.sort(key=lambda r: (_CATEGORY_ORDER.get(r[0], 99), r[1], r[2], json.dumps(r[4], sort_keys=True)))
    if not rows:
        print("no findings yet")
        return

    print(f"\n== findings · {ws.name} ==")
    current = ""
    shown = 0
    for category, origin, kind, state, value, source in rows:
        if args.limit and shown >= args.limit:
            print(f"\n… showing first {args.limit} finding(s); rerun with --limit 0 for all")
            break
        if category != current:
            current = category
            print(f"\n[{category}]")
        state_prefix = "" if state == "supported" else f"{state} "
        detail = _value_summary(value)
        op = (" [op-attested]" if source.startswith("operator-attested:")
              else " [op]" if source.startswith("operator:") else "")
        print(f"  {origin:18} {state_prefix}{friendly(kind)}{op}"
              + (f" — {_trim(detail)}" if detail else ""))
        if not args.no_evidence and source:
            print(f"    source: {_trim(redact_command(source, include_secrets=include_secrets))}")
        shown += 1
    print()


def cmd_sweep(args) -> None:
    ws = _load_or_exit()
    range_ = args.range.strip()
    if range_ not in ws.scope:
        # Typing the range at the CLI is an explicit authorization; record it in
        # scope so the runner gate (and any later web sweep) sees it.
        added = ws.add_scope(range_)
        if not added:
            print(f"not a valid host, IP, or CIDR: {range_!r}")
            return
        range_ = added
        ws.save()
        print(f"authorized scope: {range_}")
    try:
        summary = discovery.run_sweep(ws, range_, dry_run=args.dry_run, timeout=args.timeout)
    except RunnerError as exc:
        print(f"sweep refused: {exc}")
        return
    if args.dry_run:
        print(summary["command"])
        return
    hosts, created = summary["hosts"], summary["created"]
    print(f"swept {range_}: {len(hosts)} live host(s), {len(created)} new target(s)")
    for host in created:
        print(f"  + {host}")
    for host in summary["existing"]:
        print(f"    {host} (already a target)")
    if not args.no_enumerate and created:
        _quickstart_targets(ws, created, timeout=args.quick_timeout,
                            dry_run=False, allow_shell=args.allow_shell)


def _targets_in_entries(ws: Workspace, entries: list[str]) -> list[str]:
    hosts: list[str] = []
    for rec in ws.targets:
        if any(target_in_scope(rec["host"], [entry])[0] for entry in entries):
            hosts.append(rec["host"])
    return hosts


def _quickstart_targets(
    ws: Workspace,
    hosts: list[str],
    *,
    timeout: int,
    dry_run: bool,
    allow_shell: bool,
) -> list[quickstart.QuickStartResult]:
    results: list[quickstart.QuickStartResult] = []
    seen: set[str] = set()
    for host in hosts:
        if host in seen:
            continue
        seen.add(host)
        label = (ws.get_target(host) or {}).get("label") or host
        print(f"\n== Quick Start - {label} ({host}) ==")

        def on_step(step: quickstart.QuickStartStep) -> None:
            if step.status == "running":
                print(f"$ {step.command}")
            elif step.status in {"success", "failed", "timeout", "dry-run"}:
                facts = f" +{len(step.added)} fact(s)" if step.added else ""
                print(f"  {step.status}: {step.title}{facts}")
            elif step.status not in {"waiting"}:
                reason = f" ({step.reason})" if step.reason else ""
                print(f"  {step.status}: {step.title}{reason}")

        result = quickstart.run_quickstart(
            ws, host, timeout=timeout, dry_run=dry_run,
            allow_shell=allow_shell, on_step=on_step,
        )
        results.append(result)
        print(f"stored {len(result.facts)} new fact(s); skipped {len(result.skipped)} step(s)")
    return results


def cmd_scan(args) -> None:
    ws = _load_or_exit()
    if args.entries:
        added, existing, rejected = _add_scope_values(ws, args.entries, extract_only=args.extract)
        if added or existing:
            ws.save()
        _print_scope_result(added, existing, rejected)
        entries = list(dict.fromkeys(added + existing))
    else:
        entries = list(ws.scope)
    if not entries:
        print("scope is empty. add scope first: obol scope add <ip-or-cidr>")
        return

    all_created: list[str] = []
    print(f"\nscanning {len(entries)} scope entr{'y' if len(entries) == 1 else 'ies'}")
    for entry in entries:
        try:
            summary = discovery.run_sweep(ws, entry, dry_run=args.dry_run, timeout=args.timeout)
        except RunnerError as exc:
            print(f"  refused {entry}: {exc}")
            continue
        if args.dry_run:
            print(f"  {entry}: {summary['command']}")
            continue
        all_created.extend(summary["created"])
        print(
            f"  {entry}: {len(summary['hosts'])} live, "
            f"{len(summary['created'])} new, {len(summary['existing'])} existing"
        )

    if args.dry_run or args.no_enumerate:
        return

    hosts = all_created if args.new_only else _targets_in_entries(ws, entries)
    if not hosts:
        print("\nno targets to enumerate yet")
        return
    _quickstart_targets(ws, hosts, timeout=args.quick_timeout,
                        dry_run=False, allow_shell=args.allow_shell)
    print("\nnext: obol overview")


def cmd_scope(args) -> None:
    ws = _load_or_exit()
    if args.scope_cmd == "add":
        added, existing, rejected = _add_scope_values(ws, args.values)
        if added or existing:
            ws.save()
        _print_scope_result(added, existing, rejected)
        return
    if args.scope_cmd == "paste":
        text = _read_scope_paste(args)
        added, existing, rejected = _add_scope_values(ws, [text], extract_only=True)
        if added or existing:
            ws.save()
        _print_scope_result(added, existing, rejected)
        return
    if args.scope_cmd in {"rm", "remove"}:
        removed = []
        missing = []
        for value in args.values:
            if any(t.get("host") == normalize_scope_entry(value) for t in ws.targets):
                print(f"refused: {value} is a target; remove the target before removing its scope")
                continue
            if ws.remove_scope(value):
                removed.append(value)
            else:
                missing.append(value)
        if removed:
            ws.save()
        for value in removed:
            print(f"removed scope: {value}")
        for value in missing:
            print(f"not in scope: {value}")
        return
    if args.scope_cmd == "clear":
        blocked = {t.get("host") for t in ws.targets}
        removable = [entry for entry in ws.scope if normalize_scope_entry(entry) not in blocked]
        for entry in removable:
            ws.remove_scope(entry)
        if removable:
            ws.save()
        print(f"removed {len(removable)} non-target scope entr{'y' if len(removable) == 1 else 'ies'}")
        if blocked:
            print("kept target scope entries; remove targets first to clear those")
        return
    if ws.scope:
        for entry in ws.scope:
            marker = "target" if any(t.get("host") == entry for t in ws.targets) else "scope"
            print(f"{entry}  [{marker}]")
    else:
        print("scope is empty")


def cmd_serve(args) -> None:
    from . import webapp
    ws = find_workspace()   # optional: link a cwd engagement into the library
    try:
        webapp.serve(ws, host=args.host, port=args.port)
    except SystemExit:
        raise
    except OSError as exc:
        print(f"error: could not bind {args.host}:{args.port} — {exc}", file=sys.stderr)
        raise SystemExit(1)


def cmd_engagement(args) -> None:
    sub = getattr(args, "engagement_cmd", "list")
    if sub == "new":
        ws = library.create_engagement(args.name)
        print(f"created engagement {ws.name!r} (slug {ws.root.name}) and set it active")
        print("add a target: obol target add <ip>")
        return
    if sub == "use":
        if not library.get_engagement(args.slug):
            print(f"no engagement {args.slug!r}. see `obol engagement list`.", file=sys.stderr)
            raise SystemExit(1)
        library.set_active(args.slug)
        print(f"active engagement: {args.slug}")
        return
    engs = library.list_engagements()
    if not engs:
        print("no engagements yet. create one: obol engagement new <name>")
        return
    for e in engs:
        mark = "*" if e["active"] else " "
        print(f" {mark} {e['slug']:22} {e['name']}  ({e['targets']} targets, {e['facts']} facts)")


def cmd_profile(args) -> None:
    """Show or set the engagement profile (platform/exam type + flag config)."""
    from . import profile as profile_mod
    sub = getattr(args, "profile_cmd", "show")
    if sub == "list":
        print("engagement profiles (platform / exam type):")
        for p in profile_mod.list_presets():
            print(f"  {p['id']:8} {p['name']:20} flags: {', '.join(p['flag_names'])}"
                  f"   formats: {', '.join(p['flag_formats'])}")
        return
    ws = _load_or_exit()
    if sub == "set":
        data: dict = {}
        if args.platform:
            if not profile_mod.normalize_platform(args.platform):
                print(f"unknown platform {args.platform!r}. see `obol profile list`.", file=sys.stderr)
                raise SystemExit(1)
            data["platform"] = args.platform
        else:
            # keep the current platform when only overriding names/formats
            data["platform"] = (ws.profile or {}).get("platform", profile_mod.DEFAULT_PLATFORM)
        if args.flag_names:
            data["flag_names"] = [n.strip() for n in args.flag_names.split(",") if n.strip()]
        if args.flag_formats:
            data["flag_formats"] = [f.strip() for f in args.flag_formats.split(",") if f.strip()]
        ws.set_profile(data)
        ws.save()
        print(f"engagement profile set: {ws.profile.get('platform')}")
    # show (default, and after set)
    cfg = ws.flag_config()
    print(f"platform : {cfg['platform']} ({cfg['platform_name']})")
    print(f"flag files: {', '.join(cfg['names'])}")
    print(f"formats   : {', '.join(cfg['formats'])}")


def cmd_target(args) -> None:
    ws = _load_or_exit()
    sub = getattr(args, "target_cmd", "list")
    if sub == "add":
        if args.label and len(args.hosts) != 1:
            print("--label can only be used when adding one target", file=sys.stderr)
            raise SystemExit(1)
        for host in args.hosts:
            norm = normalize_scope_entry(host)
            if not norm:
                print(f"ignored invalid target: {host}")
                continue
            rec = ws.add_target(norm, args.label or "")
            print(f"added target {rec['label']} ({rec['host']})" + ("  [active]" if ws.target == rec["host"] else ""))
        ws.save()
        return
    if sub == "use":
        if not ws.set_active_target(args.host):
            print(f"no target {args.host!r} in this engagement.", file=sys.stderr)
            raise SystemExit(1)
        ws.save()
        print(f"active target: {ws.target}")
        return
    if sub == "rm":
        if not ws.remove_target(args.host):
            print(f"no target {args.host!r}.", file=sys.stderr)
            raise SystemExit(1)
        ws.save()
        print(f"removed target {args.host}")
        return
    if not ws.targets:
        print("no targets yet. add one: obol target add <ip>")
        return
    for t in ws.targets:
        mark = "*" if t["host"] == ws.target else " "
        print(f" {mark} {t['host']:16} {t.get('label', '')}")


def cmd_web(args) -> None:
    from . import web
    ws = _load_or_exit()
    out = Path(args.out) if args.out else (ws.dir / "web" / "index.html")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(web.build_page(ws))
    print(f"wrote {out}")


def cmd_report(args) -> None:
    from .report import write_report
    ws = _load_or_exit()
    out = Path(args.out) if args.out else None
    # Show secrets by default (lab/exam notes); `--redact` opts into redaction for a
    # draft you intend to share. `--include-secrets` is kept as a harmless no-op.
    include_secrets = not args.redact
    path = write_report(ws, out=out, include_secrets=include_secrets, max_next=args.max_next)
    print(f"wrote {path}")
    if include_secrets:
        print("secrets shown — this report contains passwords/hashes; use --redact for a shareable draft")
    else:
        print("secrets redacted")


def cmd_debug(args) -> None:
    from . import debug
    ws = _load_or_exit()
    out = Path(args.out) if getattr(args, "out", None) else None
    screenshots = not getattr(args, "no_screenshots", False)
    if getattr(args, "debug_cmd", "package") == "capture":
        print(f"capturing every {args.interval}s — Ctrl-C to stop and bundle…")
        zip_path = debug.capture(
            lambda: _load_or_exit(), out=out, interval=args.interval,
            count=args.count, duration=args.duration,
            include_secrets=args.include_secrets, screenshots=screenshots,
            on_tick=lambda seq, s: print(f"  snapshot {seq}: {s['facts_total']} facts · {s['runs_total']} runs"),
        )
    else:
        zip_path = debug.build_debug_package(
            ws, out=out, include_secrets=args.include_secrets, screenshots=screenshots,
            live_url=getattr(args, "url", "") or "", live_token=getattr(args, "token", "") or "")
    print(f"wrote {zip_path}")
    if not args.include_secrets:
        print("secrets redacted in report.md — raw run output under runs/ is verbatim; treat the package as sensitive")


def _pick_login_kind(ws: Workspace, host: str, requested: str) -> str:
    """Resolve which login kind to open: the one requested, or the single ready
    offer, else print the choices and exit."""
    offers = sessions.eligible_sessions(ws, host)
    if requested:
        return requested
    ready = [o for o in offers if o["ready"]]
    if len(ready) == 1:
        return ready[0]["kind"]
    if not offers:
        print(f"no login is available for {host} yet — need a validated credential "
              f"and a reachable service (winrm/ssh/rdp).", file=sys.stderr)
        raise SystemExit(1)
    print(f"pick a login kind for {host} with --kind:")
    for o in offers:
        state = "ready" if o["ready"] else f"not ready ({o['reason']})"
        print(f"  {o['kind']:<6} {o['label']}  — {state}")
    raise SystemExit(1)


def cmd_login(args) -> None:
    ws = _load_or_exit()
    host = args.target or ws.target
    if not host:
        print("no target — pass a host or set an active target.", file=sys.stderr)
        raise SystemExit(1)
    kind = _pick_login_kind(ws, host, args.kind)
    print(f"\n$ validating {kind} access on {host} …")
    try:
        res = sessions.open_session(ws, host, kind, method=args.method,
                                    dry_run=args.dry_run, surface="cli")
    except (SessionError, ActionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except RunnerError as exc:
        print(f"\nerror: {exc}", file=sys.stderr)
        raise SystemExit(1)
    if args.dry_run:
        print(f"\ndry run — would validate with:\n   $ {res['outcome'].command}")
        print(f"then hand off the interactive login:\n   $ {res['login_command']}")
        return
    if not res["ok"]:
        print(f"\n✗ {res['reason']}")
        raise SystemExit(1)
    s = res["session"]
    via = " via pass-the-hash" if res.get("method") == "pth" else ""
    print(f"\n{board.SYM_OK} access proven{via} ({s['proof_fact']}) — session {s['id']} recorded (status: {s['status']}).")
    print("\nlaunch the interactive session in your terminal:")
    print(f"   $ {res['login_command']}")
    print("\nprivesc moves for this host are now unlocked — `obol next`.")


def cmd_sessions(args) -> None:
    ws = _load_or_exit()
    if not ws.sessions:
        print("no sessions yet. establish one with `obol login <host>`.")
        return
    print(f"{'ID':<20} {'HOST':<16} {'KIND':<6} {'USER':<18} STATUS")
    for s in ws.sessions:
        print(f"{s['id']:<20} {s['host']:<16} {s['kind']:<6} {(s.get('user') or '-'):<18} {s['status']}")


def cmd_session(args) -> None:
    ws = _load_or_exit()
    cmd = getattr(args, "session_cmd", "list")
    if cmd == "close":
        if not ws.close_session(args.id):
            print(f"no session {args.id!r}", file=sys.stderr)
            raise SystemExit(1)
        ws.save()
        print(f"closed {args.id}")
    elif cmd == "rm":
        if not ws.remove_session(args.id):
            print(f"no session {args.id!r}", file=sys.stderr)
            raise SystemExit(1)
        ws.save()
        print(f"removed {args.id}")
    elif cmd == "probe":
        print(f"$ re-validating session {args.id} …")
        try:
            res = sessions.probe_session(ws, args.id)
        except (SessionError, ActionError, RunnerError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            raise SystemExit(1)
        print(f"session {args.id}: {'active' if res['alive'] else 'dead'}")
    else:
        cmd_sessions(args)


def cmd_pivots(args) -> None:
    """Show the engagement's pivot candidates: hosts with a proven foothold whose
    local enumeration turned up multi-homing or adjacent subnets to pivot into."""
    ws = _load_or_exit()
    rows = engagement_pivots(ws)
    if not rows:
        print("no pivot candidates yet — get a foothold and run the local enumeration "
              "sweep (`obol next` on a host you have access to).")
        return
    print("PIVOT CANDIDATES")
    for piv in rows:
        tag = "multi-homed" if piv["multihomed"] else "adjacent subnet"
        print(f"\n  {piv['label']} ({piv['host']}) — {tag}")
        for s in piv["subnets"]:
            mark = "in scope" if s["in_scope"] else "NOT in scope — a tunnel would authorize it"
            print(f"    {s['cidr']:<20} {mark}")
        if piv["dns_servers"]:
            print(f"    internal DNS: {', '.join(piv['dns_servers'])}")
    print("\nbuild a tunnel: obol tunnel open <host> --kind <ligolo|chisel|sshuttle|ssh-dynamic|ssh-local> --subnet <cidr>")


def cmd_topology(args) -> None:
    """Show the pivot topology: network segments joined by tunnels (§6f)."""
    from .graph import build_topology
    ws = _load_or_exit()
    topo = build_topology(ws)
    if not topo["segments"]:
        print("no network segments yet — add a CIDR to scope and sweep it.")
        return
    print("PIVOT TOPOLOGY")
    for seg in topo["segments"]:
        src = "operator" if seg["source"] == "operator" else f"pivot-authorized via {seg['via_tunnel']}"
        print(f"\n  ▢ {seg['cidr']}  ({src})")
        for h in seg["hosts"]:
            marks = []
            if h["foothold"]:
                marks.append("foothold")
            if h["session"]:
                marks.append("session")
            tag = f"  [{', '.join(marks)}]" if marks else ""
            print(f"      • {h['label']} ({h['host']}){tag}")
        if not seg["hosts"]:
            print("      (no hosts discovered yet)")
    if topo["hops"]:
        print("\n  TUNNEL HOPS")
        for hop in topo["hops"]:
            pxy = " proxychains" if hop["proxychains"] else ""
            staged = f"  [{hop['staged_material']} @ {hop['staged_path']}]" if hop["staged_material"] else ""
            frm = hop["from_segment"] or hop["pivot_host"]
            print(f"    {frm} ──{hop['kind']}/{hop['transport']}[{hop['status']}]{pxy}──▶ {hop['to_segment']}{staged}")


def cmd_tunnels(args) -> None:
    """List tunnel transports and any live tunnels."""
    ws = _load_or_exit()
    if ws.tunnels:
        print(f"{'ID':<20} {'HOST':<16} {'KIND':<12} {'TRANSPORT':<12} {'EXPOSED':<18} STATUS")
        for t in ws.tunnels:
            pxy = " (proxychains)" if t.get("proxychains") else ""
            print(f"{t['id']:<20} {t['host']:<16} {t['kind']:<12} {t['transport']:<12} "
                  f"{(t.get('exposed_subnet') or '-'):<18} {t['status']}{pxy}")
        print()
    print("available transports:")
    for k in tunnels.TUNNEL_KINDS:
        pxy = "proxychains" if k.needs_proxychains else "direct"
        sub = "subnet route" if k.exposes_subnet else "single-port forward"
        print(f"  {k.key:<12} {k.transport:<12} {pxy:<12} {sub}")


def cmd_tunnel(args) -> None:
    ws = _load_or_exit()
    cmd = getattr(args, "tunnel_cmd", "list")
    if cmd == "open":
        host = args.target or ws.target
        if not host:
            print("no target — pass a host or set an active target.", file=sys.stderr)
            raise SystemExit(1)
        try:
            res = tunnels.open_tunnel(ws, host, args.kind, subnet=args.subnet,
                                      local_port=args.local_port, remote=args.remote,
                                      remote_port=args.remote_port, lhost=args.lhost,
                                      surface="cli")
        except TunnelError as exc:
            print(f"error: {exc}", file=sys.stderr)
            raise SystemExit(1)
        t = res["tunnel"]
        print(f"\n{board.SYM_OK} tunnel {t['id']} recorded ({t['kind']}, {t['transport']}, status: {t['status']}).")
        if res["scope_added"]:
            print(f"scope auto-extended (pivot-authorized): {res['scope_added']}")
        if res["proxychains"]:
            print("hosts reached through this tunnel are auto-prefixed with `proxychains -q`.")
        print("\nlaunch the tunnel in your terminal:")
        print(f"   $ {res['setup_command']}")
    elif cmd == "auto":
        host = args.target or ws.target
        if not host:
            print("no target — pass a host or set an active target.", file=sys.stderr)
            raise SystemExit(1)
        try:
            res = tunnels.auto_tunnel(ws, host, subnet=args.subnet, lhost=args.lhost,
                                      remote=args.remote, remote_port=args.remote_port,
                                      local_port=args.local_port, surface="cli")
        except TunnelError as exc:
            print(f"error: {exc}", file=sys.stderr)
            raise SystemExit(1)
        print("auto-tunnel cascade:")
        for a in res["attempts"]:
            if a.get("ok"):
                si = a.get("staged_info") or {}
                staged = f" [staged {si['material']} → {si['remote_path']}, {'verified' if si.get('verified') else 'unverified'}]" if si else ""
                print(f"  {board.SYM_OK} {a['kind']}{staged}")
            else:
                print(f"  × {a['kind']}: {a.get('reason', 'failed')}")
        if not res["ok"]:
            print(f"\n× {res.get('reason', 'no tunnel')}", file=sys.stderr)
            raise SystemExit(1)
        t = res["tunnel"]
        print(f"\n{board.SYM_OK} {t['kind']} tunnel {t['id']} ({t['transport']}, status: {t['status']}).")
        if not res["full_route"]:
            print("  note: this is a SINGLE-PORT forward, not a full subnet route.")
        if res["scope_added"]:
            print(f"  scope auto-extended (pivot-authorized): {res['scope_added']}")
        if res["proxychains"]:
            print("  hosts through this tunnel are auto-prefixed with `proxychains -q`.")
        print(f"\nlaunch it:\n   $ {res['setup_command']}")
        print(f"\n{res['sweep_hint']}")
    elif cmd == "sweep":
        try:
            res = discovery.run_tunnel_sweep(ws, args.id)
        except RunnerError as exc:
            print(f"error: {exc}", file=sys.stderr)
            raise SystemExit(1)
        print(f"through-tunnel sweep of {res['subnet']} via {res['tunnel']} ({res['transport']})")
        print(f"  tunnel health: {res['status']}  ·  {len(res['hosts'])} live host(s)")
        if res["created"]:
            print(f"  new targets: {', '.join(res['created'])}")
        if res["existing"]:
            print(f"  already known: {', '.join(res['existing'])}")
    elif cmd == "close":
        try:
            tunnels.close_tunnel(ws, args.id)
        except TunnelError as exc:
            print(f"error: {exc}", file=sys.stderr)
            raise SystemExit(1)
        print(f"closed {args.id}")
    elif cmd == "rm":
        try:
            res = tunnels.remove_tunnel(ws, args.id)
        except TunnelError as exc:
            print(f"error: {exc}", file=sys.stderr)
            raise SystemExit(1)
        print(f"removed {args.id}"
              + (f" (scope retracted: {res['scope_retracted']})" if res["scope_retracted"] else ""))
    else:
        cmd_tunnels(args)


def cmd_cache(args) -> None:
    """The Kali-side material cache: what obol can stage onto a foothold, and a
    one-click download for anything missing. Machine-scoped — no engagement needed."""
    cmd = getattr(args, "cache_cmd", "list")
    if cmd == "get":
        print(f"$ fetching {args.key} into {provision.cache_dir()} …")
        try:
            res = provision.download(args.key)
        except KeyError:
            print(f"unknown material {args.key!r} (see `obol cache`).", file=sys.stderr)
            raise SystemExit(1)
        if not res.get("ok"):
            print(f"error: {res.get('error')}", file=sys.stderr)
            raise SystemExit(1)
        vtag = "verified" if res.get("verified") else "unverified (no pinned digest)"
        print(f"{board.SYM_OK} cached {args.key}: {res['path']}")
        print(f"   sha256 {res['sha256']}  ({res['bytes']} bytes, {vtag})")
        return
    if cmd == "use":
        try:
            res = provision.use_local(args.key, args.path)
        except KeyError:
            print(f"unknown material {args.key!r} (see `obol cache`).", file=sys.stderr)
            raise SystemExit(1)
        except FileNotFoundError:
            print(f"no such file: {args.path}", file=sys.stderr)
            raise SystemExit(1)
        print(f"{board.SYM_OK} registered local {args.key}: {res['path']}")
        return
    if cmd == "rm":
        try:
            provision.remove(args.key)
        except KeyError:
            print(f"unknown material {args.key!r} (see `obol cache`).", file=sys.stderr)
            raise SystemExit(1)
        print(f"removed {args.key} from the cache")
        return
    if cmd == "path":
        path = provision.resolve_path(args.key)
        if not path:
            print(f"{args.key}: not present locally (try `obol cache get {args.key}`)", file=sys.stderr)
            raise SystemExit(1)
        print(path)
        return
    # default: list the inventory
    s = provision.scan()
    print(f"MATERIAL CACHE  ({s['present']}/{s['total']} present)   {s['cache_dir']}")
    mark = {"cached": board.SYM_OK, "installed": board.SYM_OK, "missing": "·"}
    for g in s["groups"]:
        print(f"\n  {g['category']}")
        for m in g["materials"]:
            sym = mark.get(m["status"], "·")
            hint = ""
            if m["status"] == "missing":
                hint = (f"  → obol cache get {m['key']}" if m.get("downloadable")
                        else f"  → obol cache use {m['key']} <path>")
            elif m["status"] == "installed":
                hint = "  (on PATH)"
            print(f"    {sym} {m['label']:<26} {m['os']:<7} {m['status']:<9}{hint}")
    print("\none-click download fetches into the cache and records a sha256; "
          "pinned-digest mismatches are rejected.")


def cmd_stage(args) -> None:
    """Push a cached material onto a foothold, cascading through transfer channels."""
    ws = _load_or_exit()
    host = args.target or ws.target
    if not host:
        print("no target — pass a host or set an active target.", file=sys.stderr)
        raise SystemExit(1)
    channels = [args.channel] if args.channel else None
    if args.dry_run:
        try:
            p = staging.plan(ws, host, args.material, channels=channels, remote_dir=args.remote_dir)
        except staging.StagingError as exc:
            print(f"error: {exc}", file=sys.stderr)
            raise SystemExit(1)
        print(f"transfer plan for {p['material']} → {p['host']}  (local: {p['local_path']})")
        for i, step in enumerate(p["steps"], 1):
            print(f"\n  {i}. {step['label']} ({step['channel']})")
            print(f"     $ {step['command']}")
            if step["verify"]:
                print(f"     verify: {step['verify']}")
        return
    print(f"$ staging {args.material} onto {host} …")
    try:
        res = staging.stage(ws, host, args.material, channels=channels, remote_dir=args.remote_dir)
    except (staging.StagingError, service.ActionError, RunnerError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    for a in res["attempts"]:
        sym = board.SYM_OK if a.get("ok") else "×"
        extra = " (verified)" if a.get("verified") else ("" if a.get("ok") else f" — {a.get('error', 'failed')}")
        print(f"  {sym} {a['channel']}{extra}")
    if res["ok"]:
        st = res["staged"]
        print(f"\n{board.SYM_OK} staged via {res['channel']}: {st['remote_path']} "
              f"({'verified' if st['verified'] else 'unverified'})")
    else:
        print(f"\n× {res.get('reason', 'transfer failed')}", file=sys.stderr)
        raise SystemExit(1)


def cmd_staged(args) -> None:
    """List material obol has staged onto footholds (live on-target state)."""
    ws = _load_or_exit()
    cmd = getattr(args, "staged_cmd", "list")
    if cmd == "rm":
        if not ws.remove_staged(args.id):
            print(f"no staged record {args.id!r}", file=sys.stderr)
            raise SystemExit(1)
        ws.save()
        print(f"removed {args.id}")
        return
    if not ws.staged:
        print("nothing staged yet. push a tool with `obol stage <material> [host]`.")
        return
    print(f"{'ID':<20} {'HOST':<16} {'MATERIAL':<16} {'CHANNEL':<14} {'STATUS':<9} REMOTE")
    for sf in ws.staged:
        print(f"{sf['id']:<20} {sf['host']:<16} {sf['material']:<16} {sf['channel']:<14} "
              f"{sf['status']:<9} {sf['remote_path']}")


def cmd_enum(args) -> None:
    """Stage and run a read-only enum tool (linpeas/winpeas) on a foothold, then rank
    the promising findings."""
    ws = _load_or_exit()
    host = args.target or ws.target
    if not host:
        print("no target — pass a host or set an active target.", file=sys.stderr)
        raise SystemExit(1)
    print(f"$ staging + running {args.tool} on {host} …")
    try:
        res = enumrun.run_enum(ws, host, args.tool)
    except (enumrun.EnumError, service.ActionError, RunnerError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    if res.get("guided"):
        print(f"{board.SYM_OK} staged {args.tool} at {res['remote_path']}. Run it interactively:")
        print(f"   $ {res['run_command']}")
        return
    print(f"{board.SYM_OK} ran {args.tool} ({res['remote_path']}, via {res['channel']})")
    if res["privesc_leads"]:
        print(f"\nprivesc leads: {', '.join(res['privesc_leads'])}")
    if res["highlights"]:
        print(f"\ntop findings ({len(res['highlights'])}):")
        for h in res["highlights"][:15]:
            print(f"  [{h['signal']}] {h['line'][:110]}")
    if not res["privesc_leads"] and not res["highlights"]:
        print("no ranked findings — review the raw run output under .obol/runs/.")


def cmd_listener(args) -> None:
    """Manage reverse-shell listeners (live catch-a-shell state)."""
    ws = _load_or_exit()
    cmd = getattr(args, "listener_cmd", "list")
    if cmd == "start":
        try:
            res = listeners.start_listener(ws, args.port, kind=args.kind, lhost=args.lhost,
                                           host=args.target, os_name=args.os)
        except listeners.ListenerError as exc:
            print(f"error: {exc}", file=sys.stderr)
            raise SystemExit(1)
        ln = res["listener"]
        print(f"{board.SYM_OK} listener {ln['id']} ({ln['kind']}) recorded — run it in a terminal:")
        print(f"   $ {res['listen_command']}")
        print(f"\nfire one of these on the {args.os} target (lhost {ln['lhost']}, lport {ln['port']}):")
        for p in res["payloads"]:
            print(f"   [{p['name']}] {p['command']}")
        print(f"\nwhen it lands: obol listener catch {ln['id']} --host <target> --proof \"$(id)\"")
        return
    if cmd == "catch":
        try:
            res = listeners.record_catch(ws, args.id, host=args.host, proof_output=args.proof)
        except listeners.ListenerError as exc:
            print(f"error: {exc}", file=sys.stderr)
            raise SystemExit(1)
        if res["proof_fact"]:
            print(f"{board.SYM_OK} caught + proved {res['proof_fact']} — session recorded.")
        else:
            print(f"{board.SYM_OK} marked caught (no proof output given — no fact recorded).")
        return
    if cmd in ("close", "rm"):
        ok = listeners.close_listener(ws, args.id) if cmd == "close" else listeners.remove_listener(ws, args.id)
        if not ok:
            print(f"no listener {args.id!r}", file=sys.stderr)
            raise SystemExit(1)
        print(f"{'closed' if cmd == 'close' else 'removed'} {args.id}")
        return
    # default: list
    if not ws.listeners:
        print("no listeners yet. start one with `obol listener start <port>`.")
        return
    print(f"{'ID':<20} {'KIND':<10} {'PORT':<6} {'STATUS':<10} LHOST")
    for ln in ws.listeners:
        print(f"{ln['id']:<20} {ln['kind']:<10} {ln['port']:<6} {ln['status']:<10} {ln.get('lhost', '')}")


def cmd_exploits(args) -> None:
    """List privilege-escalation exploits applicable to a foothold (by proven leads)."""
    ws = _load_or_exit()
    host = args.target or ws.target
    if not host:
        print("no target — pass a host or set an active target.", file=sys.stderr)
        raise SystemExit(1)
    rows = exploits.eligible_exploits(ws, host)
    if not rows:
        print(f"no applicable exploits for {host} yet — run `obol enum` to surface privesc leads.")
        return
    print(f"APPLICABLE EXPLOITS for {host}")
    for e in rows:
        tag = " (guided)" if e["guided"] else ""
        print(f"\n  {e['key']}{tag} — {e['label']}")
        print(f"    lead: {e['lead']}   outcomes: {', '.join(e['outcomes'])}")
        if e["note"]:
            print(f"    note: {e['note']}")
    print("\ncraft one: obol exploit <key> --outcome add-user|system-shell|revshell [--run]")


def cmd_exploit(args) -> None:
    """Craft (and, with --run, execute) an applicable privesc exploit."""
    ws = _load_or_exit()
    host = args.target or ws.target
    if not host:
        print("no target — pass a host or set an active target.", file=sys.stderr)
        raise SystemExit(1)
    try:
        if not args.run:
            res = exploits.plan_exploit(ws, host, args.key, args.outcome,
                                        newuser=args.user, newpass=args.password)
        else:
            res = exploits.run_exploit(ws, host, args.key, args.outcome, approve=True,
                                       newuser=args.user, newpass=args.password,
                                       listener_id=args.listener)
    except (exploits.ExploitError, staging.StagingError, service.ActionError, RunnerError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    if res["guided"]:
        print(f"{res['label']} is guided:\n  {res['note']}")
        return
    print(f"exploit {res['exploit']} → {res['outcome']}")
    if res.get("newuser"):
        print(f"  new admin account: {res['newuser']} / {res['newpass']}")
    print(f"\n  $ {res['command']}")
    if res.get("cleanup"):
        print(f"  cleanup: {res['cleanup']}")
    if not args.run:
        print("\nreview above, then re-run with --run to execute (approval-gated).")
        return
    if res.get("proof_fact"):
        print(f"\n{board.SYM_OK} proved {res['proof_fact']} (from command output).")
    elif res.get("credential_recorded"):
        print(f"\n{board.SYM_OK} created admin credential — use it: obol login {host}")
    else:
        print(f"\nran (rc={res.get('returncode')}). Verify the outcome before trusting it.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="obol",
        description="Evidence-driven OSCP operator companion.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""common flow:
  obol engagement new "HTB Lab"
  obol scope add 10.10.10.0/24
  obol scan
  obol overview
  obol next
  obol run 1

try:
  obol manual          full operator workflow
  obol help <command>  help for one command
""",
    )
    p.add_argument("-V", "-v", "--version", action="store_true", help="show the obol version and exit")
    p.add_argument("--info", action="store_true", help="show version and current workspace summary")
    sub = p.add_subparsers(dest="cmd")

    ph = sub.add_parser("help", help="show help for obol or a specific command")
    ph.add_argument("topic", nargs="?", help="command to explain")
    ph.set_defaults(func=cmd_help)

    sub.add_parser("manual", help="show the practical operator manual").set_defaults(func=cmd_manual)
    sub.add_parser("version", help="show the obol version").set_defaults(func=cmd_version)
    sub.add_parser("info", help="show version and current workspace summary").set_defaults(func=cmd_info)

    pi = sub.add_parser("init", help="initialize a workspace in the current directory")
    pi.add_argument("--target", help="target host/IP")
    pi.add_argument("--demo", action="store_true", help="seed the HTB Forest demo facts")
    pi.set_defaults(func=cmd_init)

    pn = sub.add_parser("next", help="show proven facts and ranked next actions for the active target")
    pn.add_argument("--all", action="store_true", help="show an engagement-wide next-move overview")
    pn.set_defaults(func=cmd_next)

    sub.add_parser("overview", help="show scope, targets, services, and top next moves").set_defaults(func=cmd_overview)

    pm = sub.add_parser("moves", help="the unified ranked move frontier for a target "
                                      "(pack actions + logins/enum/exploits/tunnels)")
    pm.add_argument("host", nargs="?", default="", help="target host (default: active target)")
    pm.add_argument("--all", action="store_true",
                    help="also list moves waiting on one input, with the reason")
    pm.set_defaults(func=cmd_moves)

    pd = sub.add_parser("do", help="run one move from the frontier by id (see `obol moves`)")
    pd.add_argument("id", help="move id: a pack action id, or login:KIND / enum:TOOL / "
                              "tunnel:KIND / exploit:KEY")
    pd.add_argument("host", nargs="?", default="", help="target host (default: active target)")
    pd.add_argument("--dry-run", action="store_true",
                    help="preview an action/login command without executing")
    pd.add_argument("--method", default="", help="login method: password|pth")
    pd.add_argument("--subnet", default="", help="exposed subnet for a subnet-routing tunnel")
    pd.add_argument("--outcome", default="",
                    help="exploit outcome to craft: add-user|system-shell|revshell")
    pd.set_defaults(func=cmd_do)

    pc = sub.add_parser("cruise", help="auto-run the safe (recon/enum) moves for a target, "
                                       "stopping at the first move that needs your approval")
    pc.add_argument("host", nargs="?", default="", help="target host (default: active target)")
    pc.add_argument("--all", action="store_true",
                    help="cruise every in-scope target (the recursion across segments)")
    pc.add_argument("--sweep", action="store_true",
                    help="auto-run through-tunnel sweeps of already-opened pivots "
                         "(carries cruise into the pivoted segment; opening a tunnel still asks)")
    pc.add_argument("--max-steps", type=int, default=25, help="safety cap on moves per target")
    pc.set_defaults(func=cmd_cruise)

    pau = sub.add_parser("autonomy", help="show (or set) how autonomous obol may be this "
                                          "engagement — the exam/lab consent policy")
    pau.add_argument("action", nargs="?", default="show", choices=["show", "set"])
    pau.add_argument("kind", nargs="?", default="",
                     help="move kind for `set` (login/stage/tunnel/sweep/enum/exploit/…)")
    pau.add_argument("decision", nargs="?", default="",
                     help="auto | ask | never | clear (for `set`)")
    pau.set_defaults(func=cmd_autonomy)

    po = sub.add_parser("objectives", help="show the per-target objective ladder "
                                           "(initial access → privesc → local → root flag)")
    po.add_argument("host", nargs="?", default="", help="target host (default: active target)")
    po.set_defaults(func=cmd_objectives)

    pi = sub.add_parser("ingest", help="parse output from a command you ran yourself into "
                                       "facts (paste on stdin or --file) — the way back into cruise")
    pi.add_argument("--action", default="", help="scope action-specific parsers (e.g. linux-enum)")
    pi.add_argument("--target", default="", help="host the output is about (default: active target)")
    pi.add_argument("--note", default="", help="what you ran (recorded as the run's lineage)")
    pi.add_argument("--file", default="", help="read the output from a file instead of stdin")
    pi.set_defaults(func=cmd_ingest)

    pa = sub.add_parser("assert", help="record an operator-attested fact directly (the escape "
                                       "hatch when there is no parseable output)")
    pa.add_argument("kind", help="fact kind, e.g. access.shell, foothold.linux, credential.available")
    pa.add_argument("--target", default="", help="host the fact is about (default: active target)")
    pa.add_argument("--scope", default="", help="explicit scope (e.g. domain:htb.local); default host:<target>")
    pa.add_argument("--set", action="append", metavar="k=v", help="value field(s) for the fact")
    pa.add_argument("--note", default="", help="how you proved it (recorded as lineage)")
    pa.add_argument("--state", default="supported", choices=["supported", "refuted", "inconclusive"])
    pa.set_defaults(func=cmd_assert)

    pe = sub.add_parser("explain", help="show the full command card (hypothesis, commands, references) for action N")
    pe.add_argument("n", type=int)
    pe.set_defaults(func=cmd_explain)

    pr = sub.add_parser("run", help="run next action N, ingest its evidence, update facts")
    pr.add_argument("n", type=int)
    pr.add_argument("--cmd", type=int, default=1, help="command variant to run from `obol explain N` (default 1)")
    pr.add_argument("--set", action="append", default=[], metavar="KEY=VALUE", help="set command template input for this workspace")
    pr.add_argument("--timeout", type=int, default=300)
    pr.add_argument("--dry-run", action="store_true", help="print and validate the command without executing it")
    pr.add_argument("--allow-shell", action="store_true", help="allow shell metacharacters in guided handoff commands")
    pr.set_defaults(func=cmd_run)

    sub.add_parser("playbooks", help="list available playbooks (named, ordered action sequences)").set_defaults(func=cmd_playbooks)

    pp = sub.add_parser("playbook", help="show a playbook's command plan, or run one step of it")
    pp.add_argument("name", help="playbook name (see `obol playbooks`)")
    pp.add_argument("--step", type=int, help="run this step through the same runner/parser as `obol run`")
    pp.add_argument("--approve", action="store_true", help="approve a step marked require_approval (noisy/risky)")
    pp.add_argument("--set", action="append", default=[], metavar="KEY=VALUE", help="set command template input for this workspace")
    pp.add_argument("--timeout", type=int, default=300)
    pp.add_argument("--dry-run", action="store_true", help="print and validate the step's command without executing it")
    pp.add_argument("--allow-shell", action="store_true", help="allow shell metacharacters in guided handoff commands")
    pp.set_defaults(func=cmd_playbook)

    sub.add_parser("facts", help="list all proven facts").set_defaults(func=cmd_facts)

    pf = sub.add_parser("findings", help="show engagement-wide findings grouped by category")
    pf.add_argument("--host", help="only show host-scoped findings for this host")
    pf.add_argument("--category", help="only show one category (target, service, ad, credential, access, ...)")
    pf.add_argument("--limit", type=int, default=0, help="maximum findings to print (0 = all)")
    pf.add_argument("--redact", action="store_true", help="redact passwords/hashes/tickets")
    pf.add_argument("--include-refuted", action="store_true", help="include refuted validation evidence")
    pf.add_argument("--no-evidence", action="store_true", help="hide source command lines")
    pf.set_defaults(func=cmd_findings)

    pscan = sub.add_parser("scan", help="scan every scoped entry, then Quick Start scoped targets")
    pscan.add_argument("entries", nargs="*", help="optional IP/CIDR entries to authorize and scan now")
    pscan.add_argument("--extract", action="store_true", help="extract only IPs/CIDRs from pasted entries")
    pscan.add_argument("--no-enumerate", action="store_true", help="discovery only; do not run Quick Start")
    pscan.add_argument("--new-only", action="store_true", help="Quick Start only targets created by this scan")
    pscan.add_argument("--timeout", type=int, default=600, help="discovery sweep timeout in seconds")
    pscan.add_argument("--quick-timeout", type=int, default=300, help="per-command Quick Start timeout in seconds")
    pscan.add_argument("--dry-run", action="store_true", help="print discovery commands without running them")
    pscan.add_argument("--allow-shell", action="store_true", help="allow shell metacharacters in guided handoff commands")
    pscan.set_defaults(func=cmd_scan)

    psweep = sub.add_parser("sweep", help="discover live hosts in one range and add them as targets")
    psweep.add_argument("range", help="an authorized CIDR or host (added to scope if new)")
    psweep.add_argument("--no-enumerate", action="store_true", help="discovery only; do not Quick Start new hosts")
    psweep.add_argument("--timeout", type=int, default=600, help="discovery sweep timeout in seconds")
    psweep.add_argument("--quick-timeout", type=int, default=300, help="per-command Quick Start timeout in seconds")
    psweep.add_argument("--dry-run", action="store_true", help="print the discovery command without running it")
    psweep.add_argument("--allow-shell", action="store_true", help="allow shell metacharacters in guided handoff commands")
    psweep.set_defaults(func=cmd_sweep)

    plogin = sub.add_parser("login", help="validate access and open an interactive session (winrm/ssh/rdp)")
    plogin.add_argument("target", nargs="?", default="", help="host to log into (default: active target)")
    plogin.add_argument("--kind", default="", choices=[k.key for k in sessions.SESSION_KINDS],
                        help="login kind; inferred when only one is ready")
    plogin.add_argument("--method", default="", choices=["password", "pth"],
                        help="auth method: password or pth (pass-the-hash); "
                             "default prefers a password, else an NT hash")
    plogin.add_argument("--dry-run", action="store_true", help="show the proof + login commands without running")
    plogin.set_defaults(func=cmd_login)

    sub.add_parser("sessions", help="list interactive sessions (live login/pivot state)").set_defaults(func=cmd_sessions)
    psession = sub.add_parser("session", help="inspect or manage one session (probe/close/rm)")
    session_sub = psession.add_subparsers(dest="session_cmd")
    session_sub.add_parser("list", help="list sessions").set_defaults(func=cmd_session, session_cmd="list")
    for name, helptext in (("probe", "re-validate a session and refresh its status"),
                           ("close", "mark a session closed"),
                           ("rm", "remove a session record")):
        sp = session_sub.add_parser(name, help=helptext)
        sp.add_argument("id", help="session id (see `obol sessions`)")
        sp.set_defaults(func=cmd_session, session_cmd=name)
    psession.set_defaults(func=cmd_session, session_cmd="list")

    # pivots + tunnels (§6c/§6d) --------------------------------------------------
    sub.add_parser("pivots", help="show pivot candidates (multi-homed hosts + adjacent subnets)").set_defaults(func=cmd_pivots)

    sub.add_parser("topology", help="show the pivot topology (segments joined by tunnels)").set_defaults(func=cmd_topology)
    sub.add_parser("tunnels", help="list tunnel transports and any live tunnels").set_defaults(func=cmd_tunnels)
    ptunnel = sub.add_parser("tunnel", help="open or manage a pivot tunnel (ligolo/chisel/sshuttle/ssh)")
    tunnel_sub = ptunnel.add_subparsers(dest="tunnel_cmd")
    tunnel_sub.add_parser("list", help="list tunnels").set_defaults(func=cmd_tunnel, tunnel_cmd="list")
    t_open = tunnel_sub.add_parser("open", help="record a tunnel from a foothold and auto-extend scope to its subnet")
    t_open.add_argument("target", nargs="?", default="", help="foothold host (default: active target)")
    t_open.add_argument("--kind", required=True, choices=[k.key for k in tunnels.TUNNEL_KINDS],
                        help="tunnel transport")
    t_open.add_argument("--subnet", default="", help="the subnet the tunnel exposes (for subnet-route transports)")
    t_open.add_argument("--lhost", default="", help="your listener host/IP (for reverse transports)")
    t_open.add_argument("--local-port", type=int, default=0, dest="local_port", help="local listener/forward port")
    t_open.add_argument("--remote", default="", help="remote host for a single-port forward (ssh -L)")
    t_open.add_argument("--remote-port", type=int, default=0, dest="remote_port", help="remote port for a single-port forward")
    t_open.set_defaults(func=cmd_tunnel, tunnel_cmd="open")
    t_auto = tunnel_sub.add_parser("auto", help="auto-tunnel: walk the feasibility cascade, stage the binary, stand up the best pivot")
    t_auto.add_argument("target", nargs="?", default="", help="foothold host (default: active target)")
    t_auto.add_argument("--subnet", default="", help="subnet to route (default: inferred from pivot candidates)")
    t_auto.add_argument("--lhost", default="", help="your listener host/IP")
    t_auto.add_argument("--local-port", type=int, default=0, dest="local_port", help="local listener/forward port")
    t_auto.add_argument("--remote", default="", help="remote host for a portforward fallback")
    t_auto.add_argument("--remote-port", type=int, default=0, dest="remote_port", help="remote port for a portforward fallback")
    t_auto.set_defaults(func=cmd_tunnel, tunnel_cmd="auto")
    t_sweep = tunnel_sub.add_parser("sweep", help="through-tunnel sweep: re-run discovery through a tunnel (confirms health, finds hosts)")
    t_sweep.add_argument("id", help="tunnel id (see `obol tunnels`)")
    t_sweep.set_defaults(func=cmd_tunnel, tunnel_cmd="sweep")
    for name, helptext in (("close", "mark a tunnel down"),
                           ("rm", "remove a tunnel record (retracts its auto-added scope)")):
        tp = tunnel_sub.add_parser(name, help=helptext)
        tp.add_argument("id", help="tunnel id (see `obol tunnels`)")
        tp.set_defaults(func=cmd_tunnel, tunnel_cmd=name)
    ptunnel.set_defaults(func=cmd_tunnel, tunnel_cmd="list")

    pcache = sub.add_parser("cache", help="list/download stageable materials on this Kali box (linpeas, potatoes, chisel/ligolo)")
    cache_sub = pcache.add_subparsers(dest="cache_cmd")
    cache_sub.add_parser("list", help="list the material cache").set_defaults(func=cmd_cache, cache_cmd="list")
    c_get = cache_sub.add_parser("get", help="download a material into the cache (verifies sha256)")
    c_get.add_argument("key", help="material key (see `obol cache`)")
    c_get.set_defaults(func=cmd_cache, cache_cmd="get")
    c_use = cache_sub.add_parser("use", help="register an operator-supplied local file as a material")
    c_use.add_argument("key", help="material key (see `obol cache`)")
    c_use.add_argument("path", help="path to the local file")
    c_use.set_defaults(func=cmd_cache, cache_cmd="use")
    c_rm = cache_sub.add_parser("rm", help="drop a material from the cache")
    c_rm.add_argument("key", help="material key (see `obol cache`)")
    c_rm.set_defaults(func=cmd_cache, cache_cmd="rm")
    c_path = cache_sub.add_parser("path", help="print the local path of a cached material")
    c_path.add_argument("key", help="material key (see `obol cache`)")
    c_path.set_defaults(func=cmd_cache, cache_cmd="path")
    pcache.set_defaults(func=cmd_cache, cache_cmd="list")

    pstage = sub.add_parser("stage", help="push a cached material onto a foothold (cascades through transfer channels)")
    pstage.add_argument("material", help="material key (see `obol cache`)")
    pstage.add_argument("target", nargs="?", default="", help="foothold host (default: active target)")
    pstage.add_argument("--channel", default="", choices=[c.key for c in staging.CHANNELS],
                        help="force one transfer channel instead of the cascade")
    pstage.add_argument("--remote-dir", default="", dest="remote_dir", help="destination directory on the target")
    pstage.add_argument("--dry-run", action="store_true", help="show the channel cascade and commands without transferring")
    pstage.set_defaults(func=cmd_stage)
    pexploits = sub.add_parser("exploits", help="list privesc exploits applicable to a foothold (by proven leads)")
    pexploits.add_argument("target", nargs="?", default="", help="foothold host (default: active target)")
    pexploits.set_defaults(func=cmd_exploits)
    pexploit = sub.add_parser("exploit", help="craft (and with --run, execute) a privesc exploit")
    pexploit.add_argument("key", choices=[e.key for e in exploits.EXPLOITS], help="exploit key (see `obol exploits`)")
    pexploit.add_argument("target", nargs="?", default="", help="foothold host (default: active target)")
    pexploit.add_argument("--outcome", default="add-user",
                          choices=["add-user", "system-shell", "revshell"], help="what the exploit should do")
    pexploit.add_argument("--user", default="", help="new account name (add-user; default: obol)")
    pexploit.add_argument("--password", default="", help="new account password (add-user; default: random)")
    pexploit.add_argument("--listener", default="", help="listener id for the revshell outcome (see `obol listener`)")
    pexploit.add_argument("--run", action="store_true", help="execute (approval-gated); without it, only craft for review")
    pexploit.set_defaults(func=cmd_exploit)
    penum = sub.add_parser("enum", help="stage + run a read-only enum tool (linpeas/winpeas) and rank findings")
    penum.add_argument("tool", choices=list(enumrun.ENUM_TOOLS.keys()), help="enum tool")
    penum.add_argument("target", nargs="?", default="", help="foothold host (default: active target)")
    penum.set_defaults(func=cmd_enum)
    plistener = sub.add_parser("listener", help="manage reverse-shell listeners (catch a shell back to obol)")
    listener_sub = plistener.add_subparsers(dest="listener_cmd")
    listener_sub.add_parser("list", help="list listeners").set_defaults(func=cmd_listener, listener_cmd="list")
    l_start = listener_sub.add_parser("start", help="record a listener and get the listen command + payloads")
    l_start.add_argument("port", type=int, help="listen port")
    l_start.add_argument("--kind", default="penelope", choices=[k.key for k in listeners.LISTENER_KINDS])
    l_start.add_argument("--lhost", default="", help="callback IP (default: auto-detect tun0/OBOL_LHOST)")
    l_start.add_argument("--os", default="linux", choices=["linux", "windows"], help="target OS for the payload set")
    l_start.add_argument("--target", default="", help="associate with a target host")
    l_start.set_defaults(func=cmd_listener, listener_cmd="start")
    l_catch = listener_sub.add_parser("catch", help="mark a listener as having caught a shell (record proof)")
    l_catch.add_argument("id", help="listener id (see `obol listener`)")
    l_catch.add_argument("--host", required=True, help="the target the shell came from")
    l_catch.add_argument("--proof", default="", help="the shell's id/whoami output (records the access fact)")
    l_catch.set_defaults(func=cmd_listener, listener_cmd="catch")
    for name, helptext in (("close", "mark a listener closed"), ("rm", "remove a listener record")):
        lp = listener_sub.add_parser(name, help=helptext)
        lp.add_argument("id", help="listener id (see `obol listener`)")
        lp.set_defaults(func=cmd_listener, listener_cmd=name)
    plistener.set_defaults(func=cmd_listener, listener_cmd="list")
    sub.add_parser("staged", help="list material staged onto footholds").set_defaults(func=cmd_staged, staged_cmd="list")
    pstaged = sub.add_parser("unstage", help="remove a staged-material record (does not delete the file on the target)")
    pstaged.add_argument("id", help="staged record id (see `obol staged`)")
    pstaged.set_defaults(func=cmd_staged, staged_cmd="rm")

    pscope = sub.add_parser("scope", help="list, add, paste-filter, or remove authorized scope entries")
    scope_sub = pscope.add_subparsers(dest="scope_cmd")
    scope_sub.add_parser("list", help="list scope").set_defaults(func=cmd_scope, scope_cmd="list")
    padd = scope_sub.add_parser("add", help="add IPs, hostnames, URLs, or CIDRs to scope")
    padd.add_argument("values", nargs="+")
    padd.set_defaults(func=cmd_scope, scope_cmd="add")
    ppaste = scope_sub.add_parser("paste", help="extract only valid IPs/CIDRs from pasted text")
    ppaste.add_argument("text", nargs="*", help="pasted text; stdin is used when omitted")
    ppaste.add_argument("--file", help="read pasted text from a file")
    ppaste.set_defaults(func=cmd_scope, scope_cmd="paste")
    prm = scope_sub.add_parser("rm", aliases=["remove"], help="remove scope entries")
    prm.add_argument("values", nargs="+")
    prm.set_defaults(func=cmd_scope, scope_cmd="rm")
    scope_sub.add_parser("clear", help="remove non-target scope entries").set_defaults(func=cmd_scope, scope_cmd="clear")
    pscope.set_defaults(func=cmd_scope, scope_cmd="list")

    peng = sub.add_parser("engagement", help="manage engagements in the app-managed library")
    eng_sub = peng.add_subparsers(dest="engagement_cmd")
    eng_sub.add_parser("list", help="list engagements").set_defaults(func=cmd_engagement, engagement_cmd="list")
    e_new = eng_sub.add_parser("new", help="create an engagement and make it active")
    e_new.add_argument("name")
    e_new.set_defaults(func=cmd_engagement, engagement_cmd="new")
    e_use = eng_sub.add_parser("use", help="set the active engagement")
    e_use.add_argument("slug")
    e_use.set_defaults(func=cmd_engagement, engagement_cmd="use")
    peng.set_defaults(func=cmd_engagement, engagement_cmd="list")

    ptgt = sub.add_parser("target", help="manage targets in the current/active engagement")
    tgt_sub = ptgt.add_subparsers(dest="target_cmd")
    tgt_sub.add_parser("list", help="list targets").set_defaults(func=cmd_target, target_cmd="list")
    t_add = tgt_sub.add_parser("add", help="add one or more target hosts (unlocks the nmap prelude)")
    t_add.add_argument("hosts", nargs="+")
    t_add.add_argument("--label", help="friendly label for the target")
    t_add.set_defaults(func=cmd_target, target_cmd="add")
    t_use = tgt_sub.add_parser("use", help="set the active target")
    t_use.add_argument("host")
    t_use.set_defaults(func=cmd_target, target_cmd="use")
    t_rm = tgt_sub.add_parser("rm", help="remove a target")
    t_rm.add_argument("host")
    t_rm.set_defaults(func=cmd_target, target_cmd="rm")
    ptgt.set_defaults(func=cmd_target, target_cmd="list")

    pprof = sub.add_parser("profile", help="show or set the engagement profile (platform/exam type + flag config)")
    prof_sub = pprof.add_subparsers(dest="profile_cmd")
    prof_sub.add_parser("show", help="show the current engagement profile").set_defaults(func=cmd_profile, profile_cmd="show")
    prof_sub.add_parser("list", help="list the available platform/exam presets").set_defaults(func=cmd_profile, profile_cmd="list")
    p_set = prof_sub.add_parser("set", help="set the platform/exam type and/or override flag names/formats")
    p_set.add_argument("platform", nargs="?", default="", help="preset id or name (htb, oscp, thm, ctf, custom)")
    p_set.add_argument("--flag-names", dest="flag_names", default="", help="comma-separated flag filenames (override)")
    p_set.add_argument("--flag-formats", dest="flag_formats", default="", help="comma-separated value formats: brace,hex32,hex64,uuid,token")
    p_set.set_defaults(func=cmd_profile, profile_cmd="set")
    pprof.set_defaults(func=cmd_profile, profile_cmd="show")

    ps = sub.add_parser("serve", help="serve the live web surface on localhost (mirrors and drives the workspace)")
    ps.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1; keep local — the web can launch tools)")
    ps.add_argument("--port", type=int, default=8765)
    ps.set_defaults(func=cmd_serve)

    pw = sub.add_parser("web", help="write a self-contained read-only snapshot to a static HTML file")
    pw.add_argument("--out", help="output path (default .obol/web/index.html)")
    pw.set_defaults(func=cmd_web)

    prep = sub.add_parser("report", help="write an OSCP-style markdown report from the workspace ledger and facts")
    prep.add_argument("--out", help="output path (default report.md in the workspace root)")
    prep.add_argument("--redact", action="store_true", help="redact passwords/hashes/tickets (for a shareable draft; secrets are shown by default)")
    prep.add_argument("--include-secrets", action="store_true", help="deprecated no-op — secrets are already shown by default")
    prep.add_argument("--max-next", type=int, default=8, help="maximum recommended next actions to include")
    prep.set_defaults(func=cmd_report)

    pdbg = sub.add_parser("debug", help="build a debug package for review (state, evidence, terminal/site screenshots)")
    dbg_sub = pdbg.add_subparsers(dest="debug_cmd")
    d_pkg = dbg_sub.add_parser("package", help="write a one-shot debug package (.zip)")
    d_pkg.add_argument("--out", help="output directory (default .obol/debug)")
    d_pkg.add_argument("--include-secrets", action="store_true", help="include secrets in the embedded report")
    d_pkg.add_argument("--no-screenshots", action="store_true", help="skip PNG screenshots even if a browser is available")
    d_pkg.add_argument("--url", help="live `obol serve` URL to screenshot the real console (e.g. http://127.0.0.1:8765)")
    d_pkg.add_argument("--token", help="access token for --url (from the `obol serve` banner)")
    d_pkg.set_defaults(func=cmd_debug, debug_cmd="package")
    d_cap = dbg_sub.add_parser("capture", help="snapshot on a timer during a test run, then bundle a .zip")
    d_cap.add_argument("--interval", type=int, default=30, help="seconds between snapshots (default 30)")
    d_cap.add_argument("--count", type=int, help="stop after this many snapshots")
    d_cap.add_argument("--duration", type=int, help="stop after this many seconds")
    d_cap.add_argument("--out", help="output directory (default .obol/debug)")
    d_cap.add_argument("--include-secrets", action="store_true", help="include secrets in embedded reports")
    d_cap.add_argument("--no-screenshots", action="store_true", help="skip PNG screenshots")
    d_cap.set_defaults(func=cmd_debug, debug_cmd="capture")
    pdbg.set_defaults(func=cmd_debug, debug_cmd="package")
    return p


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "version", False):
        print(_version_text())
        return
    if getattr(args, "info", False):
        _print_info()
        return
    if not getattr(args, "cmd", None):
        parser.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    main()
