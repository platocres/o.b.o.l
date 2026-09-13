"""obol command-line surface.

Deliberately shell subcommands (PentOS-style), not an in-process REPL: every
action is independently re-runnable and leaves an explicit command in the
scrollback, which is what OSCP documentation needs. The loop is the human
running `obol next` -> `obol run N` -> `obol next` again.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import board
from .pack import next_actions, apply_action
from .seed import seed_forest
from .workspace import Workspace, find_workspace


def _load_or_exit() -> Workspace:
    ws = find_workspace()
    if ws is None:
        print("no obol workspace here. run `obol init` first.", file=sys.stderr)
        raise SystemExit(1)
    return ws


def _pick(ws: Workspace, n: int):
    actions = next_actions(ws.facts)
    if not 1 <= n <= len(actions):
        print(f"no next action #{n}. `obol next` lists {len(actions)}.", file=sys.stderr)
        raise SystemExit(1)
    return actions[n - 1]


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
    board.render_board(_load_or_exit())


def cmd_explain(args) -> None:
    ws = _load_or_exit()
    board.render_command(_pick(ws, args.n), ws)


def cmd_run(args) -> None:
    ws = _load_or_exit()
    action = _pick(ws, args.n)
    cmd = board.fill_command(action, ws)
    print(f"\n$ {cmd}")
    new = apply_action(action, ws.facts, source=cmd)
    ws.record_run(action.tool, cmd, [f.kind for f in new])
    ws.save()
    if new:
        print(f"\n{board.SYM_OK} ingested — new facts:")
        for f in new:
            detail = f.value.get("password") or f.value.get("hash") or f.value.get("sam") or ""
            print(f"   + {f.kind}" + (f"  ({detail})" if detail else ""))
    else:
        print("\n(no new facts — already proven)")
    print("\nnext: obol next")


def cmd_facts(args) -> None:
    ws = _load_or_exit()
    for f in sorted(ws.facts.facts, key=lambda x: x.kind):
        print(f"  {f.state.value:12} {f.kind:28} {f.value}")


def cmd_serve(args) -> None:
    from . import web
    web.serve(_load_or_exit(), port=args.port)


def cmd_web(args) -> None:
    from . import web
    ws = _load_or_exit()
    out = Path(args.out) if args.out else (ws.dir / "web" / "index.html")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(web.build_page(ws))
    print(f"wrote {out}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="obol", description="Evidence-driven OSCP operator companion.")
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("init", help="initialize a workspace in the current directory")
    pi.add_argument("--target", help="target host/IP")
    pi.add_argument("--demo", action="store_true", help="seed the HTB Forest demo facts")
    pi.set_defaults(func=cmd_init)

    sub.add_parser("next", help="show proven facts, ranked next actions, and blocked paths").set_defaults(func=cmd_next)

    pe = sub.add_parser("explain", help="show the command and proof boundary for next action N")
    pe.add_argument("n", type=int)
    pe.set_defaults(func=cmd_explain)

    pr = sub.add_parser("run", help="run next action N, ingest its evidence, update facts")
    pr.add_argument("n", type=int)
    pr.set_defaults(func=cmd_run)

    sub.add_parser("facts", help="list all proven facts").set_defaults(func=cmd_facts)

    ps = sub.add_parser("serve", help="serve the read-only web view on localhost")
    ps.add_argument("--port", type=int, default=8765)
    ps.set_defaults(func=cmd_serve)

    pw = sub.add_parser("web", help="write the read-only web view to a static HTML file")
    pw.add_argument("--out", help="output path (default .obol/web/index.html)")
    pw.set_defaults(func=cmd_web)
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
