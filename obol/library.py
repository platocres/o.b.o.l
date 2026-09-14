"""Engagement library — many engagements under one app-managed base directory.

An *engagement* is a workspace (a `.obol/` store) that holds one or more *targets*.
The library keeps engagements side by side under a base dir so both the terminal and
the web can create, list, and switch between them — instead of one engagement per
shell directory. The base dir is `$OBOL_HOME` (default `~/.obol`), engagements live
under `<base>/engagements/<slug>/`, and `<base>/active` records the selected one.

Backward compatible: the directory-based workspace (`obol init` in a cwd) still
works; the library is the model the web surface and the `obol engagement`/`target`
commands use.
"""
from __future__ import annotations

import os
import re
import time
from pathlib import Path

from .workspace import Workspace, has_state


_BASE_OVERRIDE: Path | None = None


def set_base(path) -> None:
    """Override the library base dir for this process (used by `obol serve` and
    tests). Takes precedence over $OBOL_HOME."""
    global _BASE_OVERRIDE
    _BASE_OVERRIDE = Path(path).expanduser() if path else None


def base_dir() -> Path:
    if _BASE_OVERRIDE is not None:
        return _BASE_OVERRIDE
    return Path(os.environ.get("OBOL_HOME", str(Path.home() / ".obol"))).expanduser()


def engagements_dir() -> Path:
    return base_dir() / "engagements"


def _active_file() -> Path:
    return base_dir() / "active"


def slugify(name: str) -> str:
    """A filesystem-safe slug for an engagement display name."""
    slug = re.sub(r"[^a-z0-9]+", "-", str(name or "").strip().lower()).strip("-")
    return slug or "engagement"


def _unique_slug(name: str) -> str:
    base = slugify(name)
    root = engagements_dir()
    slug, n = base, 2
    while has_state(root / slug):
        slug = f"{base}-{n}"
        n += 1
    return slug


def engagement_path(slug: str) -> Path:
    return engagements_dir() / slug


def list_engagements() -> list[dict]:
    """All engagements in the library, newest-active first isn't guaranteed — sorted
    by name. Each: {slug, name, path, targets, facts, created_at, active}."""
    root = engagements_dir()
    out: list[dict] = []
    if not root.exists():
        return out
    active = active_slug()
    for child in sorted(root.iterdir(), key=lambda p: p.name):
        if not has_state(child):
            continue
        ws = Workspace(child).load()
        out.append({
            "slug": child.name,
            "name": ws.name,
            "path": str(child),
            "targets": len(ws.targets),
            "facts": len(ws.facts.facts),
            "created_at": ws.created_at,
            "active": child.name == active,
        })
    return out


def create_engagement(name: str) -> Workspace:
    slug = _unique_slug(name)
    root = engagement_path(slug)
    root.mkdir(parents=True, exist_ok=True)
    ws = Workspace(root)
    ws.name = str(name).strip() or slug
    ws.created_at = time.time()
    ws.save()
    set_active(slug)
    return ws


def get_engagement(slug: str) -> Workspace | None:
    root = engagement_path(slug)
    if not has_state(root):
        return None
    return Workspace(root).load()


def active_slug() -> str | None:
    f = _active_file()
    if f.exists():
        slug = f.read_text().strip()
        if slug and has_state(engagement_path(slug)):
            return slug
    return None


def set_active(slug: str) -> None:
    base_dir().mkdir(parents=True, exist_ok=True)
    _active_file().write_text(slug)


def resolve_active() -> Workspace | None:
    slug = active_slug()
    return get_engagement(slug) if slug else None
