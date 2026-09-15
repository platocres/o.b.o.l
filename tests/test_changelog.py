import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _git(args: list[str]) -> list[str]:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _changed_files() -> set[str]:
    changed = set(_git(["diff", "--name-only"]))
    changed.update(_git(["diff", "--cached", "--name-only"]))
    changed.update(_git(["ls-files", "--others", "--exclude-standard"]))
    base = _git(["merge-base", "HEAD", "origin/main"])
    if base:
        changed.update(_git(["diff", "--name-only", f"{base[0]}...HEAD"]))
    return changed


def _requires_changelog(path: str) -> bool:
    if path == "CHANGELOG.md":
        return False
    if path.startswith(".github/"):
        return False
    if path.startswith("tests/"):
        return False
    if path.startswith(("obol/", "docs/", "scripts/")):
        return True
    return path in {"README.md", "AGENTS.md", "CLAUDE.md", "pyproject.toml"}


def test_changelog_exists_and_agents_point_to_it():
    changelog = ROOT / "CHANGELOG.md"
    assert changelog.exists()
    text = changelog.read_text()
    assert "## Unreleased" in text
    assert "Backfilled Project History" in text
    assert "CHANGELOG.md" in (ROOT / "AGENTS.md").read_text()


def test_meaningful_repo_changes_update_changelog():
    changed = _changed_files()
    meaningful = sorted(path for path in changed if _requires_changelog(path))
    if not meaningful:
        return
    assert "CHANGELOG.md" in changed, (
        "Meaningful repo changes must update CHANGELOG.md. "
        f"Files needing a changelog entry: {', '.join(meaningful)}"
    )
