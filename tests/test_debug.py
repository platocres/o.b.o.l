"""The debug package: a complete, self-describing bundle for review. Screenshots are
disabled here (no browser in CI) — the text bundle must stand on its own."""
import json
import zipfile

from obol import debug
from obol.facts import Fact
from obol.workspace import Workspace


def _seed(tmp_path) -> Workspace:
    ws = Workspace(tmp_path)
    ws.name = "Debug Eng"
    ws.add_target("10.10.10.5", "DC")
    ws.facts.add(Fact("ports.open", "host:10.10.10.5", {"ports": [445]}, source="nmap -Pn"))
    ws.record_run("nmap", "nmap -Pn 10.10.10.5", ["ports.open"], target="10.10.10.5",
                  returncode=0, dry_run=False)
    ws.save()
    return ws


def test_package_contains_everything(tmp_path):
    ws = _seed(tmp_path)
    zip_path = debug.build_debug_package(ws, out=tmp_path / "out", screenshots=False)
    assert zip_path.exists()
    names = zipfile.ZipFile(zip_path).namelist()
    stem = zip_path.stem
    for member in ("manifest.json", "README.md", "state.json", "events.jsonl",
                   "facts.json", "ledger.json", "report.md", "tools.json", "env.json",
                   "terminal/next.txt", "terminal/facts.txt", "site/index.html"):
        assert f"{stem}/{member}" in names, f"missing {member}"


def test_manifest_and_facts_are_valid(tmp_path):
    ws = _seed(tmp_path)
    zip_path = debug.build_debug_package(ws, out=tmp_path / "out", screenshots=False)
    zf = zipfile.ZipFile(zip_path)
    stem = zip_path.stem

    manifest = json.loads(zf.read(f"{stem}/manifest.json"))
    assert manifest["schema"] == debug.SCHEMA
    assert manifest["engagement"] == "Debug Eng"
    assert manifest["counts"]["facts_total"] >= 1

    state = json.loads(zf.read(f"{stem}/state.json"))
    assert state["name"] == "Debug Eng"

    facts = json.loads(zf.read(f"{stem}/facts.json"))
    assert "10.10.10.5" in facts["by_target"]
    assert facts["total"] >= 1


def test_capture_timeline(tmp_path):
    _seed(tmp_path)
    zip_path = debug.capture(lambda: Workspace(tmp_path).load(), out=tmp_path / "cap",
                             interval=0, count=2, screenshots=False)
    names = zipfile.ZipFile(zip_path).namelist()
    stem = zip_path.stem
    assert any(f"{stem}/timeline/001/" in n for n in names)
    assert any(f"{stem}/timeline/002/" in n for n in names)
    manifest = json.loads(zipfile.ZipFile(zip_path).read(f"{stem}/manifest.json"))
    assert manifest["mode"] == "capture" and len(manifest["ticks"]) == 2
