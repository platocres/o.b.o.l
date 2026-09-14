"""The SQLite store: concurrency-safe (two surfaces write), idempotent, migrates a
legacy state.json, and emits a change feed for the web SSE loop."""
import json

from obol.facts import Fact
from obol.store import STATE_DB, fact_hash
from obol.workspace import Workspace, has_state


def test_persist_and_reload(tmp_path):
    ws = Workspace(tmp_path)
    ws.add_target("10.10.10.5", "DC")
    ws.facts.add(Fact("ports.open", "host:10.10.10.5", {"ports": [445]}, source="nmap"))
    ws.record_run("nmap", "nmap -Pn 10.10.10.5", ["ports.open"])
    ws.save()
    assert (tmp_path / ".obol" / STATE_DB).exists()

    again = Workspace(tmp_path).load()
    assert [t["host"] for t in again.targets] == ["10.10.10.5"]
    assert again.facts.has("ports.open")
    assert len(again.runs) == 1 and again.runs[0]["id"]


def test_two_writers_do_not_clobber(tmp_path):
    """Terminal and web are separate processes doing read-modify-write. A whole-file
    JSON rewrite loses one; the store keeps both."""
    Workspace(tmp_path).load().save()  # create the db
    terminal = Workspace(tmp_path).load()
    web = Workspace(tmp_path).load()

    terminal.add_target("10.0.0.1")
    terminal.facts.add(Fact("smb.reachable", "host:10.0.0.1", {"tool": "nxc"}, source="terminal"))
    terminal.record_run("nxc", "nxc smb 10.0.0.1", ["smb.reachable"])
    terminal.save()

    web.add_target("10.0.0.2")
    web.facts.add(Fact("http.reachable", "host:10.0.0.2", {"tool": "nmap"}, source="web"))
    web.record_run("nmap", "nmap -p80 10.0.0.2", ["http.reachable"])
    web.save()

    final = Workspace(tmp_path).load()
    hosts = {t["host"] for t in final.targets}
    assert {"10.0.0.1", "10.0.0.2"} <= hosts, "both writers' targets survived"
    assert {"smb.reachable", "http.reachable"} <= final.facts.kinds()
    assert len([r for r in final.runs if r["tool"] in ("nxc", "nmap")]) == 2


def test_resave_is_idempotent(tmp_path):
    ws = Workspace(tmp_path)
    ws.facts.add(Fact("host.up", "host:10.0.0.9", {}, source="nmap"))
    ws.record_run("nmap", "nmap 10.0.0.9", ["host.up"])
    ws.save(); ws.save(); ws.save()
    reloaded = Workspace(tmp_path).load()
    assert len(reloaded.facts.facts) == 1
    assert len(reloaded.runs) == 1


def test_fact_hash_stable_and_scope_aware():
    a = fact_hash("ports.open", "host:1.1.1.1", {"ports": [80, 443]})
    b = fact_hash("ports.open", "host:1.1.1.1", {"ports": [80, 443]})
    c = fact_hash("ports.open", "host:2.2.2.2", {"ports": [80, 443]})
    assert a == b and a != c


def test_remove_target_persists_and_does_not_resurrect(tmp_path):
    ws = Workspace(tmp_path)
    ws.add_target("10.0.0.1"); ws.add_target("10.0.0.2"); ws.save()
    ws2 = Workspace(tmp_path).load()
    assert ws2.remove_target("10.0.0.2")
    ws2.save()
    assert [t["host"] for t in Workspace(tmp_path).load().targets] == ["10.0.0.1"]


def test_change_feed_emits_events(tmp_path):
    ws = Workspace(tmp_path)
    ws.add_target("10.0.0.7")
    ws.facts.add(Fact("ports.open", "host:10.0.0.7", {"ports": [22]}, source="nmap"))
    ws.record_run("nmap", "nmap 10.0.0.7", ["ports.open"])
    ws.save()
    events = ws.store.read_events(0)
    kinds = {e["type"] for e in events}
    assert {"target_added", "fact_added", "run"} <= kinds
    # events carry a useful payload
    run_ev = next(e for e in events if e["type"] == "run")
    assert run_ev["detail"]["tool"] == "nmap"
    # a fresh save with nothing new emits no events
    before = ws.store.latest_event_id()
    Workspace(tmp_path).load().save()
    assert ws.store.latest_event_id() == before


def test_legacy_json_migration(tmp_path):
    obol = tmp_path / ".obol"
    obol.mkdir()
    legacy = {
        "name": "Legacy Eng", "created_at": 1.0, "target": "10.0.0.1",
        "targets": [{"host": "10.0.0.1", "label": "OLD"}],
        "scope": ["10.0.0.1"],
        "facts": [{"kind": "host.up", "scope": "host:10.0.0.1", "value": {},
                   "state": "supported", "source": "old nmap"}],
        "runs": [{"id": "legacy1", "tool": "nmap", "command": "x", "produced": [], "at": 1.0}],
    }
    (obol / "state.json").write_text(json.dumps(legacy))
    assert has_state(tmp_path)

    ws = Workspace(tmp_path).load()          # reads legacy JSON in memory
    assert ws.name == "Legacy Eng" and ws.facts.has("host.up")
    ws.save()                                 # migrates to SQLite
    assert (obol / STATE_DB).exists()

    migrated = Workspace(tmp_path).load()
    assert migrated.name == "Legacy Eng"
    assert migrated.facts.has("host.up")
    assert len(migrated.runs) == 1
