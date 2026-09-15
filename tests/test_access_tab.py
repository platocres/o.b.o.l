"""The Access/Pivot tab's aggregate endpoint (§8): one call returns the per-target
foothold, sessions, staged material, listeners, eligible enum tools, and applicable
exploits, so the SPA tab renders from a single fetch."""
import pytest

from obol import library, provision
from obol.facts import Fact

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402
from obol.webapp.server import create_app  # noqa: E402

H = {"X-Obol-Token": "t"}


def _win_foothold(tmp_path, host="10.10.10.7"):
    library.set_base(tmp_path)
    library.engagements_dir().mkdir(parents=True, exist_ok=True)
    ws = library.create_engagement("E")
    ws.add_target(host)
    ws.target = host
    ws.facts.add(Fact("foothold.windows", f"host:{host}", {"tool": "winrm"}, source="login"))
    ws.facts.add(Fact("credential.available", f"host:{host}", {"user": "svc", "password": "pw"}, source="x"))
    ws.facts.add(Fact("privesc.windows_privilege", f"host:{host}",
                      {"privileges": ["SeImpersonatePrivilege"], "state": "Enabled"}, source="winpeas"))
    ws.save()
    library.set_active(ws.root.name)
    return ws, host


def test_access_endpoint_aggregates_state(tmp_path):
    ws, host = _win_foothold(tmp_path)
    cx = TestClient(create_app(tmp_path, token="t"))
    d = cx.get("/api/access", params={"host": host}, headers=H).json()
    assert d["foothold_os"] == "windows"
    assert d["sessions"] == [] and d["staged"] == []
    assert any(e["key"] == "godpotato" for e in d["exploits"])   # gated on SeImpersonate
    assert any(t["key"] == "winpeas" for t in d["enum_tools"])
    assert set(d["cache_summary"]) == {"present", "total"}
    assert d["cache_summary"]["total"] == len(provision.REGISTRY)


def test_access_endpoint_no_foothold(tmp_path):
    library.set_base(tmp_path)
    library.engagements_dir().mkdir(parents=True, exist_ok=True)
    ws = library.create_engagement("E")
    ws.add_target("10.10.10.9")
    ws.target = "10.10.10.9"
    ws.save()
    library.set_active(ws.root.name)
    cx = TestClient(create_app(tmp_path, token="t"))
    d = cx.get("/api/access", params={"host": "10.10.10.9"}, headers=H).json()
    assert d["foothold_os"] == "" and d["exploits"] == []
