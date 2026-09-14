"""Tool inventory: the catalogue scan, install hints, path overrides, and the
runner resolving a tool O.B.O.L was pointed at."""
import os

import pytest

from obol import library, tools


@pytest.fixture(autouse=True)
def temp_base(tmp_path):
    library.set_base(tmp_path)
    yield
    library.set_base(None)


def test_scan_shape_and_counts():
    s = tools.scan()
    assert s["total"] == len(tools.REGISTRY) and 0 <= s["found"] <= s["total"]
    keys = {t["key"] for g in s["groups"] for t in g["tools"]}
    assert {"nmap", "netexec", "impacket"} <= keys
    # every catalogue tool carries the fields the page needs
    for g in s["groups"]:
        for t in g["tools"]:
            assert set(t) >= {"key", "label", "found", "path", "install_cmd", "actions", "manual", "bins"}


def test_install_command_apt_pipx_and_manual():
    assert tools.install_command("nmap") == "sudo apt-get install -y nmap"
    assert tools.install_command("certipy") == "pipx install certipy-ad"
    assert tools.install_command("rubeus") == ""       # manual/Windows — nothing to install


def test_actions_are_mapped_to_tools():
    s = tools.scan()
    flat = {t["key"]: t for g in s["groups"] for t in g["tools"]}
    assert flat["nmap"]["actions"], "nmap should back some pack actions"
    assert len(flat["impacket"]["actions"]) >= 5, "impacket suite backs many actions"


def test_add_override_and_resolve(tmp_path):
    # point O.B.O.L at an existing file as if it were the tool binary
    d = tools.add_override("gobuster", "/bin/sh")
    assert d["found"] and d["path"] == "/bin/sh" and d["source"] == "added"
    # a fresh scan now counts it, and the runner can resolve it off-PATH
    assert any(t["key"] == "gobuster" and t["found"]
               for g in tools.scan()["groups"] for t in g["tools"])
    if not __import__("shutil").which("gobuster"):
        assert tools.resolve_binary("gobuster") == "/bin/sh"


def test_add_override_rejects_missing_file_and_unknown_tool():
    with pytest.raises(FileNotFoundError):
        tools.add_override("nmap", "/no/such/file")
    with pytest.raises(KeyError):
        tools.add_override("not-a-tool", "/bin/sh")


# ── web endpoints ─────────────────────────────────────────────────────────────
fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402
from obol.webapp.server import create_app  # noqa: E402

H = {"X-Obol-Token": "t"}


def test_tools_endpoints(tmp_path):
    cx = TestClient(create_app(tmp_path, token="t"))
    s = cx.get("/api/tools", headers=H).json()
    assert s["total"] == len(tools.REGISTRY)
    # add-path endpoint validates
    assert cx.post("/api/tools/add", json={"tool": "nmap", "path": "/no/file"}, headers=H).status_code == 400
    assert cx.post("/api/tools/add", json={"tool": "zzz", "path": "/bin/sh"}, headers=H).status_code == 404
    r = cx.post("/api/tools/add", json={"tool": "nmap", "path": "/bin/sh"}, headers=H)
    assert r.status_code == 200 and r.json()["found"] is True
    # install endpoint rejects unknown tools
    assert cx.post("/api/tools/install", json={"tool": "zzz"}, headers=H).status_code == 404
