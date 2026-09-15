"""Material cache/provisioner (§8 spine): the catalogue scan, one-click download
with sha256 verification, local overrides, and the web endpoints. Downloads use an
injected fetcher so tests never touch the network."""
import hashlib
from pathlib import Path

import pytest

from obol import library, provision


@pytest.fixture(autouse=True)
def temp_base(tmp_path):
    library.set_base(tmp_path)
    yield
    library.set_base(None)


def _fake_fetcher(content: bytes):
    def fetch(url, dest, timeout=0):
        dest.parent.mkdir(parents=True, exist_ok=True)
        Path(dest).write_bytes(content)
        return len(content)
    return fetch


def test_scan_shape_and_counts():
    s = provision.scan()
    assert s["total"] == len(provision.REGISTRY) and 0 <= s["present"] <= s["total"]
    keys = {m["key"] for g in s["groups"] for m in g["materials"]}
    assert {"linpeas", "winpeas", "godpotato", "chisel"} <= keys
    for g in s["groups"]:
        for m in g["materials"]:
            assert set(m) >= {"key", "label", "os", "kind", "status", "purpose"}


def test_download_records_hash_and_marks_present():
    content = b"#!/bin/sh\necho linpeas\n"
    res = provision.download("linpeas", fetcher=_fake_fetcher(content))
    assert res["ok"] and res["sha256"] == hashlib.sha256(content).hexdigest()
    # unpinned entry -> recorded but not "verified"
    assert res["verified"] is False
    assert Path(res["path"]).read_bytes() == content
    # a fresh scan now counts it as present/cached
    flat = {m["key"]: m for g in provision.scan()["groups"] for m in g["materials"]}
    assert flat["linpeas"]["status"] == "cached"
    assert provision.resolve_path("linpeas") == res["path"]


def test_pinned_digest_mismatch_is_rejected(monkeypatch):
    # pin a digest that won't match what the fetcher writes
    m = next(x for x in provision.REGISTRY if x.key == "linpeas")
    monkeypatch.setattr(m, "sha256", "0" * 64)
    res = provision.download("linpeas", fetcher=_fake_fetcher(b"payload"))
    assert not res["ok"] and "mismatch" in res["error"]
    # nothing cached, file cleaned up
    assert provision.status(m)["status"] == "missing"
    assert not (provision.cache_dir() / m.dest_name()).exists()


def test_pinned_digest_match_marks_verified(monkeypatch):
    content = b"trusted-binary"
    digest = hashlib.sha256(content).hexdigest()
    m = next(x for x in provision.REGISTRY if x.key == "godpotato")
    monkeypatch.setattr(m, "sha256", digest)
    res = provision.download("godpotato", fetcher=_fake_fetcher(content))
    assert res["ok"] and res["verified"] is True and res["sha256"] == digest


def test_ensure_downloads_then_short_circuits():
    calls = {"n": 0}

    def counting_fetcher(url, dest, timeout=0):
        calls["n"] += 1
        Path(dest).write_bytes(b"x")
        return 1

    first = provision.ensure("linpeas", fetcher=counting_fetcher)
    assert first["ok"] and first["already"] is False and calls["n"] == 1
    second = provision.ensure("linpeas", fetcher=counting_fetcher)
    assert second["ok"] and second["already"] is True and calls["n"] == 1  # not re-fetched


def test_use_local_registers_operator_file(tmp_path):
    supplied = tmp_path / "Rubeus.exe"
    supplied.write_bytes(b"MZ...")
    res = provision.use_local("rubeus", str(supplied))
    assert res["ok"] and res["status"] == "cached" and res["source"] == "added"
    # removing an operator-supplied file de-registers but leaves it on disk
    provision.remove("rubeus")
    assert supplied.exists()
    assert provision.status(next(m for m in provision.REGISTRY if m.key == "rubeus"))["status"] == "missing"


def test_use_local_rejects_missing_file_and_unknown_key():
    with pytest.raises(FileNotFoundError):
        provision.use_local("rubeus", "/no/such/file")
    with pytest.raises(KeyError):
        provision.use_local("not-a-material", "/bin/sh")


def test_manual_material_without_url_is_not_downloadable():
    res = provision.download("nc64", fetcher=_fake_fetcher(b"x"))
    assert not res["ok"] and "supply a local file" in res["error"]


def test_download_removes_cached_copy(tmp_path):
    provision.download("linpeas", fetcher=_fake_fetcher(b"data"))
    cached = provision.cache_dir() / "linpeas.sh"
    assert cached.exists()
    provision.remove("linpeas")
    assert not cached.exists()


# ── web endpoints ──────────────────────────────────────────────────────────────
fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402
from obol.webapp.server import create_app  # noqa: E402

H = {"X-Obol-Token": "t"}


def test_cache_endpoints(tmp_path, monkeypatch):
    library.set_base(tmp_path)
    cx = TestClient(create_app(tmp_path, token="t"))
    s = cx.get("/api/cache", headers=H).json()
    assert s["total"] == len(provision.REGISTRY)
    # get with an injected fetcher
    monkeypatch.setattr(provision, "_http_fetch", _fake_fetcher(b"payload"))
    r = cx.post("/api/cache/get", json={"key": "linpeas"}, headers=H)
    assert r.status_code == 200 and r.json()["ok"] is True
    # unknown material -> 404
    assert cx.post("/api/cache/get", json={"key": "zzz"}, headers=H).status_code == 404
    # use rejects a missing file
    assert cx.post("/api/cache/use", json={"key": "rubeus", "path": "/no/file"}, headers=H).status_code == 400
    # rm succeeds
    assert cx.post("/api/cache/rm", json={"key": "linpeas"}, headers=H).status_code == 200
