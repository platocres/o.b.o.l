"""Getting-on-the-box moves (ROADMAP §15b): a hand-found credential unlocks the frontier,
a reverse-shell listener move, and the initial engagement discovery sweep so cruise can
start from a bare scope range.
"""
from obol import cruise, dispatch, ingest, library, moves, sessions
from obol.facts import Fact
from obol.runner import RunResult


def _ws(tmp_path, host="10.10.10.80"):
    library.set_base(tmp_path)
    library.engagements_dir().mkdir(parents=True, exist_ok=True)
    ws = library.create_engagement("E")
    ws.add_target(host)
    ws.target = host
    return ws


# ── obol cred add ─────────────────────────────────────────────────────────────
def test_hand_found_credential_unlocks_login_and_is_usable(tmp_path):
    ws = _ws(tmp_path)
    ws.facts.add(Fact("winrm.reachable", "host:10.10.10.80", {"tool": "nxc"}, source="x"))
    ws.save()
    # no login offered yet — no credential
    assert not any(m.id == "login:winrm" and m.ready
                   for m in moves.frontier_moves(ws, "10.10.10.80"))
    # add an admin password by hand
    res = ingest.add_credential(ws, user="Administrator", password="Winter2024!",
                                admin=True, target="10.10.10.80", note="dumped by hand")
    assert res["added"]
    # obol can now use it — the session layer picks it up
    cred = sessions.password_credential(ws, "10.10.10.80")
    assert cred and cred["user"] == "Administrator" and cred["password"] == "Winter2024!"
    # and the winrm login is now offered and ready
    assert any(m.id == "login:winrm" and m.ready
               for m in moves.frontier_moves(ws, "10.10.10.80"))
    # lineage stays honest — operator-attested
    fact = next(f for f in ws.facts.facts if f.kind == "credential.available")
    assert fact.source.startswith("operator-attested:")


def test_cred_add_accepts_an_nt_hash_for_pth(tmp_path):
    ws = _ws(tmp_path)
    ingest.add_credential(ws, user="admin", nthash="aad3b435b51404eeaad3b435b51404ee:"
                          "31d6cfe0d16ae931b73c59d7e0c089c0", target="10.10.10.80")
    cred = sessions.hash_credential(ws, "10.10.10.80")
    assert cred and cred["user"] == "admin" and "nthash" in cred


def test_cred_add_requires_a_secret(tmp_path):
    ws = _ws(tmp_path)
    import pytest
    with pytest.raises(ValueError):
        ingest.add_credential(ws, user="x")   # no password or hash


# ── listener move (local, catch a reverse shell) ──────────────────────────────
def test_listener_move_offered_on_a_code_exec_path(tmp_path):
    ws = _ws(tmp_path)
    # a confirmed web RCE but no session → offer a listener to catch a shell
    ws.facts.add(Fact("web.cmdi_confirmed", "host:10.10.10.80", {"method": "cmdi"}, source="curl"))
    ws.save()
    listeners = [m for m in moves.frontier_moves(ws, "10.10.10.80") if m.kind == "listener"]
    assert listeners and listeners[0].id == "listener:start"
    # it is a LOCAL move — safe to run unattended (obol's own box), even on the exam
    ws.set_profile({"platform": "oscp"})
    lm = next(m for m in moves.frontier_moves(ws, "10.10.10.80") if m.kind == "listener")
    assert lm.decision == "auto"


def test_dispatch_listener_move_records_a_listener(tmp_path):
    ws = _ws(tmp_path)
    ws.facts.add(Fact("web.cmdi_confirmed", "host:10.10.10.80", {"method": "cmdi"}, source="curl"))
    ws.save()
    res = dispatch.run_move(ws, "listener:start", host="10.10.10.80", params={"port": 4444})
    assert res["ok"] and res["posture"] == "handoff" and res["command"]
    assert ws.listeners and ws.listeners[-1]["port"] == 4444


# ── initial engagement discovery sweep in cruise --all ────────────────────────
def test_engagement_cruise_sweeps_scope_ranges_first(tmp_path, monkeypatch):
    """`obol cruise --all --sweep` sweeps an authorized scope range to populate targets,
    so cruise can start from a bare /24."""
    ws = _ws(tmp_path, "10.10.10.80")
    ws.add_scope("10.10.20.0/24")
    ws.save()
    from obol import discovery

    def fake_sweep(ws, range_, **kw):
        ws.add_target("10.10.20.7"); ws.save()
        return {"range": range_, "created": ["10.10.20.7"], "hosts": ["10.10.20.7"]}

    monkeypatch.setattr(discovery, "run_sweep", fake_sweep)
    # a benign runner so per-host cruise doesn't blow up
    monkeypatch.setattr("obol.service.run_command",
                        lambda ws, command, tool, **kw: RunResult(command, command.split(), 0, "", "",
                                                                  ws.runs_dir / "o", ws.runs_dir / "e", 1.0, 1))
    eng = cruise.cruise_engagement(ws, auto_kinds=frozenset({"sweep"}), max_steps=3)
    assert any(d["range"] == "10.10.20.0/24" for d in eng.discoveries)
    assert "10.10.20.7" in [h["host"] for h in eng.hosts]  # the discovered host got cruised


def test_engagement_cruise_holds_scope_sweep_for_approval_by_default(tmp_path):
    ws = _ws(tmp_path, "10.10.10.80")
    ws.add_scope("10.10.20.0/24")
    ws.set_profile({"platform": "oscp"})   # exam → ask before sweeping a segment
    ws.save()
    eng = cruise.cruise_engagement(ws, max_steps=1)   # no --sweep, exam mode
    assert "10.10.20.0/24" in eng.pending_sweeps and not eng.discoveries


# ── followed sessions (§15c) ──────────────────────────────────────────────────
def test_parse_transcript_earns_operator_session_facts(tmp_path):
    from obol import follow, ingest
    ws = _ws(tmp_path, "10.10.10.161")
    # a transcript with ANSI noise, as a real PTY log would have
    text = "\x1b[0;32m*Evil-WinRM*\x1b[0m PS C:\\Users\\svc> whoami\nhtb\\svc\n"
    added = follow.parse_transcript(ws, text, target="10.10.10.161", note="evil-winrm session")
    # obol recognizes the interactive session established a Windows foothold — from the
    # transcript, no copy-paste, and honestly lineage-tagged as operator-run.
    assert "foothold.windows" in added
    fact = next(f for f in ws.facts.facts if f.kind == "foothold.windows")
    assert fact.source.startswith("operator-session:")
    assert ingest.fact_origin(fact) == "operator-executed"   # classified as operator, not obol


def test_capture_screenshot_degrades_without_a_display(tmp_path, monkeypatch):
    from obol import follow
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    assert follow.capture_screenshot(tmp_path) == ""   # no display → no screenshot, no crash


def test_tail_penelope_logs_ingests_new_logs(tmp_path):
    from obol import follow
    ws = _ws(tmp_path, "10.10.10.161")
    logdir = tmp_path / "pen"; logdir.mkdir()
    (logdir / "session_10.10.10.161.log").write_text("id\nuid=33(www-data) gid=33(www-data)\n"
                                                     "PORT   STATE SERVICE\n80/tcp open http\n")
    res = follow.tail_penelope_logs(ws, log_dir=str(logdir), target="10.10.10.161")
    assert res["ok"] and res["files"]
    # a second tail does not double-ingest (the log is marked seen)
    res2 = follow.tail_penelope_logs(ws, log_dir=str(logdir), target="10.10.10.161")
    assert not res2["files"]


# ── one-pass install (§15d) ───────────────────────────────────────────────────
def test_install_plan_batches_apt_and_lists_pipx(monkeypatch):
    from obol import tools
    fake_missing = [
        {"key": "a", "label": "A", "apt": "apkg", "pipx": "", "install": "apt-get install apkg"},
        {"key": "b", "label": "B", "apt": "bpkg", "pipx": "", "install": "apt-get install bpkg"},
        {"key": "c", "label": "C", "apt": "", "pipx": "cpkg", "install": "pipx install cpkg"},
    ]
    plan = tools.install_plan(fake_missing)
    # one batched apt line for all apt packages, sudo-prefixed
    apt_line = [c for c in plan["commands"] if c.startswith("sudo apt-get install")]
    assert apt_line and "apkg" in apt_line[0] and "bpkg" in apt_line[0]
    assert "pipx install cpkg" in plan["commands"]


def test_missing_tools_only_lists_installable_absent_tools(monkeypatch):
    from obol import tools
    # force everything "not found" so the installer set is the apt/pipx-hinted catalogue
    monkeypatch.setattr(tools, "detect", lambda t, ov=None: {"found": False, "path": "", "source": ""})
    miss = tools.missing_tools()
    assert miss and all(m["apt"] or m["pipx"] for m in miss)
