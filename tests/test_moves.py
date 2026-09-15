"""The unified move frontier (cruise-control pillar I, docs/ROADMAP.md).

`moves.frontier_moves` must merge the packs' live actions with the built-primitive
offers (login/enum/exploit/tunnel) into one fact-gated, phase-ranked list — reusing
each layer's existing eligibility verbatim (never a second planner), staying
proof-bound (an escalate/pivot move only once a foothold is proven), and ranking by
the same phase/frontier model the planner already uses.
"""
from obol import library, moves
from obol.facts import Fact
from obol.seed import seed_forest

HOST = "10.10.10.20"


def _ws(tmp_path, host=HOST):
    library.set_base(tmp_path)
    library.engagements_dir().mkdir(parents=True, exist_ok=True)
    ws = library.create_engagement("E")
    ws.add_target(host)
    ws.target = host
    return ws


def _by_id(ms):
    return {m.id: m for m in ms}


# ── pack actions are moves ────────────────────────────────────────────────────
def test_pack_actions_surface_as_ready_dispatchable_moves(tmp_path):
    ws = _ws(tmp_path, "10.10.10.161")
    seed_forest(ws)
    ws.save()
    ms = moves.frontier_moves(ws, "10.10.10.161")
    actions = [m for m in ms if m.kind == "action"]
    assert actions, "seeded Forest should unlock pack-action moves"
    # a pack action is always 'ready' (its prereq facts are met) and stably addressable
    assert all(m.ready for m in actions)
    assert all(m.id and m.detail.get("action_id") == m.id for m in actions)
    # every move carries a known phase from the shared taxonomy
    from obol.phases import PHASES
    assert all(m.phase in PHASES for m in ms)


# ── a login becomes a first-class move ────────────────────────────────────────
def test_login_is_a_ready_move_with_a_credential(tmp_path):
    ws = _ws(tmp_path)
    ws.facts.add(Fact("winrm.reachable", f"host:{HOST}", {"tool": "nxc"}, source="x"))
    ws.facts.add(Fact("credential.available", f"host:{HOST}",
                      {"user": "svc", "password": "s3rvice"}, source="crack"))
    ws.save()
    m = _by_id(moves.frontier_moves(ws, HOST)).get("login:winrm")
    assert m is not None and m.kind == "login"
    assert m.ready and m.phase == "access"
    assert m.detail.get("user") == "svc"


def test_login_offered_but_not_ready_without_a_credential(tmp_path):
    ws = _ws(tmp_path)
    ws.facts.add(Fact("winrm.reachable", f"host:{HOST}", {"tool": "nxc"}, source="x"))
    ws.save()
    m = _by_id(moves.frontier_moves(ws, HOST)).get("login:winrm")
    assert m is not None and not m.ready
    assert m.reason  # an actionable reason (the missing credential), not blocked-language


def test_proven_login_is_not_offered_as_a_next_move(tmp_path):
    ws = _ws(tmp_path)
    ws.facts.add(Fact("winrm.reachable", f"host:{HOST}", {"tool": "nxc"}, source="x"))
    ws.facts.add(Fact("credential.available", f"host:{HOST}",
                      {"user": "svc", "password": "s3rvice"}, source="crack"))
    ws.add_session(host=HOST, kind="winrm", user="svc", os="windows", status="active")
    ws.save()
    assert "login:winrm" not in _by_id(moves.frontier_moves(ws, HOST))


# ── escalate/pivot moves are gated on a proven foothold ───────────────────────
def test_escalate_moves_are_absent_until_a_foothold_is_proven(tmp_path):
    ws = _ws(tmp_path)
    ws.facts.add(Fact("port:22", f"host:{HOST}", {"port": 22, "service": "ssh"}, source="nmap"))
    ws.save()
    kinds = {m.kind for m in moves.frontier_moves(ws, HOST)}
    assert "enum" not in kinds and "exploit" not in kinds and "tunnel" not in kinds


def test_enum_move_appears_once_a_linux_foothold_and_credential_exist(tmp_path):
    ws = _ws(tmp_path)
    ws.facts.add(Fact("foothold.linux", f"host:{HOST}", {"user": "www-data"}, source="shell"))
    ws.facts.add(Fact("credential.available", f"host:{HOST}",
                      {"user": "bob", "password": "pw"}, source="loot"))
    ws.save()
    ms = _by_id(moves.frontier_moves(ws, HOST))
    enum = [m for m in ms.values() if m.kind == "enum"]
    assert enum, "a proven Linux foothold + credential should offer enum run-and-rank"
    assert all(m.phase == "escalate" for m in enum)
    assert any(m.ready for m in enum)


# ── ranking: on-flow before premature, by the shared frontier model ───────────
def test_premature_move_ranks_below_on_flow_actions(tmp_path):
    """A login (access phase) offered mid-enumeration is past the frontier, so it
    sorts below the on-flow pack actions — the same frontier split `next_actions` uses."""
    ws = _ws(tmp_path, "10.10.10.161")
    seed_forest(ws)  # frontier sits around enum/creds
    ws.facts.add(Fact("winrm.reachable", "host:10.10.10.161", {"tool": "nxc"}, source="x"))
    ws.facts.add(Fact("credential.available", "host:10.10.10.161",
                      {"user": "svc", "password": "s3rvice"}, source="crack"))
    ws.save()
    ms = moves.frontier_moves(ws, "10.10.10.161")
    ids = [m.id for m in ms]
    login_idx = ids.index("login:winrm")
    first_action_idx = next(i for i, m in enumerate(ms) if m.kind == "action")
    assert first_action_idx < login_idx


def test_no_host_returns_pack_actions_only(tmp_path):
    """With no target resolvable, the frontier is the engagement fact view and only
    pack actions (no per-host primitive) are enumerated — no crash."""
    ws = _ws(tmp_path)
    ws.target = ""
    ws.save()
    ms = moves.frontier_moves(ws, "")
    assert all(m.kind == "action" for m in ms)
