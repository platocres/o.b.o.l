"""Move autonomy tiers (cruise stop-contract): how autonomous obol may be with a move.

Data-driven, conservative, and honest: recon/enum + Quick Start's safe baseline are
`auto`; everything past that boundary and the box-touching primitives default to
`approve`; a privesc exploit is `manual`. An explicit pack `autonomy` overrides the
derivation.
"""
from obol import autonomy, library, moves
from obol.facts import Fact
from obol.pack import Action, load_packs
from obol.quickstart import QUICKSTART_ACTION_IDS
from obol.seed import seed_forest


def _action(**kw):
    return Action(id=kw.pop("id", "a"), title=kw.pop("title", "A"), **kw)


# ── derivation ────────────────────────────────────────────────────────────────
def test_recon_and_enum_actions_are_auto():
    recon = _action(id="r", produces=["port:445"])          # recon
    enum = _action(id="e", produces=["ad.user_list"])       # enum
    assert autonomy.tier_of_action(recon) == "auto"
    assert autonomy.tier_of_action(enum) == "auto"


def test_creds_access_escalate_default_to_approve():
    creds = _action(id="c", produces=["credential.available"])  # creds
    access = _action(id="ac", produces=["foothold.windows"])    # access
    loot = _action(id="l", produces=["loot.ntds"])              # loot
    for a in (creds, access, loot):
        assert autonomy.tier_of_action(a) == "approve"


def test_quickstart_baseline_actions_are_auto():
    """Every id obol already auto-runs in Quick Start classifies as auto (the blessed
    safe-baseline boundary), even a later-phase one like nikto/gpp."""
    pack = {a.id: a for a in load_packs()}
    for aid in QUICKSTART_ACTION_IDS:
        a = pack.get(aid)
        if a is not None:
            assert autonomy.tier_of_action(a) == "auto", aid


def test_explicit_pack_autonomy_overrides_the_derivation():
    # a normally-auto enum action pinned to approve by pack data
    noisy = _action(id="n", produces=["ad.user_list"], autonomy="approve")
    assert autonomy.tier_of_action(noisy) == "approve"
    # and the reverse: a normally-approve action pinned to auto
    safe = _action(id="s", produces=["credential.available"], autonomy="auto")
    assert autonomy.tier_of_action(safe) == "auto"


def test_primitive_tiers_are_fixed_by_kind():
    assert autonomy.PRIMITIVE_TIER["enum"] == "approve"
    assert autonomy.PRIMITIVE_TIER["login"] == "approve"
    assert autonomy.PRIMITIVE_TIER["tunnel"] == "approve"
    assert autonomy.PRIMITIVE_TIER["exploit"] == "manual"


def test_needs_approval_predicate():
    assert not autonomy.needs_approval("auto")
    assert autonomy.needs_approval("approve")
    assert autonomy.needs_approval("manual")


# ── the frontier carries the tier ─────────────────────────────────────────────
def _ws(tmp_path, host):
    library.set_base(tmp_path)
    library.engagements_dir().mkdir(parents=True, exist_ok=True)
    ws = library.create_engagement("E")
    ws.add_target(host)
    ws.target = host
    return ws


def test_frontier_moves_tag_each_move_with_its_tier(tmp_path):
    ws = _ws(tmp_path, "10.10.10.161")
    seed_forest(ws)
    ws.facts.add(Fact("winrm.reachable", "host:10.10.10.161", {"tool": "nxc"}, source="x"))
    ws.facts.add(Fact("credential.available", "host:10.10.10.161",
                      {"user": "svc", "password": "s3rvice"}, source="crack"))
    ws.save()
    by_id = {m.id: m for m in moves.frontier_moves(ws, "10.10.10.161")}
    # every move carries a valid tier
    assert all(m.autonomy in autonomy.TIERS for m in by_id.values())
    # a login is approve-tier (box-touching)
    assert by_id["login:winrm"].autonomy == "approve"
    # an auto recon/enum pack action is present and auto
    assert any(m.kind == "action" and m.autonomy == "auto" for m in by_id.values())
