"""The engagement phase/flow ranking model (ROADMAP item 2).

These lock in that `next_actions` ranks by the shared phase model relative to the
target's frontier, not by a bare scalar priority — so recon/enum sort ahead of a
premature high-value branch, while priority still orders the on-flow band (a slow,
deliberately low-priority recon step must not leapfrog the real next move).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from obol.facts import Fact, FactSet
from obol.pack import Action, load_packs, next_actions
from obol.phases import (
    frontier_index,
    phase_of_action,
    phase_of_kind,
    prematurity,
    target_phase,
)


def test_phase_of_action_derives_from_produces():
    recon = Action(id="r", title="r", produces=["scan.nmap.quick"])
    creds = Action(id="c", title="c", produces=["hash.asrep", "credential.candidate"])
    loot = Action(id="l", title="l", produces=["hash.ntlm", "loot.ntds"])  # latest wins
    assert phase_of_action(recon) == "recon"
    assert phase_of_action(creds) == "creds"
    assert phase_of_action(loot) == "loot"


def test_phase_of_action_falls_back_to_prerequisites_then_recon():
    from_reqs = Action(id="x", title="x", requires_all=["access.admin"])  # no produces
    assert phase_of_action(from_reqs) == "access"
    empty = Action(id="e", title="e")
    assert phase_of_action(empty) == "recon"


def test_explicit_phase_overrides_the_derivation():
    """Methodology data can correct a misplaced card without any planner branching."""
    a = Action(id="bh", title="bh", produces=["ad.graph.collected"], phase="enum")
    assert phase_of_action(a) == "enum"          # override, not the derived 'escalate'
    ignored = Action(id="i", title="i", produces=["loot.ntds"], phase="not-a-phase")
    assert phase_of_action(ignored) == "loot"    # bogus override ignored, derivation used


def test_frontier_is_reached_phase_plus_one_capped():
    bare = FactSet([Fact("target.configured", "host:t", {})])
    assert target_phase(bare) == "recon"
    assert frontier_index(bare) == 1             # pushing into enum
    endgame = FactSet([Fact("loot.ntds", "host:t", {})])
    assert target_phase(endgame) == "loot"
    assert frontier_index(endgame) == 5          # capped at the last phase, not 6


def _synthetic_pack():
    # One eligible action per phase, all gated only on a live host so all go live at once.
    return [
        Action(id="recon-hi", title="recon-hi", requires_all=["host.up"], produces=["scan.nmap.udp"], priority=90),
        Action(id="enum-lo", title="enum-lo", requires_all=["host.up"], produces=["ad.user_list"], priority=20),
        Action(id="loot-hi", title="loot-hi", requires_all=["host.up"], produces=["loot.ntds"], priority=99),
    ]


def test_premature_high_value_branch_is_demoted_below_on_flow():
    """The core fix: a high-priority loot action eligible during recon/enum sorts
    BELOW the on-flow recon/enum moves, even though its priority is highest."""
    facts = FactSet([Fact("host.up", "host:t", {})])          # frontier = enum
    ids = [a.id for a in next_actions(facts, _synthetic_pack())]
    assert ids == ["recon-hi", "enum-lo", "loot-hi"]
    assert prematurity(_synthetic_pack()[2], facts) > 0        # loot is ahead of frontier


def test_priority_still_orders_the_on_flow_band():
    """Within the on-flow band a higher-priority action wins — a low-priority recon
    step (a slow UDP sweep) must not leapfrog a higher-priority enum move."""
    pack = [
        Action(id="recon-slow", title="recon-slow", requires_all=["host.up"], produces=["scan.nmap.udp"], priority=10),
        Action(id="enum-primary", title="enum-primary", requires_all=["host.up"], produces=["ad.dc_candidate"], priority=95),
    ]
    facts = FactSet([Fact("host.up", "host:t", {})])          # frontier = enum -> both on-flow
    assert prematurity(pack[0], facts) == 0 and prematurity(pack[1], facts) == 0
    ids = [a.id for a in next_actions(facts, pack)]
    assert ids == ["enum-primary", "recon-slow"]             # priority orders equals


def test_frontier_is_context_sensitive_same_action_reranks():
    """The same escalate action is premature before a foothold and on-flow after one."""
    escalate = Action(id="esc", title="esc", requires_all=["host.up"], produces=["ad.control_paths"], priority=50)
    enum = Action(id="enum", title="enum", requires_all=["host.up"], produces=["ad.user_list"], priority=40)
    pack = [escalate, enum]

    early = FactSet([Fact("host.up", "host:t", {})])                 # frontier = enum
    early_ids = [a.id for a in next_actions(early, pack)]
    assert early_ids == ["enum", "esc"]                             # escalate demoted (premature)

    footed = FactSet([Fact("host.up", "host:t", {}), Fact("foothold.windows", "host:t", {})])
    assert phase_of_kind("foothold.windows") == "access"            # frontier = escalate
    footed_ids = [a.id for a in next_actions(footed, pack)]
    assert footed_ids == ["esc", "enum"]                           # now on-flow, priority wins


def test_real_pack_creds_outrank_premature_escalate():
    """On the real packs: with a user list + a candidate credential but no foothold yet
    (frontier = access), the quiet creds move (AS-REP roast, priority 80) outranks the
    higher-priority BloodHound collection (escalate, priority 84) that a bare priority
    sort surfaced first. Both are live; the phase model reorders them."""
    facts = FactSet([
        Fact("ad.user_list", "domain:htb.local", {"users": ["a"]}),
        Fact("ad.dc_candidate", "host:t", {}),
        Fact("ad.domain_known", "domain:htb.local", {}),
        Fact("kerberos.reachable", "host:t", {}),
        Fact("credential.available", "domain:htb.local", {"user": "a", "password": "x"}),
    ])
    assert target_phase(facts) == "creds"        # no access fact yet -> escalate is premature
    pack = load_packs()
    ids = [a.id for a in next_actions(facts, pack)]
    assert "asrep-roast" in ids and "bloodhound-collect" in ids
    by = {a.id: a for a in pack}
    assert by["bloodhound-collect"].priority > by["asrep-roast"].priority  # priority sort disagreed
    assert ids.index("asrep-roast") < ids.index("bloodhound-collect")
