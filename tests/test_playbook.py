"""Tests for playbooks — named, ordered sequences of pack actions.

These lock in the properties that keep a playbook honest: it is data (not code),
every step resolves to a real pack action (so packs and playbooks cannot silently
drift apart), the noisy steps are approval-gated, and the plan renders the same
scoped, templated commands the shared runner would build.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from obol.board import render_step_command
from obol.pack import load_pack
from obol.playbook import list_playbooks, load_playbook, resolve_step, resolve_steps
from obol.workspace import Workspace


def test_ad_recon_playbook_is_available():
    names = {p.name for p in list_playbooks()}
    assert "ad-recon" in names


def test_every_step_resolves_to_a_real_pack_action():
    """The key regression guard: a step id typo or a pack rename fails loudly."""
    pack = load_pack()
    playbooks = list_playbooks()
    assert playbooks, "no playbooks shipped"
    for pb in playbooks:
        assert pb.steps, f"{pb.name} has no steps"
        for step in pb.steps:
            action = resolve_step(step, pack)  # raises KeyError on drift
            assert action.id == step.action_id


def test_ad_recon_is_the_documented_recon_sequence():
    pb = load_playbook("ad-recon")
    assert [s.action_id for s in pb.steps] == [
        "nmap-fast-open-ports",
        "nmap-version-scripts",
        "ad-dc-identify",
        "ad-anon-ldap-enum",
        "ad-user-enum",
    ]


def test_noisy_step_is_approval_gated_and_quiet_steps_are_not():
    pb = load_playbook("ad-recon")
    rid = next(s for s in pb.steps if s.action_id == "ad-user-enum")
    assert rid.require_approval is True
    nmap = next(s for s in pb.steps if s.action_id == "nmap-fast-open-ports")
    assert nmap.require_approval is False


def test_plan_renders_scoped_targeted_commands():
    ws = Workspace(Path("/tmp/obol-pb-ws"))
    ws.target = "10.10.10.10"
    pb = load_playbook("ad-recon")
    step, action = resolve_steps(pb, load_pack())[0]
    cmd = render_step_command(step, action, ws)
    # target substituted so the runner's scope check accepts it; no dangling token
    assert "10.10.10.10" in cmd
    assert "{{target}}" not in cmd


def test_later_step_keeps_unfilled_token_until_earlier_evidence_exists():
    """The targeted nmap step depends on ports from step 1; the token stays visible
    (and the runner would refuse it) until those facts exist."""
    ws = Workspace(Path("/tmp/obol-pb-ws2"))
    ws.target = "10.10.10.10"
    pb = load_playbook("ad-recon")
    step, action = resolve_steps(pb, load_pack())[1]  # nmap-version-scripts
    cmd = render_step_command(step, action, ws)
    assert "{{nmap_ports}}" in cmd


def test_step_command_variant_is_one_based_and_valid():
    pb = load_playbook("ad-recon")
    pack = load_pack()
    for step in pb.steps:
        assert step.cmd >= 1
        action = resolve_step(step, pack)
        assert step.cmd <= len(action.commands or [1])
