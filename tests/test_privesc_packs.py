import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from obol.facts import Fact, FactSet
from obol.pack import load_pack, load_packs, next_actions


def test_privesc_packs_load_and_merge_with_unique_ids():
    linux = load_pack("orange_linux_privesc_2025_03")
    windows = load_pack("orange_windows_privesc_2025_03")
    assert len(linux) == 12
    assert len(windows) == 10
    assert {"linux-enum", "sudo-abuse", "capabilities"} <= {a.id for a in linux}
    assert {"windows-enum", "seimpersonate", "alwaysinstallelevated"} <= {a.id for a in windows}

    merged = load_packs()
    ids = [a.id for a in merged]
    assert len(ids) == len(set(ids))
    assert len(merged) >= len(linux) + len(windows)


def test_privesc_stays_locked_until_a_matching_foothold_exists():
    bare = FactSet([Fact("target.configured", "host:target", {"target": "target"})])
    live = {a.id for a in next_actions(bare)}
    assert "linux-enum" not in live
    assert "windows-enum" not in live

    linux = FactSet([
        Fact("target.configured", "host:target", {"target": "target"}),
        Fact("host.os_family", "host:target", {"family": "linux"}),
        Fact("foothold.linux", "host:target", {"service": "ssh"}),
    ])
    live = {a.id for a in next_actions(linux)}
    assert "linux-enum" in live
    assert "windows-enum" not in live
    assert "sudo-abuse" not in live

    windows = FactSet([
        Fact("target.configured", "host:target", {"target": "target"}),
        Fact("host.os_family", "host:target", {"family": "windows"}),
        Fact("foothold.windows", "host:target", {"service": "winrm"}),
    ])
    live = {a.id for a in next_actions(windows)}
    assert "windows-enum" in live
    assert "linux-enum" not in live
    assert "seimpersonate" not in live


def test_privesc_lead_facts_unlock_specific_abuse_paths():
    linux = FactSet([
        Fact("host.os_family", "host:target", {"family": "linux"}),
        Fact("foothold.linux", "host:target", {"service": "ssh"}),
        Fact("privesc.sudo_rights", "host:target", {"entries": ["(root) NOPASSWD: /usr/bin/find"]}),
        Fact("privesc.capability", "host:target", {"entries": [{"path": "/usr/bin/python3"}]}),
    ])
    live = {a.id for a in next_actions(linux)}
    assert {"sudo-abuse", "capabilities"} <= live

    windows = FactSet([
        Fact("host.os_family", "host:target", {"family": "windows"}),
        Fact("foothold.windows", "host:target", {"service": "winrm"}),
        Fact("privesc.windows_privilege", "host:target", {"privileges": ["SeImpersonatePrivilege"]}),
        Fact("privesc.always_install_elevated", "host:target", {"hklm": True, "hkcu": True}),
    ])
    live = {a.id for a in next_actions(windows)}
    assert {"seimpersonate", "alwaysinstallelevated"} <= live


def test_privesc_actions_have_boundaries_and_os_tags():
    for pack_name, family in [
        ("orange_linux_privesc_2025_03", "linux"),
        ("orange_windows_privesc_2025_03", "windows"),
    ]:
        for action in load_pack(pack_name):
            assert action.proves, f"{action.id} missing proves"
            assert action.does_not_prove, f"{action.id} missing does_not_prove"
            assert action.os == [family]
