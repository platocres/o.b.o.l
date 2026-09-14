"""Command-line ergonomics: help, scope paste, and whole-scope scan."""
from pathlib import Path

import pytest

from obol import cli, library, quickstart
from obol.facts import Fact
from obol.workspace import Workspace


@pytest.fixture(autouse=True)
def isolated_library(tmp_path):
    library.set_base(tmp_path / "library")
    yield
    library.set_base(None)


def test_help_version_info_and_manual(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0
    assert "obol scan" in capsys.readouterr().out

    cli.main(["--version"])
    assert capsys.readouterr().out.strip().startswith("obol ")

    cli.main(["manual"])
    out = capsys.readouterr().out
    assert "obol scope paste" in out and "obol scan" in out

    cli.main(["--info"])
    assert "workspace:" in capsys.readouterr().out


def test_scope_paste_extracts_only_valid_ip_scope_entries(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cli.main(["init"])
    capsys.readouterr()

    cli.main([
        "scope", "paste",
        "targets:", "10.10.10.5,", "bad-host", "999.999.999.999",
        "https://10.10.10.6:8443/login", "10.10.10.0/24",
    ])

    out = capsys.readouterr().out
    assert "added scope: 10.10.10.5" in out
    assert "added scope: 10.10.10.6" in out
    assert "added scope: 10.10.10.0/24" in out
    ws = Workspace(tmp_path).load()
    assert ws.scope == ["10.10.10.5", "10.10.10.6", "10.10.10.0/24"]


def test_scope_add_multiple_and_remove(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cli.main(["init"])
    capsys.readouterr()

    cli.main(["scope", "add", "10.0.0.1", "10.0.0.0/24"])
    cli.main(["scope", "rm", "10.0.0.1"])

    out = capsys.readouterr().out
    assert "added scope: 10.0.0.1" in out
    assert "added scope: 10.0.0.0/24" in out
    assert "removed scope: 10.0.0.1" in out
    assert Workspace(tmp_path).load().scope == ["10.0.0.0/24"]


def test_scan_sweeps_every_scope_entry_and_quickstarts_targets(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cli.main(["init"])
    cli.main(["scope", "add", "10.0.0.0/24"])
    capsys.readouterr()

    swept = []
    quickstarted = []

    def fake_sweep(ws, entry, **kwargs):
        swept.append((entry, kwargs))
        if not kwargs.get("dry_run") and not ws.get_target("10.0.0.5"):
            ws.add_target("10.0.0.5", "DC01")
            ws.save()
            created = ["10.0.0.5"]
            existing = []
        else:
            created = []
            existing = ["10.0.0.5"]
        return {
            "range": entry,
            "command": f"nmap -sn {entry}",
            "dry_run": kwargs.get("dry_run", False),
            "hosts": ["10.0.0.5"],
            "created": created,
            "existing": existing,
        }

    def fake_quickstart(ws, host, **kwargs):
        quickstarted.append((host, kwargs))
        step = quickstart.QuickStartStep(
            "nmap-fast-open-ports",
            "Nmap Fast TCP Open-Port Discovery",
            "success",
            "nmap -Pn -p- 10.0.0.5",
            added=[Fact("host.up", f"host:{host}", {"target": host})],
        )
        if kwargs.get("on_step"):
            kwargs["on_step"](step)
        return quickstart.QuickStartResult(target=host, ran=[step])

    monkeypatch.setattr(cli.discovery, "run_sweep", fake_sweep)
    monkeypatch.setattr(cli.quickstart, "run_quickstart", fake_quickstart)

    cli.main(["scan"])

    out = capsys.readouterr().out
    assert swept == [("10.0.0.0/24", {"dry_run": False, "timeout": 600})]
    assert [host for host, _ in quickstarted] == ["10.0.0.5"]
    assert "scanning 1 scope entry" in out
    assert "Quick Start" in out


def test_scan_no_enumerate_skips_quickstart(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cli.main(["init"])
    cli.main(["scope", "add", "10.0.0.0/24"])

    monkeypatch.setattr(
        cli.discovery,
        "run_sweep",
        lambda ws, entry, **kwargs: {
            "range": entry, "command": f"nmap -sn {entry}", "dry_run": False,
            "hosts": [], "created": [], "existing": [],
        },
    )
    monkeypatch.setattr(cli.quickstart, "run_quickstart", lambda *args, **kwargs: pytest.fail("should not enumerate"))

    cli.main(["scan", "--no-enumerate"])
