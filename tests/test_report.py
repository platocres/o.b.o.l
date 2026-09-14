from pathlib import Path

from obol.facts import Fact
from obol.report import build_report, redact_command, write_report
from obol.workspace import Workspace


def test_report_redacts_secrets_and_cites_evidence(tmp_path: Path):
    ws = Workspace(tmp_path)
    ws.name = "forest"
    ws.target = "10.10.10.161"
    ws.scope.append("10.10.10.161")
    ws.facts.add(Fact("host.up", "host:10.10.10.161", {"target": ws.target}, source="nmap -Pn 10.10.10.161"))
    ws.facts.add(
        Fact(
            "port:445",
            "host:10.10.10.161",
            {"protocol": "tcp", "service": "microsoft-ds"},
            source="nmap -p- 10.10.10.161",
        )
    )
    ws.facts.add(
        Fact(
            "credential.plaintext",
            "domain:corp.local",
            {"user": "svc-backup", "password": "Spring2026!"},
            source="hashcat --show",
        )
    )
    ws.facts.add(
        Fact(
            "access.admin",
            "host:10.10.10.161",
            {"user": "svc-backup"},
            source="nxc smb 10.10.10.161 -u svc-backup -p 'Spring2026!'",
        )
    )
    ws.record_run(
        "nxc",
        "nxc smb 10.10.10.161 -u svc-backup -p 'Spring2026!'",
        ["access.admin"],
        returncode=0,
        stdout=".obol/runs/1.stdout",
        stderr=".obol/runs/1.stderr",
    )

    text = build_report(ws)

    assert "OSCP-Style Evidence Report" in text
    assert "10.10.10.161" in text
    assert "445/tcp microsoft-ds" in text
    assert "Spring2026!" not in text
    assert "<redacted>" in text
    assert "Raw stdout" in text
    assert "```mermaid" in text


def test_report_can_include_secrets_for_private_notes(tmp_path: Path):
    ws = Workspace(tmp_path)
    ws.target = "10.10.10.161"
    ws.facts.add(
        Fact(
            "credential.available",
            "domain:corp.local",
            {"user": "svc", "password": "Winter2026!"},
            source="john --show",
        )
    )

    assert "Winter2026!" in build_report(ws, include_secrets=True)


def test_write_report_defaults_to_workspace_root(tmp_path: Path):
    ws = Workspace(tmp_path)

    path = write_report(ws)

    assert path == tmp_path / "report.md"
    assert path.exists()


def test_redact_command_is_tool_aware():
    assert redact_command("nmap -Pn -p 80,443 10.10.10.10") == "nmap -Pn -p 80,443 10.10.10.10"
    assert (
        redact_command("nxc smb 10.10.10.10 -u bob -p 'Secret123!'")
        == "nxc smb 10.10.10.10 -u bob -p <redacted>"
    )
