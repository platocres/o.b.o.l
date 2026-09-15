"""Fingerprint -> probable-exploit matcher (§15b). A version/service/OS/web fingerprint
matches a known exploit as a proof-bound CANDIDATE LEAD (never confirmed-vulnerable), and
the candidate flows through the same points a regular exploit does (a move, craft, cache).
"""
from obol import dispatch, library, moves, vulnmatch
from obol.facts import Fact


def _ws(tmp_path, host="10.10.10.90"):
    library.set_base(tmp_path)
    library.engagements_dir().mkdir(parents=True, exist_ok=True)
    ws = library.create_engagement("E")
    ws.add_target(host)
    ws.target = host
    return ws


def _port(ws, host, port, service, version=""):
    ws.facts.add(Fact(f"port:{port}", f"host:{host}",
                      {"port": port, "protocol": "tcp", "service": service, "version": version},
                      source="nmap -sV"))


# ── matching ──────────────────────────────────────────────────────────────────
def test_version_fingerprint_matches_a_known_exploit(tmp_path):
    ws = _ws(tmp_path)
    _port(ws, "10.10.10.90", 21, "ftp", "vsftpd 2.3.4")
    keys = {c["key"] for c in vulnmatch.match_exploits(ws, "10.10.10.90")}
    assert "vsftpd234" in keys


def test_a_patched_version_does_not_match(tmp_path):
    ws = _ws(tmp_path)
    _port(ws, "10.10.10.90", 21, "ftp", "vsftpd 3.0.3")
    keys = {c["key"] for c in vulnmatch.match_exploits(ws, "10.10.10.90")}
    assert "vsftpd234" not in keys


def test_os_family_gates_a_match(tmp_path):
    ws = _ws(tmp_path)
    _port(ws, "10.10.10.90", 445, "microsoft-ds")
    ws.facts.add(Fact("host.os_family", "host:10.10.10.90", {"family": "windows"}, source="nmap"))
    assert any(c["key"] == "eternalblue" for c in vulnmatch.match_exploits(ws, "10.10.10.90"))
    # the same SMB port on a proven-Linux host does not match EternalBlue
    ws2 = _ws(tmp_path / "b", "10.10.10.91")
    _port(ws2, "10.10.10.91", 445, "netbios-ssn")
    ws2.facts.add(Fact("host.os_family", "host:10.10.10.91", {"family": "linux"}, source="nmap"))
    assert not any(c["key"] == "eternalblue" for c in vulnmatch.match_exploits(ws2, "10.10.10.91"))


def test_web_and_kernel_fingerprints(tmp_path):
    ws = _ws(tmp_path)
    _port(ws, "10.10.10.90", 80, "http", "Apache Drupal 7")
    assert any(c["key"] == "drupalgeddon2" for c in vulnmatch.match_exploits(ws, "10.10.10.90"))
    ws.facts.add(Fact("foothold.linux", "host:10.10.10.90", {"user": "www"}, source="shell"))
    assert any(c["key"] == "dirtycow" for c in vulnmatch.match_exploits(ws, "10.10.10.90"))


# ── proof boundary: a match is a candidate lead, never a confirmed vuln ────────
def test_match_records_a_candidate_lead_not_a_confirmed_vuln(tmp_path):
    ws = _ws(tmp_path)
    _port(ws, "10.10.10.90", 21, "ftp", "vsftpd 2.3.4")
    added = vulnmatch.record_candidates(ws, "10.10.10.90")
    assert "vsftpd234" in added
    cand = next(f for f in ws.facts.facts if f.kind == "exploit.candidate"
                and f.value.get("key") == "vsftpd234")
    assert "candidate" in cand.source.lower() and "not confirmed" in cand.source.lower()
    # obol records NO "confirmed vulnerable" fact from a version match
    assert not ws.facts.has("vuln.confirmed") and not ws.facts.has("exploit.confirmed")
    # idempotent — a second pass adds nothing new
    assert vulnmatch.record_candidates(ws, "10.10.10.90") == []


# ── flows through the same points as any exploit: a move + craft ──────────────
def test_matched_exploit_is_a_manual_move_and_crafts(tmp_path):
    ws = _ws(tmp_path)
    _port(ws, "10.10.10.90", 21, "ftp", "vsftpd 2.3.4")
    ws.save()
    m = next((mv for mv in moves.frontier_moves(ws, "10.10.10.90")
              if mv.id == "exploit:vuln:vsftpd234"), None)
    assert m is not None and m.kind == "exploit" and m.autonomy == "manual"
    # dispatch crafts it (never fires) and records the candidate lead
    res = dispatch.run_move(ws, "exploit:vuln:vsftpd234", host="10.10.10.90")
    assert res["ok"] and res["posture"] == "craft" and res["command"]
    assert ws.facts.has("exploit.candidate")


def test_registry_and_cache_stay_in_sync(tmp_path):
    """Every fingerprint entry that names a stageable material has that material in the
    provision cache (so 'all proper points an exploit goes through' are wired)."""
    from obol import provision
    keys = {m.key for m in provision.REGISTRY}
    for ke in vulnmatch.load_known():
        if ke.material:
            assert ke.material in keys, f"{ke.key} references uncached material {ke.material}"
