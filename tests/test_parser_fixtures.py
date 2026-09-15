import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from obol.facts import Fact, ProofState
from obol.pack import Action
from obol.parsers import parse_action_output
from obol.workspace import Workspace


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "parser"
MANIFEST = FIXTURE_DIR / "manifest.json"


def _workspace(tmp_path: Path, *, target: str, domain: str = "") -> Workspace:
    ws = Workspace(tmp_path)
    ws.target = target
    ws.add_scope(target)
    ws.facts.add(Fact("target.configured", f"host:{target}", {"target": target}, source="fixture"))
    if domain:
        ws.facts.add(Fact("ad.domain_known", f"domain:{domain}", {"name": domain}, source="fixture"))
    return ws


def _contains(actual, expected) -> bool:
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return False
        return all(key in actual and _contains(actual[key], value) for key, value in expected.items())
    if isinstance(expected, list):
        if not isinstance(actual, list):
            return False
        return all(any(_contains(item, expected_item) for item in actual) for expected_item in expected)
    return actual == expected


def _matching_facts(facts, expected):
    state = ProofState(expected.get("state", "supported"))
    matches = [fact for fact in facts if fact.kind == expected["kind"] and fact.state is state]
    if "scope" in expected:
        matches = [fact for fact in matches if fact.scope == expected["scope"]]
    if "value_contains" in expected:
        matches = [fact for fact in matches if _contains(fact.value, expected["value_contains"])]
    return matches


def _supported_kinds(facts) -> set[str]:
    return {fact.kind for fact in facts if fact.state is ProofState.SUPPORTED}


def _refuted_kinds(facts) -> set[str]:
    return {fact.kind for fact in facts if fact.state is ProofState.REFUTED}


def test_parser_fixture_manifest_is_valid():
    data = json.loads(MANIFEST.read_text())
    ids = [case["id"] for case in data["cases"]]
    assert len(ids) == len(set(ids))
    for case in data["cases"]:
        assert (FIXTURE_DIR / case["stdout"]).exists()
        assert case["command"]
        assert case["action_id"]


def test_parser_fixture_corpus_proves_expected_facts_and_blocks_overclaims(tmp_path):
    data = json.loads(MANIFEST.read_text())
    default_forbidden = set(data["defaults"].get("forbidden_supported_kinds", []))

    for case in data["cases"]:
        target = case.get("target", data["defaults"]["target"])
        ws = _workspace(tmp_path / case["id"], target=target, domain=case.get("domain", ""))
        action = Action(id=case["action_id"], title=case["action_id"], tool=case.get("tool", ""))
        stdout = (FIXTURE_DIR / case["stdout"]).read_text()
        stderr = ""
        if case.get("stderr"):
            stderr = (FIXTURE_DIR / case["stderr"]).read_text()

        facts = parse_action_output(action, ws, case["command"], stdout, stderr, case["command"])
        supported = _supported_kinds(facts)
        refuted = _refuted_kinds(facts)

        if "expected_fact_count" in case:
            assert len(facts) == case["expected_fact_count"], case["id"]

        for kind in case.get("expected_supported_kinds", []):
            assert kind in supported, f"{case['id']} did not produce supported {kind}; got {sorted(supported)}"
        for kind in case.get("expected_refuted_kinds", []):
            assert kind in refuted, f"{case['id']} did not produce refuted {kind}; got {sorted(refuted)}"

        for expected in case.get("expected_facts", []):
            assert _matching_facts(facts, expected), f"{case['id']} missing matching fact: {expected}"

        forbidden = default_forbidden | set(case.get("forbidden_supported_kinds", []))
        if case.get("allow_default_forbidden_supported_kinds"):
            forbidden -= set(case["allow_default_forbidden_supported_kinds"])
        assert not (supported & forbidden), f"{case['id']} overclaimed {sorted(supported & forbidden)}"

        for fact in facts:
            assert fact.source == case["command"], f"{case['id']} lost source lineage for {fact.kind}"
