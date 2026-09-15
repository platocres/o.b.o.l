"""The path graph is one projection: the structured model, the mermaid render, and
the web all agree because they come from build_graph_model."""
from obol.graph import build_graph_model, build_graph_svg, build_mermaid, phase_of_kind, PHASES
from obol.seed import seed_forest
from obol.workspace import Workspace


def _seeded(tmp_path) -> Workspace:
    ws = Workspace(tmp_path)
    seed_forest(ws)
    return ws


def test_phase_of_kind_maps_engagement_stages():
    assert phase_of_kind("port:445") == "recon"
    assert phase_of_kind("ad.user_list") == "enum"
    assert phase_of_kind("hash.asrep") == "creds"
    assert phase_of_kind("credential.available") == "creds"
    assert phase_of_kind("access.admin") == "access"
    assert phase_of_kind("loot.ntds") == "loot"
    assert phase_of_kind("ad.control_paths") == "escalate"


def test_model_shape_and_phase_membership(tmp_path):
    model = build_graph_model(_seeded(tmp_path).facts)
    assert model["phases"] == PHASES
    assert model["nodes"] and model["edges"]
    for n in model["nodes"]:
        assert n["type"] in ("fact", "action")
        assert n["phase"] in PHASES
        if n["type"] == "fact":
            assert n["state"] in ("proven", "future")
        else:
            assert n["state"] in ("done", "next")
    ids = {n["id"] for n in model["nodes"]}
    for e in model["edges"]:                       # every edge endpoint is a real node
        assert e["from"] in ids and e["to"] in ids


def test_model_excludes_blocked_actions(tmp_path):
    """Only done + live actions appear — no blocked/far-off branches (a product
    guardrail)."""
    from obol.pack import load_packs, next_actions
    facts = _seeded(tmp_path).facts
    model = build_graph_model(facts)
    live_ids = {a.id for a in next_actions(facts)}
    settled_ids = {a.id for a in load_packs() if a.settled(facts)}
    for n in model["nodes"]:
        if n["type"] == "action":
            assert n["action_id"] in live_ids or n["action_id"] in settled_ids


def test_mermaid_renders_from_model(tmp_path):
    facts = _seeded(tmp_path).facts
    mm = build_mermaid(facts)
    assert mm.startswith("flowchart TD")
    assert "classDef proven" in mm
    # one node line per model node
    model = build_graph_model(facts)
    for n in model["nodes"]:
        assert n["id"] in mm


def test_graph_svg_is_offline_and_covers_every_node(tmp_path):
    """The offline SVG renderer (for the static `obol web` snapshot) draws the same
    model with no script, web font, or CDN — so the path graph works offline."""
    facts = _seeded(tmp_path).facts
    svg = build_graph_svg(facts)
    assert svg.startswith("<svg") and svg.rstrip().endswith("</svg>")
    low = svg.lower()
    # no external fetches (the xmlns namespace URL is not a network load, so it's fine)
    assert "cdn" not in low and "<script" not in low and "mermaid" not in low
    assert "src=" not in low and "href=" not in low and "<link" not in low
    # a phase header for the earliest populated stage, and one rect + full-label
    # tooltip per model node
    assert "RECON" in svg
    model = build_graph_model(facts)
    assert svg.count("<rect") == len(model["nodes"])
    assert svg.count("<title>") == len(model["nodes"])


def test_graph_svg_handles_empty_path(tmp_path):
    svg = build_graph_svg(Workspace(tmp_path).facts)
    assert svg.startswith("<svg") and "run a scan" in svg
