from cpgvd.pipeline import RuleSets, _prioritize_absence, _rawify, cpg_path_for
from cpgvd.config import Config
from cpgvd.models import ControlTrigger, FunctionContext, GuardEvidence


class _Hit:
    def __init__(self, operation):
        self.operation = operation


def test_prioritize_absence_puts_route_handlers_first_then_by_count():
    items = [
        ("dao_many_reads", [_Hit("db_read")] * 5),
        ("route_handler", [_Hit("route")]),
        ("one_write", [_Hit("db_write")]),
        ("route_plus_writes", [_Hit("route"), _Hit("db_write")]),
    ]
    order = [k for k, _ in _prioritize_absence(items)]
    # both route handlers come before any non-route function
    assert order.index("route_plus_writes") < order.index("dao_many_reads")
    assert order.index("route_handler") < order.index("dao_many_reads")
    # among routes, more triggers first
    assert order.index("route_plus_writes") < order.index("route_handler")


def test_rulesets_load_only_pulls_absence_rules_when_needed():
    assert RuleSets.load("injection").absence_rules == {}
    assert RuleSets.load("absence").absence_rules
    assert RuleSets.load("both").absence_rules


def _ctx(file="app/routes/x.js", start=5):
    return FunctionContext(
        context_id="absence-route:x:/y:5", language="javascript", file=file,
        method_name="h", full_name="h", start_line=start, end_line=start + 3,
        code="the CPG slice", route_path="/y",
        control_triggers=[ControlTrigger(operation="route", category="c", code="app.get(...)", file=file, line=start, node_id=1)],
        guard_evidence=[GuardEvidence(control="authentication", category="c", code="requireAuth", file=file, line=start)],
    )


def test_rawify_swaps_in_the_whole_file_and_drops_cpg_context(tmp_path):
    f = tmp_path / "app" / "routes"
    f.mkdir(parents=True)
    (f / "x.js").write_text("line1\nline2\napp.get('/y', requireAuth, h)\nline4\n")

    raw = _rawify(_ctx(), tmp_path)

    assert raw.grounding == "raw"
    assert "app.get('/y', requireAuth, h)" in raw.code
    assert raw.control_triggers == [] and raw.guard_evidence == []
    # anchor fields kept for scoring
    assert raw.file == "app/routes/x.js" and raw.start_line == 5 and raw.route_path == "/y"


def test_rawify_truncates_a_huge_file_around_the_candidate_line(tmp_path):
    (tmp_path / "big.js").write_text("\n".join(f"row {i}" for i in range(5000)))
    raw = _rawify(_ctx(file="big.js", start=2500), tmp_path, max_chars=2000)
    assert len(raw.code) < 4000
    assert "row 2500" in raw.code
    assert "omitted" in raw.code


def test_to_raw_prompt_text_is_minimal():
    text = _rawify_inline().to_raw_prompt_text()
    assert "No call graph or guard list" in text
    assert "CPG node" not in text


def _rawify_inline():
    c = _ctx()
    c.code = "app.get('/y', requireAuth, h)"
    c.grounding = "raw"
    return c


def test_cpg_path_is_content_addressed(tmp_path):
    (tmp_path / "a.js").write_text("app.get('/x', h);\n")
    p1 = cpg_path_for(tmp_path, Config(work_dir=tmp_path / "_w"))
    (tmp_path / "a.js").write_text("app.get('/x', requireAuth, h);\n")
    p2 = cpg_path_for(tmp_path, Config(work_dir=tmp_path / "_w"))
    assert p1 != p2


def test_ruleset_load_hygiene_and_all_modes():
    assert RuleSets.load("injection").hygiene_rules == {}
    assert RuleSets.load("both").hygiene_rules == {}
    hy = RuleSets.load("hygiene")
    assert hy.hygiene_rules.get("javascript") and hy.absence_rules == {}
    allm = RuleSets.load("all")
    assert allm.rules and allm.absence_rules and allm.hygiene_rules
