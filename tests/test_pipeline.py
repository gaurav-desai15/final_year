from cpgvd.pipeline import RuleSets, _prioritize_absence, cpg_path_for
from cpgvd.config import Config


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


def test_cpg_path_is_content_addressed(tmp_path):
    (tmp_path / "a.js").write_text("app.get('/x', h);\n")
    p1 = cpg_path_for(tmp_path, Config(work_dir=tmp_path / "_w"))
    (tmp_path / "a.js").write_text("app.get('/x', requireAuth, h);\n")
    p2 = cpg_path_for(tmp_path, Config(work_dir=tmp_path / "_w"))
    assert p1 != p2
