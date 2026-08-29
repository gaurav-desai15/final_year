from cpgvd.metrics import (
    compression_summary,
    count_repo_source_lines,
    finding_is_grounded,
    grounded_findings_ratio,
)
from cpgvd.models import Confidence, Finding, FunctionContext, Severity


def _ctx(context_id="c1", file="app/x.js", start=10, end=25, code="a\nb\nc\n", grounding="cpg"):
    return FunctionContext(
        context_id=context_id, language="javascript", file=file, method_name="h",
        full_name="h", start_line=start, end_line=end, code=code, grounding=grounding,
    )


def _finding(context_id="c1", file="app/x.js", start=12, end=14):
    return Finding(
        id="f", context_id=context_id, file=file, start_line=start, end_line=end,
        function="h", vulnerability_type="Missing Authorization", severity=Severity.HIGH,
        confidence=Confidence.HIGH, title="t", description="d",
    )


def test_count_repo_source_lines_skips_node_modules_and_blanks(tmp_path):
    (tmp_path / "a.js").write_text("one\n\ntwo\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "big.js").write_text("\n".join("x" for _ in range(1000)))
    assert count_repo_source_lines(tmp_path) == 2


def test_compression_summary_ratios(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "x.js").write_text("\n".join(f"line{i}" for i in range(100)))  # 100 LoC
    ctx = _ctx(code="\n".join("y" for _ in range(10)))  # 10-line slice

    s = compression_summary([ctx], tmp_path)
    assert s["slice_loc_median"] == 10
    assert s["file_loc_median"] == 100
    assert s["slice_over_file_median"] == 0.1


def test_grounded_findings_ratio_counts_cited_lines_inside_the_slice():
    ctx = _ctx(start=10, end=25)
    inside = _finding(start=12, end=14)
    outside = _finding(start=200, end=204)
    r = grounded_findings_ratio([inside, outside], [ctx])
    assert r == {"findings_checked": 2, "grounded": 1, "ratio": 0.5}


def test_finding_grounded_for_raw_context_uses_whole_file():
    raw = _ctx(grounding="raw", start=1, code="\n".join(f"l{i}" for i in range(300)))
    assert finding_is_grounded(_finding(start=250, end=252), raw)
