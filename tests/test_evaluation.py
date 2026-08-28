from cpgvd.evaluation import _finding_control_classes, _score_one, _summarize
from cpgvd.models import Confidence, Finding, MutationRecord, Severity


def _finding(file="app/routes/index.js", start=45, title="Route is not authenticated", vtype="Missing Authentication", cwe="CWE-306"):
    return Finding(
        id="f", context_id="c", file=file, start_line=start, end_line=start + 2,
        function="h", vulnerability_type=vtype, cwe=cwe, severity=Severity.HIGH,
        confidence=Confidence.HIGH, title=title, description="no auth check on this route",
    )


def _rec(operator="M1", control="authentication", file="app/routes/index.js", line=45):
    return MutationRecord(
        id=f"demo::{operator}::{file}::{line}", app="demo", operator=operator,
        control_class=control, file=file, start_line=line, end_line=line, original_text="x",
    )


def test_score_one_hit_within_window_and_class_match():
    res = _score_one(_rec(line=45), [_finding(start=48)], set(), window=20)
    assert res.detected and res.matched_control_ok
    assert res.matched_line == 48


def test_score_one_miss_when_finding_far_away():
    res = _score_one(_rec(line=45), [_finding(start=200)], set(), window=20)
    assert not res.detected


def test_score_one_miss_when_finding_in_other_file():
    res = _score_one(_rec(file="app/routes/index.js", line=45), [_finding(file="app/data/user-dao.js", start=45)], set(), window=20)
    assert not res.detected


def test_score_one_ignores_baseline_line():
    baseline = {("index.js", 48)}
    res = _score_one(_rec(line=45), [_finding(start=48)], baseline, window=20)
    assert not res.detected  # the detector flags this line even with the control present


def test_score_one_class_mismatch_still_detected_but_flagged():
    rec = _rec(operator="M4", control="session", line=45)
    f = _finding(start=46, vtype="Missing Authorization", cwe="CWE-862", title="no role check")
    res = _score_one(rec, [f], set(), window=20)
    assert res.detected and not res.matched_control_ok


def test_finding_control_classes_maps_cwe_and_words():
    assert "authorization" in _finding_control_classes(_finding(cwe="CWE-862"))
    assert "ownership" in _finding_control_classes(_finding(vtype="IDOR", cwe="CWE-639", title="idor"))
    assert "session" in _finding_control_classes(_finding(vtype="Missing session validation", cwe="", title="session"))


def test_summarize_recall_and_buckets():
    records = [_rec("M1", "authentication", line=10), _rec("M1", "authentication", line=20), _rec("M4", "session", line=30)]
    results = [
        _score_one(records[0], [_finding(start=11)], set(), 20),      # hit
        _score_one(records[1], [], set(), 20),                        # miss
        _score_one(records[2], [_finding(start=31, cwe="", vtype="Missing session validation", title="session")], set(), 20),  # hit
    ]
    s = _summarize("demo", "abc123", records, results, baseline_fp=2)
    assert s.tp == 2 and s.fn == 1
    assert s.recall == round(2 / 3, 3)
    assert s.baseline_fp == 2
    assert s.by_operator["M1"] == {"tp": 1, "fn": 1, "recall": 0.5}
    assert s.by_control_class["session"]["recall"] == 1.0
    # precision folds in the 2 baseline FPs
    assert s.precision == round(2 / (2 + 2), 3)
