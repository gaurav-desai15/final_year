"""Tests for the matching engine.

The matcher decides every TP/FP/FN in the project's results, so these tests
are less about coverage than about pinning down the decisions that would
silently distort a dissertation figure if they changed: line tolerance,
path-suffix matching, one-finding-per-ground-truth assignment, and the
refusal to match a safe sibling call site to a vulnerable one.
"""

from __future__ import annotations

import pytest

from benchmark.matcher import (
    line_score,
    match_findings,
    name_score,
    normalize_path,
    path_score,
    score_pair,
)
from benchmark.models import GroundTruth, MatchPolicy
from cpgvd.models import Confidence, Finding, Severity


def make_finding(
    fid: str = "f1",
    file: str = "app.py",
    start: int = 10,
    end: int = 20,
    cwe: str = "CWE-78",
    function: str = "app.py:<module>.admin_run",
    vuln: str = "OS Command Injection",
    description: str = "",
) -> Finding:
    return Finding(
        id=fid,
        context_id=f"ctx-{fid}",
        file=file,
        start_line=start,
        end_line=end,
        function=function,
        vulnerability_type=vuln,
        cwe=cwe,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        title=vuln,
        description=description,
    )


class TestPathScore:
    def test_exact_match(self):
        assert path_score("app.py", "app.py", "suffix") == 1.0

    def test_suffix_match_across_roots(self):
        # cpgvd reports paths relative to the clone root; an imported suite
        # may record them relative to its own source root.
        assert path_score("src/pkg/app.py", "pkg/app.py", "suffix") == 1.0

    def test_suffix_does_not_match_partial_component(self):
        # "myapp.py" must not count as a suffix match for "app.py":
        # component-wise comparison, not string endswith.
        assert path_score("src/myapp.py", "app.py", "suffix") == 0.0

    def test_exact_mode_rejects_suffix(self):
        assert path_score("src/pkg/app.py", "pkg/app.py", "exact") == 0.0

    def test_basename_mode(self):
        assert path_score("a/b/app.py", "z/app.py", "basename") == 1.0

    def test_empty_paths_score_zero(self):
        assert path_score("", "app.py", "suffix") == 0.0

    @pytest.mark.parametrize("raw,expected", [
        ("./app.py", "app.py"), ("/app.py", "app.py"),
        ("a\\b.py", "a/b.py"), ("  app.py  ", "app.py"),
    ])
    def test_normalize(self, raw, expected):
        assert normalize_path(raw) == expected


class TestLineScore:
    def test_overlapping_ranges_score_full(self):
        score, delta = line_score(10, 20, (15, 25), tolerance=10)
        assert score == 1.0
        assert delta == 0

    def test_gap_within_tolerance_decays(self):
        score, delta = line_score(10, 12, (16, 20), tolerance=10)
        assert delta == 4
        assert 0.0 < score < 1.0

    def test_gap_beyond_tolerance_scores_zero(self):
        score, delta = line_score(10, 12, (60, 70), tolerance=10)
        assert score == 0.0
        assert delta == 48

    def test_zero_tolerance_requires_overlap(self):
        assert line_score(10, 12, (13, 20), tolerance=0)[0] == 0.0
        assert line_score(10, 14, (13, 20), tolerance=0)[0] == 1.0


class TestNameScore:
    def test_exact(self):
        assert name_score("admin_run", "admin_run") == 1.0

    def test_qualified_name_contains_bare_name(self):
        # cpgvd reports fully-qualified names; ground truth uses bare ones.
        assert name_score("app.py:<module>.admin_run", "admin_run") == pytest.approx(0.9)

    def test_unrelated_names_score_zero(self):
        assert name_score("alpha", "beta") == 0.0

    def test_empty_scores_zero(self):
        assert name_score("", "admin_run") == 0.0


class TestScorePair:
    def test_full_agreement_scores_one(self):
        finding = make_finding()
        truth = GroundTruth(id="gt1", cwe="CWE-78", file="app.py",
                            start_line=10, end_line=20, function="admin_run")
        score, signals, delta = score_pair(finding, truth, MatchPolicy())
        assert score > 0.95
        assert signals.file == 1.0
        assert delta == 0

    def test_require_file_gates_the_match(self):
        finding = make_finding(file="other.py")
        truth = GroundTruth(id="gt1", cwe="CWE-78", file="app.py", start_line=10)
        score, _, _ = score_pair(finding, truth, MatchPolicy(require_file=True))
        assert score == 0.0

    def test_require_cwe_gates_the_match(self):
        finding = make_finding(cwe="CWE-89")
        truth = GroundTruth(id="gt1", cwe="CWE-78", file="app.py", start_line=10)
        score, _, _ = score_pair(finding, truth, MatchPolicy(require_cwe=True))
        assert score == 0.0

    def test_cwe_mismatch_without_gate_still_scores(self):
        # A correct detection reported under a sibling CWE should not be
        # thrown away by default -- it degrades the score, not the match.
        finding = make_finding(cwe="CWE-89")
        truth = GroundTruth(id="gt1", cwe="CWE-78", file="app.py",
                            start_line=10, end_line=20)
        score, _, _ = score_pair(finding, truth, MatchPolicy())
        assert 0.0 < score < 1.0

    def test_sparse_ground_truth_is_not_penalized(self):
        # Ground truth naming only a file and CWE should score as well as
        # richer ground truth when everything it does specify agrees.
        finding = make_finding()
        truth = GroundTruth(id="gt1", cwe="CWE-78", file="app.py")
        score, _, _ = score_pair(finding, truth, MatchPolicy())
        assert score == pytest.approx(1.0)

    def test_ground_truth_with_nothing_matchable_scores_zero(self):
        score, _, _ = score_pair(make_finding(), GroundTruth(id="gt1"), MatchPolicy())
        assert score == 0.0

    def test_normalized_cwe_forms_agree(self):
        finding = make_finding(cwe="CWE-78: Improper Neutralization")
        truth = GroundTruth(id="gt1", cwe="cwe 78", file="app.py")
        score, signals, _ = score_pair(finding, truth, MatchPolicy())
        assert signals.cwe == 1.0
        assert score == pytest.approx(1.0)


class TestMatchFindings:
    def test_simple_match(self):
        findings = [make_finding()]
        truth = [GroundTruth(id="gt1", cwe="CWE-78", file="app.py", start_line=10, end_line=20)]
        matches, fps, fns = match_findings(findings, truth, MatchPolicy())
        assert len(matches) == 1
        assert not fps and not fns
        assert matches[0].ground_truth_id == "gt1"
        assert matches[0].ground_truth_cwe == "CWE-78"

    def test_unmatched_finding_is_a_false_positive(self):
        findings = [make_finding(file="unrelated.py")]
        truth = [GroundTruth(id="gt1", cwe="CWE-78", file="app.py", start_line=10)]
        matches, fps, fns = match_findings(findings, truth, MatchPolicy())
        assert not matches
        assert [f.finding_id for f in fps] == ["f1"]
        assert [f.ground_truth_id for f in fns] == ["gt1"]

    def test_one_finding_cannot_satisfy_two_ground_truths(self):
        # Otherwise a single scattershot finding would inflate recall.
        findings = [make_finding(start=10, end=60)]
        truth = [
            GroundTruth(id="gt1", cwe="CWE-78", file="app.py", start_line=12, end_line=14),
            GroundTruth(id="gt2", cwe="CWE-78", file="app.py", start_line=50, end_line=55),
        ]
        matches, _, fns = match_findings(findings, truth, MatchPolicy())
        assert len(matches) == 1
        assert len(fns) == 1

    def test_best_pairing_wins(self):
        # The closer finding should claim the ground truth, leaving the
        # farther one as the false positive.
        near = make_finding(fid="near", start=10, end=12)
        far = make_finding(fid="far", start=100, end=102)
        truth = [GroundTruth(id="gt1", cwe="CWE-78", file="app.py", start_line=10, end_line=12)]
        matches, fps, _ = match_findings([far, near], truth, MatchPolicy())
        assert matches[0].finding_id == "near"
        assert [f.finding_id for f in fps] == ["far"]

    def test_safe_sibling_is_not_matched_under_tight_policy(self):
        """The dataset-level guard that makes bundled-examples meaningful.

        A finding on a *safe* call site four lines below the vulnerable one
        must count as a false positive, not be absorbed as a true positive.
        """
        policy = MatchPolicy(line_tolerance=3, require_line=True)
        safe_site = make_finding(fid="fp", start=55, end=64, cwe="CWE-22")
        truth = [GroundTruth(id="gt1", cwe="CWE-22", file="app.py",
                             start_line=45, end_line=51)]
        matches, fps, fns = match_findings([safe_site], truth, policy)
        assert not matches
        assert len(fps) == 1 and len(fns) == 1

    def test_near_miss_records_best_score_for_triage(self):
        policy = MatchPolicy(line_tolerance=3, require_line=True)
        finding = make_finding(start=55, end=64, cwe="CWE-22")
        truth = [GroundTruth(id="gt1", cwe="CWE-22", file="app.py",
                             start_line=45, end_line=51)]
        _, fps, fns = match_findings([finding], truth, policy)
        # Gate failure means a 0.0 score; the point is the field exists and
        # is populated so `near_miss_false_negatives` can triage on it.
        assert fns[0].best_score == 0.0
        assert fps[0].best_score == 0.0

    def test_empty_inputs(self):
        assert match_findings([], [], MatchPolicy()) == ([], [], [])
