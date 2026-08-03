"""Scores one scanned case against its ground truth.

Confusion-matrix accounting, in one place so the definitions are auditable:

* **TP** -- a ground-truth vulnerability that some finding matched.
* **FN** -- a ground-truth vulnerability nothing matched.
* **FP** -- an in-scope finding that matched no ground truth.
* **TN** -- only defined for cases the dataset labels `safe`: a case asserted
  to contain none of the vulnerability classes we detect. A clean scan of
  such a case is one TN; findings on it are FPs. Cases labeled `vulnerable`
  or `mixed` contribute no TNs, because "this function is not vulnerable"
  isn't enumerable -- there's no denominator. Precision/recall/F1 don't use
  TN, so this conservatism costs nothing except an accuracy figure we can't
  honestly compute for the whole suite.
"""

from __future__ import annotations

import logging

from cpgvd.models import AnalysisReport

from ..models import (
    BenchmarkCase,
    CaseLabel,
    CaseResult,
    MatchPolicy,
    Metrics,
)
from ..matcher import in_scope, match_findings

logger = logging.getLogger(__name__)


def evaluate_case(
    case: BenchmarkCase,
    report: AnalysisReport,
    policy: MatchPolicy,
    *,
    dataset_name: str,
    duration_seconds: float = 0.0,
    raw_report_path: str = "",
) -> CaseResult:
    """Match `report`'s findings against `case`'s ground truth and score them."""
    effective_policy = policy.merged_with(case.match_policy)

    in_scope_findings = [f for f in report.findings if in_scope(f, case.scope_paths)]
    dropped = len(report.findings) - len(in_scope_findings)
    if dropped:
        logger.debug("Case %s: dropped %d finding(s) outside scope_paths", case.id, dropped)

    matches, false_positives, false_negatives = match_findings(
        in_scope_findings, case.expected, effective_policy
    )

    metrics = Metrics(
        true_positives=len(matches),
        false_positives=len(false_positives),
        false_negatives=len(false_negatives),
        true_negatives=_true_negatives(case, false_positives),
    )

    return CaseResult(
        case_id=case.id,
        dataset=dataset_name,
        repo=case.repo,
        label=case.label,
        status="ok",
        metrics=metrics,
        matches=matches,
        false_positives=false_positives,
        false_negatives=false_negatives,
        findings_reported=len(in_scope_findings),
        ground_truth_total=len(case.expected),
        duration_seconds=duration_seconds or report.stats.duration_seconds,
        stage_timings=dict(report.stats.stage_timings),
        peak_memory_mb=report.stats.peak_memory_mb,
        llm_calls=report.stats.llm_calls,
        contexts_analyzed=report.stats.candidate_contexts_analyzed,
        raw_report_path=raw_report_path,
    )


def _true_negatives(case: BenchmarkCase, false_positives: list) -> int:
    """One TN for a clean scan of a case asserted to be safe; see module docstring."""
    if case.label is not CaseLabel.SAFE:
        return 0
    return 1 if not false_positives else 0
