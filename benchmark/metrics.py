"""Aggregation over a completed run: metrics, runtime statistics, rankings.

Everything here is a pure function of a `RunResult`, so the same code serves
the live report, the archived-run analysis document, and the comparison tool.
"""

from __future__ import annotations

import statistics
from collections import Counter
from typing import Iterable

from .models import CaseResult, Metrics, RunResult, normalize_cwe


def overall(run: RunResult) -> Metrics:
    return run.overall_metrics()


def by_case(run: RunResult) -> dict[str, Metrics]:
    return {case.case_id: case.metrics for case in run.ok_cases()}


def by_dataset(run: RunResult) -> dict[str, Metrics]:
    buckets: dict[str, Metrics] = {}
    for case in run.ok_cases():
        buckets[case.dataset] = buckets.get(case.dataset, Metrics()) + case.metrics
    return buckets


def by_cwe(run: RunResult) -> dict[str, Metrics]:
    return run.metrics_by_cwe()


def by_category(run: RunResult) -> dict[str, Metrics]:
    """Confusion counts bucketed by the dataset's free-form category label."""
    buckets: dict[str, Metrics] = {}

    def bucket(name: str) -> Metrics:
        return buckets.setdefault(name or "uncategorized", Metrics())

    for case in run.ok_cases():
        for match in case.matches:
            bucket(match.ground_truth_category).true_positives += 1
        for fn in case.false_negatives:
            bucket(fn.category).false_negatives += 1
    return buckets


def runtime_stats(run: RunResult) -> dict[str, float]:
    """Wall-clock statistics across cases.

    Median is reported alongside the mean because scan durations are heavily
    right-skewed -- one large repo can pull the mean well above what a typical
    case costs.
    """
    durations = [c.duration_seconds for c in run.cases if c.duration_seconds > 0]
    findings = sum(c.findings_reported for c in run.ok_cases())
    total = sum(durations)

    if not durations:
        return {
            "total_seconds": 0.0,
            "mean_seconds": 0.0,
            "median_seconds": 0.0,
            "min_seconds": 0.0,
            "max_seconds": 0.0,
            "seconds_per_finding": 0.0,
            "cases": 0,
        }

    return {
        "total_seconds": round(total, 2),
        "mean_seconds": round(statistics.mean(durations), 2),
        "median_seconds": round(statistics.median(durations), 2),
        "min_seconds": round(min(durations), 2),
        "max_seconds": round(max(durations), 2),
        "seconds_per_finding": round(total / findings, 2) if findings else 0.0,
        "cases": len(durations),
    }


def stage_breakdown(run: RunResult) -> dict[str, dict[str, float]]:
    """Per-stage total / mean / share-of-total across every case.

    This is what answers "where does a scan actually spend its time?" -- the
    question any performance work has to be justified against.
    """
    per_stage: dict[str, list[float]] = {}
    for case in run.cases:
        for stage, seconds in case.stage_timings.items():
            per_stage.setdefault(stage, []).append(seconds)

    grand_total = sum(sum(v) for v in per_stage.values()) or 1.0
    breakdown: dict[str, dict[str, float]] = {}
    for stage, values in per_stage.items():
        total = sum(values)
        breakdown[stage] = {
            "total_seconds": round(total, 2),
            "mean_seconds": round(statistics.mean(values), 2),
            "median_seconds": round(statistics.median(values), 2),
            "share_pct": round(100 * total / grand_total, 1),
            "cases": len(values),
        }
    return dict(sorted(breakdown.items(), key=lambda kv: -kv[1]["total_seconds"]))


def memory_stats(run: RunResult) -> dict[str, float]:
    values = [c.peak_memory_mb for c in run.cases if c.peak_memory_mb > 0]
    if not values:
        return {}
    return {
        "peak_mb": round(max(values), 1),
        "mean_peak_mb": round(statistics.mean(values), 1),
        "cases_measured": len(values),
    }


def detection_latency(run: RunResult) -> dict[str, float]:
    """Time-to-detection proxies.

    True per-finding latency isn't observable (findings arrive in a batch at
    the end of the LLM stage), so we report the two figures that are: the
    average wall time a case takes to surface its findings, and the average
    LLM time per analyzed context, which is what actually scales.
    """
    ok = run.ok_cases()
    contexts = sum(c.contexts_analyzed for c in ok)
    llm_total = sum(c.stage_timings.get("llm_analysis", 0.0) for c in ok)
    findings = sum(c.findings_reported for c in ok)
    durations = [c.duration_seconds for c in ok if c.duration_seconds > 0]

    return {
        "mean_case_latency_s": round(statistics.mean(durations), 2) if durations else 0.0,
        "llm_seconds_per_context": round(llm_total / contexts, 2) if contexts else 0.0,
        "seconds_per_finding": round(sum(durations) / findings, 2) if findings else 0.0,
        "contexts_analyzed": contexts,
    }


def slowest_cases(run: RunResult, limit: int = 5) -> list[CaseResult]:
    return sorted(run.cases, key=lambda c: -c.duration_seconds)[:limit]


def fastest_cases(run: RunResult, limit: int = 5) -> list[CaseResult]:
    ran = [c for c in run.cases if c.duration_seconds > 0]
    return sorted(ran, key=lambda c: c.duration_seconds)[:limit]


def common_false_positives(run: RunResult, limit: int = 10) -> list[tuple[str, int]]:
    """Most frequent false-positive classes, as (label, count).

    Grouped by CWE + reported vulnerability type: that pairing is what
    identifies a recurring FP *pattern* worth a prompt or rule fix, whereas
    grouping by title alone splits the same pattern across many near-
    identical strings.
    """
    counter: Counter[str] = Counter()
    for case in run.ok_cases():
        for fp in case.false_positives:
            cwe = normalize_cwe(fp.cwe) or "no-CWE"
            counter[f"{cwe} / {fp.vulnerability_type or 'unspecified'}"] += 1
    return counter.most_common(limit)


def common_false_negatives(run: RunResult, limit: int = 10) -> list[tuple[str, int]]:
    """Most frequently missed vulnerability classes, as (label, count)."""
    counter: Counter[str] = Counter()
    for case in run.ok_cases():
        for fn in case.false_negatives:
            cwe = normalize_cwe(fn.cwe) or "no-CWE"
            label = f"{cwe} / {fn.category}" if fn.category else cwe
            counter[label] += 1
    return counter.most_common(limit)


def near_miss_false_negatives(run: RunResult, threshold: float = 0.3) -> list[tuple[str, float]]:
    """FNs that *almost* matched something.

    A miss with a high best-score usually means the detector did find the
    vulnerability but the matcher rejected the pairing (wrong CWE label,
    line drift beyond tolerance). Those are evaluation bugs, not detection
    failures, and separating them keeps recall honest in both directions.
    """
    result = [
        (fn.ground_truth_id, fn.best_score)
        for case in run.ok_cases()
        for fn in case.false_negatives
        if fn.best_score >= threshold
    ]
    return sorted(result, key=lambda item: -item[1])


def detection_distribution(run: RunResult) -> dict[str, int]:
    """Severity histogram over all reported findings that matched ground truth."""
    counter: Counter[str] = Counter()
    for case in run.ok_cases():
        for fp in case.false_positives:
            counter[f"FP/{fp.severity or 'unknown'}"] += 1
        counter["TP"] += len(case.matches)
        counter["FN"] += len(case.false_negatives)
    return dict(counter)


def summarize(run: RunResult) -> dict[str, object]:
    """One dict with every aggregate, for `metrics.json`."""
    metrics = overall(run)
    return {
        "overall": metrics.as_row(),
        "by_dataset": {k: v.as_row() for k, v in by_dataset(run).items()},
        "by_case": {k: v.as_row() for k, v in by_case(run).items()},
        "by_cwe": {k: v.as_row() for k, v in by_cwe(run).items()},
        "by_category": {k: v.as_row() for k, v in by_category(run).items()},
        "runtime": runtime_stats(run),
        "stage_breakdown": stage_breakdown(run),
        "memory": memory_stats(run),
        "detection_latency": detection_latency(run),
        "detection_distribution": detection_distribution(run),
        "top_false_positives": common_false_positives(run),
        "top_false_negatives": common_false_negatives(run),
        "near_miss_false_negatives": near_miss_false_negatives(run),
        "cases_total": len(run.cases),
        "cases_ok": len(run.ok_cases()),
        "cases_failed": len([c for c in run.cases if c.status == "error"]),
    }


def mean(values: Iterable[float]) -> float:
    values = list(values)
    return statistics.mean(values) if values else 0.0
