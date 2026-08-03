"""The matching engine: does a reported finding correspond to a known vulnerability?

This is the load-bearing piece of the whole framework -- every metric in the
dissertation ultimately rests on this function's judgment, so its behavior is
explicit and configurable rather than buried in the metrics code.

Design notes:

* **Never exact-line-only.** Patches shift lines, Joern frontends disagree
  about where a method starts, and the LLM sometimes points at the sink line
  and sometimes at the function signature. Line proximity is one weighted
  signal with a tolerance, not a gate (unless a dataset opts into
  `require_line`).
* **Sparse ground truth stays usable.** A signal is only scored when the
  ground-truth entry actually specifies it, and the weighted average is taken
  over the applicable signals only. Ground truth with just a file and a CWE
  therefore isn't penalized against ground truth that also names a function.
* **One finding per ground truth.** Assignment is greedy on score, so a
  single finding can't satisfy two ground-truth entries and inflate recall.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from cpgvd.models import Finding

from .models import (
    GroundTruth,
    Match,
    MatchPolicy,
    MatchSignals,
    MissedGroundTruth,
    UnmatchedFinding,
    normalize_cwe,
)

_IDENT_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")


def normalize_path(path: str) -> str:
    """Normalize a path for comparison: posix separators, no leading './'."""
    cleaned = (path or "").replace("\\", "/").strip()
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned.lstrip("/")


def path_score(finding_path: str, truth_path: str, mode: str) -> float:
    """1.0 for a match under `mode`, else 0.0.

    'suffix' (the default) is what makes ground truth portable: cpgvd reports
    paths relative to the clone root, while an imported test suite may record
    them relative to its own source root, so one is usually a path-component
    suffix of the other.
    """
    a, b = normalize_path(finding_path), normalize_path(truth_path)
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    if mode == "exact":
        return 0.0
    if mode == "basename":
        return 1.0 if PurePosixPath(a).name == PurePosixPath(b).name else 0.0

    # suffix: one path's trailing components equal the other's
    parts_a, parts_b = a.split("/"), b.split("/")
    shorter, longer = (parts_a, parts_b) if len(parts_a) <= len(parts_b) else (parts_b, parts_a)
    return 1.0 if longer[-len(shorter) :] == shorter else 0.0


def line_score(
    finding_start: int, finding_end: int, truth_span: tuple[int, int], tolerance: int
) -> tuple[float, int]:
    """Score line proximity, and report how far off the finding was.

    Overlapping ranges score 1.0. Outside that, the score decays linearly to
    0.0 at `tolerance` lines of gap, so a finding 2 lines away still counts
    strongly while one 50 lines away doesn't count at all.
    """
    t_start, t_end = truth_span
    f_start, f_end = min(finding_start, finding_end), max(finding_start, finding_end)

    if f_start <= t_end and t_start <= f_end:
        return 1.0, 0

    gap = t_start - f_end if f_end < t_start else f_start - t_end
    if tolerance <= 0 or gap > tolerance:
        return 0.0, gap
    return 1.0 - (gap / (tolerance + 1)), gap


def _tokens(value: str) -> set[str]:
    return {t.lower() for t in _IDENT_SPLIT_RE.split(value or "") if t}


def name_score(finding_value: str, truth_value: str) -> float:
    """Fuzzy identifier comparison for function names and sink expressions.

    Exact match after normalization scores 1.0; a containment relationship
    (cpgvd reports fully-qualified names like `app.py:<module>.admin_run`
    while ground truth says `admin_run`) scores 0.9; shared tokens score by
    overlap. This is deliberately generous -- function/sink are low-weight
    corroborating signals, not gates.
    """
    a, b = (finding_value or "").strip().lower(), (truth_value or "").strip().lower()
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    if b in a or a in b:
        return 0.9
    tokens_a, tokens_b = _tokens(a), _tokens(b)
    if not tokens_a or not tokens_b:
        return 0.0
    overlap = tokens_a & tokens_b
    return len(overlap) / min(len(tokens_a), len(tokens_b)) if overlap else 0.0


def cwe_score(finding_cwe: str, truth_cwe: str) -> float:
    """1.0 when the normalized CWE ids agree, else 0.0."""
    a, b = normalize_cwe(finding_cwe), normalize_cwe(truth_cwe)
    if not a or not b:
        return 0.0
    return 1.0 if a == b else 0.0


def score_pair(
    finding: Finding, truth: GroundTruth, policy: MatchPolicy
) -> tuple[float, MatchSignals, int | None]:
    """Score one (finding, ground truth) pair.

    Returns the weighted score in [0, 1], the per-signal breakdown, and the
    line delta (None when the ground truth has no line). A score of 0.0 is
    returned whenever a `require_*` gate fails, regardless of other signals.
    """
    signals = MatchSignals()
    weights = policy.weights
    weighted_sum = 0.0
    weight_total = 0.0
    line_delta: int | None = None

    if truth.file:
        signals.file = path_score(finding.file, truth.file, policy.path_match)
        weight = weights.get("file", 1.0)
        weighted_sum += signals.file * weight
        weight_total += weight
        if policy.require_file and signals.file < 1.0:
            return 0.0, signals, None

    span = truth.line_span()
    if span is not None:
        signals.line, line_delta = line_score(
            finding.start_line, finding.end_line, span, policy.line_tolerance
        )
        weight = weights.get("line", 1.0)
        weighted_sum += signals.line * weight
        weight_total += weight
        if policy.require_line and signals.line <= 0.0:
            return 0.0, signals, line_delta

    if truth.cwe:
        signals.cwe = cwe_score(finding.cwe, truth.cwe)
        weight = weights.get("cwe", 1.0)
        weighted_sum += signals.cwe * weight
        weight_total += weight
        if policy.require_cwe and signals.cwe < 1.0:
            return 0.0, signals, line_delta

    if truth.function:
        signals.function = name_score(finding.function, truth.function)
        weight = weights.get("function", 0.5)
        weighted_sum += signals.function * weight
        weight_total += weight

    if truth.sink:
        # The sink rarely appears verbatim in a Finding field, so check the
        # places it plausibly surfaces and take the best.
        signals.sink = max(
            name_score(finding.vulnerability_type, truth.sink),
            name_score(finding.title, truth.sink),
            1.0 if truth.sink.lower() in (finding.description or "").lower() else 0.0,
        )
        weight = weights.get("sink", 0.5)
        weighted_sum += signals.sink * weight
        weight_total += weight

    if weight_total == 0.0:
        # Ground truth specified nothing matchable; refuse to guess.
        return 0.0, signals, line_delta

    return weighted_sum / weight_total, signals, line_delta


def _finding_summary(finding: Finding) -> str:
    return f"{finding.vulnerability_type} @ {finding.file}:{finding.start_line} [{finding.cwe or 'no-CWE'}]"


def match_findings(
    findings: list[Finding], ground_truth: list[GroundTruth], policy: MatchPolicy
) -> tuple[list[Match], list[UnmatchedFinding], list[MissedGroundTruth]]:
    """Assign findings to ground truth, returning (matches, FPs, FNs).

    Assignment is greedy: all candidate pairs above `min_score` are sorted by
    score and consumed in order, so the best available pairing wins and each
    finding and each ground-truth entry is used at most once.
    """
    candidates: list[tuple[float, int, int, MatchSignals, int | None]] = []
    # Best score each item achieved with anything, kept even below threshold
    # so unmatched items can be triaged as near-misses vs. genuine misses.
    best_for_finding: dict[int, float] = {}
    best_for_truth: dict[int, tuple[float, int]] = {}

    for f_index, finding in enumerate(findings):
        for t_index, truth in enumerate(ground_truth):
            score, signals, delta = score_pair(finding, truth, policy)
            if score > best_for_finding.get(f_index, 0.0):
                best_for_finding[f_index] = score
            if score > best_for_truth.get(t_index, (0.0, -1))[0]:
                best_for_truth[t_index] = (score, f_index)
            if score >= policy.min_score:
                candidates.append((score, f_index, t_index, signals, delta))

    candidates.sort(key=lambda c: (-c[0], c[1], c[2]))

    used_findings: set[int] = set()
    used_truth: set[int] = set()
    matches: list[Match] = []

    for score, f_index, t_index, signals, delta in candidates:
        if f_index in used_findings or t_index in used_truth:
            continue
        used_findings.add(f_index)
        used_truth.add(t_index)
        finding, truth = findings[f_index], ground_truth[t_index]
        matches.append(
            Match(
                ground_truth_id=truth.id,
                finding_id=finding.id,
                score=round(score, 4),
                signals=signals,
                finding_summary=_finding_summary(finding),
                ground_truth_summary=truth.label(),
                ground_truth_cwe=truth.cwe,
                ground_truth_category=truth.category,
                finding_cwe=finding.cwe,
                line_delta=delta,
            )
        )

    false_positives = [
        UnmatchedFinding(
            finding_id=f.id,
            file=f.file,
            start_line=f.start_line,
            cwe=f.cwe,
            vulnerability_type=f.vulnerability_type,
            title=f.title,
            severity=f.severity.value,
            confidence=f.confidence.value,
            best_score=round(best_for_finding.get(i, 0.0), 4),
        )
        for i, f in enumerate(findings)
        if i not in used_findings
    ]

    false_negatives = []
    for i, truth in enumerate(ground_truth):
        if i in used_truth:
            continue
        best_score, best_index = best_for_truth.get(i, (0.0, -1))
        false_negatives.append(
            MissedGroundTruth(
                ground_truth_id=truth.id,
                cwe=truth.cwe,
                file=truth.file,
                start_line=truth.start_line,
                category=truth.category,
                description=truth.description,
                best_score=round(best_score, 4),
                best_candidate_finding_id=findings[best_index].id if best_index >= 0 else "",
            )
        )

    return matches, false_positives, false_negatives


def in_scope(finding: Finding, scope_paths: list[str]) -> bool:
    """Whether a finding falls inside a case's `scope_paths` restriction.

    Out-of-scope findings are dropped before matching -- they're neither
    credited nor penalized. This lets a case pin ground truth to one
    subdirectory of a large repo without every unrelated finding elsewhere
    counting as a false positive.
    """
    if not scope_paths:
        return True
    finding_path = normalize_path(finding.file)
    return any(
        finding_path == normalize_path(scope) or finding_path.startswith(normalize_path(scope).rstrip("/") + "/")
        for scope in scope_paths
    )
