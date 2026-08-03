"""Typed data structures for the benchmark framework.

Everything the benchmark produces is a pydantic model so a run archives to
JSON losslessly and can be re-loaded months later for comparison. Nothing
here imports cpgvd internals beyond `Finding`/`AnalysisReport`, which keeps
the evaluation layer decoupled from pipeline changes.
"""

from __future__ import annotations

import datetime as _dt
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class CaseLabel(str, Enum):
    """Whether a benchmark case is expected to contain vulnerabilities.

    `SAFE` cases are how true negatives enter the picture: a repo (or repo
    subset) asserted to have no vulnerability of the classes we detect, so
    any finding on it is a false positive and a clean scan is a TN.
    """

    VULNERABLE = "vulnerable"
    SAFE = "safe"
    MIXED = "mixed"  # contains both; only the listed `expected` entries are ground truth


class GroundTruth(BaseModel):
    """One known vulnerability a scanner is expected to report."""

    id: str
    cwe: str = ""
    file: str = ""
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    function: str = ""
    sink: str = ""
    description: str = ""
    # Free-form grouping used in per-class analysis (e.g. "command-injection").
    category: str = ""
    tags: list[str] = Field(default_factory=list)

    def line_span(self) -> tuple[int, int] | None:
        if self.start_line is None:
            return None
        return (self.start_line, self.end_line if self.end_line is not None else self.start_line)

    def label(self) -> str:
        loc = self.file or "?"
        if self.start_line is not None:
            loc = f"{loc}:{self.start_line}"
        return f"{self.id} ({self.cwe or 'no-CWE'} @ {loc})"


class MatchPolicy(BaseModel):
    """Configurable tolerances for deciding whether a finding matches a
    ground-truth entry.

    Deliberately *not* exact-line matching: a finding's reported line moves
    when a patch shifts code, when the LLM points at the sink line vs. the
    function signature, and when different Joern frontends report slightly
    different method line ranges. Instead each signal contributes a score,
    and a match needs both the hard requirements (`require_*`) and a total
    above `min_score`.
    """

    line_tolerance: int = Field(
        default=10, description="Lines a finding may be off by and still count as the same location."
    )
    path_match: str = Field(
        default="suffix", description="How file paths are compared: 'exact', 'suffix', or 'basename'."
    )
    require_file: bool = Field(default=True, description="A file-path match is mandatory.")
    require_cwe: bool = Field(
        default=False,
        description="A CWE match is mandatory. Off by default: models often report a "
        "correct vulnerability under a sibling CWE id.",
    )
    require_line: bool = Field(
        default=False, description="A within-tolerance line match is mandatory."
    )
    min_score: float = Field(
        default=0.5, description="Minimum weighted score (0-1) across applicable signals."
    )
    weights: dict[str, float] = Field(
        default_factory=lambda: {
            "file": 1.0,
            "line": 1.0,
            "cwe": 1.0,
            "function": 0.5,
            "sink": 0.5,
        },
        description="Per-signal weight. A signal is only scored when the ground "
        "truth actually specifies it, so sparse ground truth stays usable.",
    )

    def merged_with(self, override: dict[str, Any] | None) -> "MatchPolicy":
        """Return a copy with `override` applied (dataset-level tuning)."""
        if not override:
            return self
        data = self.model_dump()
        for key, value in override.items():
            if key == "weights" and isinstance(value, dict):
                data["weights"] = {**data["weights"], **value}
            else:
                data[key] = value
        return MatchPolicy(**data)


class BenchmarkCase(BaseModel):
    """One repository (at one commit) to scan, plus its ground truth."""

    id: str
    repo: str = Field(description="A GitHub URL or a path; relative paths resolve against the repo root.")
    ref: str = Field(default="", description="Branch/tag/commit. Pin a commit for reproducibility.")
    language: str = ""
    label: CaseLabel = CaseLabel.VULNERABLE
    description: str = ""
    expected: list[GroundTruth] = Field(default_factory=list)
    analyze_args: list[str] = Field(
        default_factory=list, description="Extra flags appended to `cpgvd analyze`."
    )
    # Findings outside these paths are ignored entirely (neither TP nor FP).
    # Useful for huge repos where only one subdirectory has ground truth.
    scope_paths: list[str] = Field(default_factory=list)
    match_policy: dict[str, Any] | None = Field(
        default=None, description="Per-case overrides on top of the dataset policy."
    )
    tags: list[str] = Field(default_factory=list)
    skip: bool = False
    skip_reason: str = ""


class Dataset(BaseModel):
    """A named collection of benchmark cases loaded from one YAML file."""

    name: str
    description: str = ""
    version: str = ""
    source_url: str = ""
    # Set false for datasets whose ground truth was auto-derived or estimated,
    # so the analysis document can flag results computed from it.
    verified: bool = True
    default_language: str = ""
    default_analyze_args: list[str] = Field(default_factory=list)
    match_policy: dict[str, Any] | None = None
    cases: list[BenchmarkCase] = Field(default_factory=list)

    def active_cases(self) -> list[BenchmarkCase]:
        return [c for c in self.cases if not c.skip]

    def ground_truth_count(self) -> int:
        return sum(len(c.expected) for c in self.active_cases())


class MatchSignals(BaseModel):
    """Per-signal scores explaining why a finding did (or didn't) match."""

    file: Optional[float] = None
    line: Optional[float] = None
    cwe: Optional[float] = None
    function: Optional[float] = None
    sink: Optional[float] = None

    def scored(self) -> dict[str, float]:
        return {k: v for k, v in self.model_dump().items() if v is not None}


class Match(BaseModel):
    """A finding paired with the ground-truth entry it satisfies."""

    ground_truth_id: str
    finding_id: str
    score: float
    signals: MatchSignals = Field(default_factory=MatchSignals)
    finding_summary: str = ""
    ground_truth_summary: str = ""
    # Denormalized off the ground truth so per-CWE / per-category aggregation
    # doesn't have to reload the dataset that produced the run.
    ground_truth_cwe: str = ""
    ground_truth_category: str = ""
    finding_cwe: str = ""
    line_delta: Optional[int] = None


class UnmatchedFinding(BaseModel):
    """A reported finding with no ground truth behind it: a false positive."""

    finding_id: str
    file: str
    start_line: int
    cwe: str = ""
    vulnerability_type: str = ""
    title: str = ""
    severity: str = ""
    confidence: str = ""
    # Best score it achieved against any ground-truth entry, for triage:
    # a near-miss (0.4) is a matching problem, a 0.0 is a genuine FP.
    best_score: float = 0.0


class MissedGroundTruth(BaseModel):
    """A ground-truth entry nothing matched: a false negative."""

    ground_truth_id: str
    cwe: str = ""
    file: str = ""
    start_line: Optional[int] = None
    category: str = ""
    description: str = ""
    best_score: float = 0.0
    best_candidate_finding_id: str = ""


class Metrics(BaseModel):
    """Confusion-matrix counts and the rates derived from them."""

    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def as_row(self) -> dict[str, float | int]:
        return {
            "tp": self.true_positives,
            "fp": self.false_positives,
            "fn": self.false_negatives,
            "tn": self.true_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
        }

    def __add__(self, other: "Metrics") -> "Metrics":
        return Metrics(
            true_positives=self.true_positives + other.true_positives,
            false_positives=self.false_positives + other.false_positives,
            false_negatives=self.false_negatives + other.false_negatives,
            true_negatives=self.true_negatives + other.true_negatives,
        )


class CaseResult(BaseModel):
    """Everything the benchmark learned from scanning one case."""

    case_id: str
    dataset: str
    repo: str
    label: CaseLabel = CaseLabel.VULNERABLE
    status: str = "ok"  # "ok" | "error" | "skipped"
    error: str = ""

    metrics: Metrics = Field(default_factory=Metrics)
    matches: list[Match] = Field(default_factory=list)
    false_positives: list[UnmatchedFinding] = Field(default_factory=list)
    false_negatives: list[MissedGroundTruth] = Field(default_factory=list)

    findings_reported: int = 0
    ground_truth_total: int = 0

    # Performance. `duration_seconds` is end-to-end for the case (including
    # process startup), `stage_timings` is the pipeline's own breakdown.
    duration_seconds: float = 0.0
    stage_timings: dict[str, float] = Field(default_factory=dict)
    peak_memory_mb: float = 0.0
    llm_calls: int = 0
    contexts_analyzed: int = 0

    # Where the raw cpgvd report for this case was archived.
    raw_report_path: str = ""

    def seconds_per_finding(self) -> float:
        return self.duration_seconds / self.findings_reported if self.findings_reported else 0.0


class RunMetadata(BaseModel):
    """Reproducibility record: what was run, with what, against what."""

    run_id: str
    label: str = ""
    created_at: _dt.datetime = Field(default_factory=lambda: _dt.datetime.now(_dt.timezone.utc))
    datasets: list[str] = Field(default_factory=list)
    runner: str = "cpgvd"
    provider: str = ""
    model: str = ""
    cpgvd_version: str = ""
    git_commit: str = ""
    git_dirty: bool = False
    command: str = ""
    match_policy: MatchPolicy = Field(default_factory=MatchPolicy)
    notes: str = ""
    # True when case results did not come from a live scan (e.g. replayed
    # from archived reports or fixtures). Reports surface this prominently so
    # a demonstration run is never mistaken for a measured one.
    synthetic: bool = False


class RunResult(BaseModel):
    """A complete benchmark run: metadata + per-case results + aggregates."""

    metadata: RunMetadata
    cases: list[CaseResult] = Field(default_factory=list)

    def ok_cases(self) -> list[CaseResult]:
        return [c for c in self.cases if c.status == "ok"]

    def overall_metrics(self) -> Metrics:
        total = Metrics()
        for case in self.ok_cases():
            total = total + case.metrics
        return total

    def metrics_by_cwe(self) -> dict[str, Metrics]:
        """Confusion counts bucketed by CWE id.

        TPs and FNs are attributed to the ground-truth CWE; FPs to the CWE
        the finding claimed. That asymmetry is intentional -- an FP's CWE is
        the only class information it has.
        """
        buckets: dict[str, Metrics] = {}

        def bucket(cwe: str) -> Metrics:
            key = normalize_cwe(cwe) or "unspecified"
            return buckets.setdefault(key, Metrics())

        for case in self.ok_cases():
            for match in case.matches:
                bucket(match.ground_truth_cwe).true_positives += 1
            for fn in case.false_negatives:
                bucket(fn.cwe).false_negatives += 1
            for fp in case.false_positives:
                bucket(fp.cwe).false_positives += 1
        return buckets

    def total_duration(self) -> float:
        return sum(c.duration_seconds for c in self.cases)

    def stage_totals(self) -> dict[str, float]:
        totals: dict[str, float] = {}
        for case in self.cases:
            for stage, seconds in case.stage_timings.items():
                totals[stage] = totals.get(stage, 0.0) + seconds
        return totals


def normalize_cwe(value: str) -> str:
    """Reduce a free-form CWE string to a bare `CWE-79`-style id.

    Models write the field inconsistently ("CWE-79", "cwe 79",
    "CWE-79: Cross-site Scripting"), and ground truth from imported suites
    uses its own conventions; comparing raw strings would under-count
    agreement badly.
    """
    import re

    match = re.search(r"cwe[-_\s]?(\d+)", value or "", re.IGNORECASE)
    return f"CWE-{match.group(1)}" if match else ""
