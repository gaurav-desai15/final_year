"""Markdown renderers for benchmark output.

Three documents come out of here:

* `render_run_report` -- the summary written into every archived run.
* `render_comparison` / `render_multi_version_table` -- regression tracking
  and cross-version comparison.
* `render_analysis_document` -- the long-form `docs/RESULT_ANALYSIS.md`.

All tables are plain GitHub-flavoured Markdown so they paste into a
dissertation without conversion.
"""

from __future__ import annotations

from typing import Iterable, Sequence

from .. import metrics as M
from ..models import Metrics, RunResult

# Below this many ground-truth entries, rates are too noisy to read as
# performance; reports say so rather than printing a confident "100%".
SMALL_SAMPLE_THRESHOLD = 20


def _table(headers: Sequence[str], rows: Iterable[Sequence[object]], align: str = "") -> list[str]:
    """Render a Markdown table. `align` is one char per column: 'l', 'c', 'r'."""
    alignment = {
        "l": ":---", "c": ":---:", "r": "---:",
    }
    sep = [alignment.get(align[i] if i < len(align) else "l", ":---") for i in range(len(headers))]
    lines = ["| " + " | ".join(str(h) for h in headers) + " |", "|" + "|".join(sep) + "|"]
    body = ["| " + " | ".join(_cell(c) for c in row) + " |" for row in rows]
    if not body:
        body = ["| " + " | ".join("--" for _ in headers) + " |"]
    return lines + body + [""]


def _cell(value: object) -> str:
    if isinstance(value, float):
        return f"{value:.3f}" if 0 < abs(value) < 1000 else f"{value:.1f}"
    return str(value)


def _pct(value: float) -> str:
    return f"{100 * value:.1f}%"


def _metric_rows(buckets: dict[str, Metrics]) -> list[list[object]]:
    rows = []
    for name, m in sorted(buckets.items(), key=lambda kv: (-kv[1].true_positives, kv[0])):
        rows.append(
            [name, m.true_positives, m.false_positives, m.false_negatives,
             _pct(m.precision), _pct(m.recall), f"{m.f1:.3f}"]
        )
    return rows


def _synthetic_banner(run: RunResult) -> list[str]:
    if not run.metadata.synthetic:
        return []
    return [
        "> ⚠️ **Synthetic run — not a measurement.** These case results were not",
        "> produced by a live scan (they were replayed from fixtures or archived",
        "> reports). The numbers below demonstrate that the framework works; they",
        "> are **not** valid results for cpgvd's detection quality and must not be",
        "> cited as such. Run the suite on a machine with Joern and an LLM backend",
        "> to produce real figures.",
        "",
    ]


def _small_sample_note(total_gt: int) -> list[str]:
    if total_gt >= SMALL_SAMPLE_THRESHOLD:
        return []
    return [
        f"> ℹ️ **Small sample:** only {total_gt} ground-truth entries in this run. "
        "Precision/recall move in large jumps at this size and should be read as "
        "smoke-test signal, not as a performance measurement. Import a larger "
        "suite (OWASP Benchmark / Juliet) before drawing conclusions.",
        "",
    ]


# --------------------------------------------------------------------------
# Run report
# --------------------------------------------------------------------------


def render_run_report(run: RunResult) -> str:
    meta = run.metadata
    overall = M.overall(run)
    runtime = M.runtime_stats(run)
    total_gt = sum(c.ground_truth_total for c in run.ok_cases())

    lines: list[str] = [f"# Benchmark run `{meta.run_id}`", ""]
    lines += _synthetic_banner(run)

    lines += [
        "| Field | Value |",
        "|:---|:---|",
        f"| Label | {meta.label or '(none)'} |",
        f"| Created | {meta.created_at.isoformat()} |",
        f"| Datasets | {', '.join(meta.datasets) or '(none)'} |",
        f"| Runner | {meta.runner} |",
        f"| Provider / model | {meta.provider or 'n/a'} / {meta.model or 'n/a'} |",
        f"| cpgvd commit | `{meta.git_commit[:12] or 'unknown'}`{' (dirty)' if meta.git_dirty else ''} |",
        f"| Cases | {len(run.ok_cases())} ok / {len(run.cases)} total |",
        f"| Ground-truth entries | {total_gt} |",
        "",
    ]
    if meta.command:
        lines += ["Command:", "", "```", meta.command, "```", ""]

    lines += ["## Headline metrics", ""]
    lines += _small_sample_note(total_gt)
    lines += _table(
        ["Metric", "Value"],
        [
            ["True positives", overall.true_positives],
            ["False positives", overall.false_positives],
            ["False negatives", overall.false_negatives],
            ["True negatives", overall.true_negatives],
            ["**Precision**", _pct(overall.precision)],
            ["**Recall**", _pct(overall.recall)],
            ["**F1**", f"{overall.f1:.3f}"],
        ],
        align="lr",
    )

    lines += ["## Per-dataset", ""]
    lines += _table(
        ["Dataset", "TP", "FP", "FN", "Precision", "Recall", "F1"],
        _metric_rows(M.by_dataset(run)),
        align="lrrrrrr",
    )

    lines += ["## Per-case", ""]
    case_rows = []
    for case in run.cases:
        m = case.metrics
        case_rows.append([
            case.case_id,
            case.status,
            m.true_positives, m.false_positives, m.false_negatives,
            _pct(m.precision), _pct(m.recall),
            f"{case.duration_seconds:.1f}s",
        ])
    lines += _table(
        ["Case", "Status", "TP", "FP", "FN", "Precision", "Recall", "Runtime"],
        case_rows,
        align="llrrrrrr",
    )

    lines += ["## Per-CWE", ""]
    lines += _table(
        ["CWE", "TP", "FP", "FN", "Precision", "Recall", "F1"],
        _metric_rows(M.by_cwe(run)),
        align="lrrrrrr",
    )

    lines += ["## Runtime", ""]
    lines += _table(
        ["Metric", "Seconds"],
        [
            ["Total", runtime["total_seconds"]],
            ["Mean per case", runtime["mean_seconds"]],
            ["Median per case", runtime["median_seconds"]],
            ["Fastest case", runtime["min_seconds"]],
            ["Slowest case", runtime["max_seconds"]],
            ["Per finding", runtime["seconds_per_finding"]],
        ],
        align="lr",
    )

    breakdown = M.stage_breakdown(run)
    if breakdown:
        lines += ["### Stage breakdown", ""]
        lines += _table(
            ["Stage", "Total (s)", "Mean (s)", "Median (s)", "Share"],
            [
                [stage, v["total_seconds"], v["mean_seconds"], v["median_seconds"], f"{v['share_pct']}%"]
                for stage, v in breakdown.items()
            ],
            align="lrrrr",
        )

    memory = M.memory_stats(run)
    if memory:
        lines += [
            f"Peak memory across cases: **{memory['peak_mb']} MB** "
            f"(mean peak {memory['mean_peak_mb']} MB over {memory['cases_measured']} case(s)).",
            "",
        ]

    failed = [c for c in run.cases if c.status == "error"]
    if failed:
        lines += ["## Failed cases", ""]
        lines += _table(
            ["Case", "Error"],
            [[c.case_id, c.error.replace("\n", " ")[:200]] for c in failed],
        )

    return "\n".join(lines)


# --------------------------------------------------------------------------
# Comparison
# --------------------------------------------------------------------------


def _delta(
    new: float,
    old: float,
    *,
    as_pct: bool = True,
    higher_is_better: bool = True,
    integer: bool = False,
) -> str:
    """Render a signed change, colour-coded by whether it's an improvement.

    `as_pct` renders rates as percentage points (the honest unit for a
    precision change: 60%->100% is +40pp, not "+40%"). `integer` keeps
    counts free of misleading decimal places.
    """
    diff = new - old
    if abs(diff) < 1e-9:
        return "→ 0"
    arrow = "🟢" if (diff > 0) == higher_is_better else "🔴"
    if as_pct:
        formatted = f"{100 * diff:+.1f}pp"
    elif integer:
        formatted = f"{int(round(diff)):+d}"
    else:
        formatted = f"{diff:+.1f}"
    return f"{arrow} {formatted}"


def render_comparison(baseline: RunResult, candidate: RunResult) -> str:
    """Regression report between two archived runs."""
    b, c = M.overall(baseline), M.overall(candidate)
    b_rt, c_rt = M.runtime_stats(baseline), M.runtime_stats(candidate)

    lines = [
        f"# Benchmark comparison: `{candidate.metadata.run_id}` vs `{baseline.metadata.run_id}`",
        "",
        f"- **Baseline:** `{baseline.metadata.run_id}` "
        f"({baseline.metadata.label or 'unlabeled'}, {baseline.metadata.model or 'n/a'})",
        f"- **Candidate:** `{candidate.metadata.run_id}` "
        f"({candidate.metadata.label or 'unlabeled'}, {candidate.metadata.model or 'n/a'})",
        "",
    ]
    if baseline.metadata.synthetic or candidate.metadata.synthetic:
        lines += [
            "> ⚠️ One or both runs are **synthetic** (replayed, not measured). "
            "This comparison demonstrates the tooling only.",
            "",
        ]

    lines += ["## Metric deltas", ""]
    lines += _table(
        ["Metric", "Baseline", "Candidate", "Delta"],
        [
            ["Precision", _pct(b.precision), _pct(c.precision), _delta(c.precision, b.precision)],
            ["Recall", _pct(b.recall), _pct(c.recall), _delta(c.recall, b.recall)],
            ["F1", f"{b.f1:.3f}", f"{c.f1:.3f}", _delta(c.f1, b.f1, as_pct=False)],
            ["True positives", b.true_positives, c.true_positives,
             _delta(c.true_positives, b.true_positives, as_pct=False, integer=True)],
            ["False positives", b.false_positives, c.false_positives,
             _delta(c.false_positives, b.false_positives, as_pct=False,
                    higher_is_better=False, integer=True)],
            ["False negatives", b.false_negatives, c.false_negatives,
             _delta(c.false_negatives, b.false_negatives, as_pct=False,
                    higher_is_better=False, integer=True)],
        ],
        align="lrrr",
    )

    lines += ["## Runtime deltas", ""]
    lines += _table(
        ["Metric", "Baseline (s)", "Candidate (s)", "Delta"],
        [
            ["Total", b_rt["total_seconds"], c_rt["total_seconds"],
             _delta(c_rt["total_seconds"], b_rt["total_seconds"], as_pct=False, higher_is_better=False)],
            ["Mean per case", b_rt["mean_seconds"], c_rt["mean_seconds"],
             _delta(c_rt["mean_seconds"], b_rt["mean_seconds"], as_pct=False, higher_is_better=False)],
            ["Median per case", b_rt["median_seconds"], c_rt["median_seconds"],
             _delta(c_rt["median_seconds"], b_rt["median_seconds"], as_pct=False, higher_is_better=False)],
        ],
        align="lrrr",
    )

    # Detection-level diffs: which specific vulnerabilities changed status.
    b_found = _detected_ids(baseline)
    c_found = _detected_ids(candidate)
    newly_detected = sorted(c_found - b_found)
    newly_missed = sorted(b_found - c_found)

    lines += ["## Newly detected vulnerabilities", ""]
    lines += (
        _table(["Ground truth id"], [[i] for i in newly_detected])
        if newly_detected
        else ["_None._", ""]
    )

    lines += ["## Newly missed vulnerabilities (regressions)", ""]
    lines += (
        _table(["Ground truth id"], [[i] for i in newly_missed])
        if newly_missed
        else ["_None._", ""]
    )

    b_fps = _fp_labels(baseline)
    c_fps = _fp_labels(candidate)
    lines += ["## False-positive class changes", ""]
    fp_rows = []
    for label in sorted(set(b_fps) | set(c_fps)):
        before, after = b_fps.get(label, 0), c_fps.get(label, 0)
        if before != after:
            fp_rows.append([label, before, after, f"{after - before:+d}"])
    lines += _table(["FP class", "Baseline", "Candidate", "Delta"], fp_rows, align="lrrr")

    lines += ["## Per-case F1", ""]
    b_cases, c_cases = M.by_case(baseline), M.by_case(candidate)
    rows = []
    for case_id in sorted(set(b_cases) | set(c_cases)):
        bm, cm = b_cases.get(case_id, Metrics()), c_cases.get(case_id, Metrics())
        rows.append([case_id, f"{bm.f1:.3f}", f"{cm.f1:.3f}", _delta(cm.f1, bm.f1)])
    lines += _table(["Case", "Baseline F1", "Candidate F1", "Delta"], rows, align="lrrr")

    verdict = _verdict(b, c)
    lines += ["## Verdict", "", verdict, ""]
    return "\n".join(lines)


def _verdict(baseline: Metrics, candidate: Metrics) -> str:
    df1 = candidate.f1 - baseline.f1
    if abs(df1) < 0.005:
        return "**No material change** in F1 (< 0.005). Treat as neutral."
    if df1 > 0:
        return (
            f"**Improvement:** F1 {baseline.f1:.3f} → {candidate.f1:.3f} (+{df1:.3f}), "
            f"precision {_pct(baseline.precision)} → {_pct(candidate.precision)}, "
            f"recall {_pct(baseline.recall)} → {_pct(candidate.recall)}."
        )
    return (
        f"**Regression:** F1 {baseline.f1:.3f} → {candidate.f1:.3f} ({df1:.3f}), "
        f"precision {_pct(baseline.precision)} → {_pct(candidate.precision)}, "
        f"recall {_pct(baseline.recall)} → {_pct(candidate.recall)}."
    )


def _detected_ids(run: RunResult) -> set[str]:
    return {m.ground_truth_id for case in run.ok_cases() for m in case.matches}


def _fp_labels(run: RunResult) -> dict[str, int]:
    return dict(M.common_false_positives(run, limit=1000))


def render_multi_version_table(runs: list[RunResult]) -> str:
    """The cross-version table: one row per run, improvements highlighted.

    Version names come from each run's label, never a hardcoded list, so a new
    experiment appears here simply by being run with `--label`.
    """
    if not runs:
        return "# Model comparison\n\n_No runs to compare._\n"

    ordered = sorted(runs, key=lambda r: r.metadata.created_at)
    reference = M.overall(ordered[0])

    lines = [
        "# Model / version comparison",
        "",
        f"Baseline for deltas: **{ordered[0].metadata.label or ordered[0].metadata.run_id}** "
        f"(earliest run in this comparison).",
        "",
    ]

    rows = []
    for run in ordered:
        m = M.overall(run)
        rt = M.runtime_stats(run)
        name = run.metadata.label or run.metadata.run_id
        flag = " ⚠️synthetic" if run.metadata.synthetic else ""
        rows.append([
            f"{name}{flag}",
            run.metadata.model or "n/a",
            _pct(m.precision),
            _pct(m.recall),
            f"{m.f1:.3f}",
            f"{rt['total_seconds']:.0f}s",
            m.false_positives,
            m.false_negatives,
            _delta(m.f1, reference.f1, as_pct=False) if run is not ordered[0] else "—",
        ])

    lines += _table(
        ["Version", "Model", "Precision", "Recall", "F1", "Runtime", "FP", "FN", "ΔF1 vs base"],
        rows,
        align="llrrrrrrr",
    )

    best = max(ordered, key=lambda r: M.overall(r).f1)
    fastest = min(ordered, key=lambda r: M.runtime_stats(r)["total_seconds"] or float("inf"))
    lines += [
        "## Highlights",
        "",
        f"- **Best F1:** {best.metadata.label or best.metadata.run_id} "
        f"({M.overall(best).f1:.3f})",
        f"- **Fastest:** {fastest.metadata.label or fastest.metadata.run_id} "
        f"({M.runtime_stats(fastest)['total_seconds']:.0f}s total)",
        "",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Result analysis document
# --------------------------------------------------------------------------


def render_analysis_document(run: RunResult, history: list[RunResult] | None = None) -> str:
    """The long-form `docs/RESULT_ANALYSIS.md`, generated from a run."""
    meta = run.metadata
    overall = M.overall(run)
    runtime = M.runtime_stats(run)
    total_gt = sum(c.ground_truth_total for c in run.ok_cases())

    lines = [
        "# Result analysis",
        "",
        "_This document is generated by `python -m benchmark.analyze`. Do not edit_",
        "_by hand -- regenerate it after each benchmark run._",
        "",
        f"Source run: **`{meta.run_id}`** ({meta.label or 'unlabeled'}), "
        f"generated {meta.created_at.isoformat()}.",
        "",
    ]
    lines += _synthetic_banner(run)

    lines += ["## 1. Overall statistics", ""]
    lines += _small_sample_note(total_gt)
    lines += _table(
        ["Metric", "Value"],
        [
            ["Cases scanned", f"{len(run.ok_cases())} / {len(run.cases)}"],
            ["Ground-truth vulnerabilities", total_gt],
            ["Findings reported", sum(c.findings_reported for c in run.ok_cases())],
            ["True positives", overall.true_positives],
            ["False positives", overall.false_positives],
            ["False negatives", overall.false_negatives],
            ["True negatives", overall.true_negatives],
            ["Precision", _pct(overall.precision)],
            ["Recall", _pct(overall.recall)],
            ["F1", f"{overall.f1:.3f}"],
        ],
        align="lr",
    )

    lines += ["## 2. Per-project statistics", ""]
    rows = []
    for case in run.cases:
        m = case.metrics
        rows.append([
            case.case_id, case.repo[:60], case.label.value, case.status,
            m.true_positives, m.false_positives, m.false_negatives,
            _pct(m.precision), _pct(m.recall), f"{case.duration_seconds:.1f}s",
        ])
    lines += _table(
        ["Case", "Repo", "Label", "Status", "TP", "FP", "FN", "Precision", "Recall", "Runtime"],
        rows, align="lllrrrrrrr",
    )

    lines += ["## 3. Per-CWE statistics", ""]
    lines += _table(
        ["CWE", "TP", "FP", "FN", "Precision", "Recall", "F1"],
        _metric_rows(M.by_cwe(run)), align="lrrrrrr",
    )

    categories = M.by_category(run)
    if categories:
        lines += ["### By vulnerability category", ""]
        lines += _table(
            ["Category", "TP", "FP", "FN", "Precision", "Recall", "F1"],
            _metric_rows(categories), align="lrrrrrr",
        )

    lines += ["## 4. Most common false positives", ""]
    fps = M.common_false_positives(run)
    lines += (
        _table(["FP class (CWE / reported type)", "Count"], [[k, v] for k, v in fps], align="lr")
        if fps else ["_No false positives in this run._", ""]
    )
    if fps:
        lines += [
            "Each row is a recurring pattern the detector reports without ground",
            "truth behind it. The highest-count row is the best target for a",
            "prompt guardrail or a tightened sink rule.",
            "",
        ]

    lines += ["## 5. Most common false negatives", ""]
    fns = M.common_false_negatives(run)
    lines += (
        _table(["Missed class (CWE / category)", "Count"], [[k, v] for k, v in fns], align="lr")
        if fns else ["_No false negatives in this run._", ""]
    )

    near = M.near_miss_false_negatives(run)
    if near:
        lines += [
            "### Near-miss misses (matching, not detection)",
            "",
            "These ground-truth entries had a finding score close to the match",
            "threshold. They usually indicate a *matching* problem -- a CWE label",
            "mismatch or line drift beyond tolerance -- rather than a genuine",
            "detection failure, and should be triaged before tuning the detector.",
            "",
        ]
        lines += _table(
            ["Ground truth id", "Best score"], [[i, f"{s:.2f}"] for i, s in near], align="lr"
        )

    lines += ["## 6. Top missed vulnerability classes", ""]
    if fns:
        worst = fns[0]
        lines += [
            f"The most-missed class is **{worst[0]}** ({worst[1]} missed). "
            "Check whether `rules/sinks_sources.yaml` has a sink pattern covering "
            "it at all -- an unmatched sink is invisible to the LLM stage no "
            "matter how good the model is.",
            "",
        ]
    else:
        lines += ["_Nothing missed in this run._", ""]

    lines += ["## 7. Runtime and performance", ""]
    lines += _table(
        ["Metric", "Value"],
        [
            ["Total runtime", f"{runtime['total_seconds']:.1f}s"],
            ["Mean per case", f"{runtime['mean_seconds']:.1f}s"],
            ["Median per case", f"{runtime['median_seconds']:.1f}s"],
            ["Seconds per finding", f"{runtime['seconds_per_finding']:.2f}s"],
        ],
        align="lr",
    )

    latency = M.detection_latency(run)
    lines += ["### Detection latency", ""]
    lines += _table(
        ["Metric", "Value"],
        [
            ["Mean case latency", f"{latency['mean_case_latency_s']:.1f}s"],
            ["LLM seconds per context", f"{latency['llm_seconds_per_context']:.2f}s"],
            ["Contexts analyzed", latency["contexts_analyzed"]],
        ],
        align="lr",
    )

    breakdown = M.stage_breakdown(run)
    if breakdown:
        lines += ["### Stage breakdown", ""]
        lines += _table(
            ["Stage", "Total (s)", "Mean (s)", "Share"],
            [[s, v["total_seconds"], v["mean_seconds"], f"{v['share_pct']}%"]
             for s, v in breakdown.items()],
            align="lrrr",
        )

    slow, fast = M.slowest_cases(run), M.fastest_cases(run)
    if slow:
        lines += ["### Slowest cases", ""]
        lines += _table(
            ["Case", "Runtime", "Contexts", "Findings"],
            [[c.case_id, f"{c.duration_seconds:.1f}s", c.contexts_analyzed, c.findings_reported]
             for c in slow],
            align="lrrr",
        )
    if fast:
        lines += ["### Fastest cases", ""]
        lines += _table(
            ["Case", "Runtime", "Contexts", "Findings"],
            [[c.case_id, f"{c.duration_seconds:.1f}s", c.contexts_analyzed, c.findings_reported]
             for c in fast],
            align="lrrr",
        )

    memory = M.memory_stats(run)
    if memory:
        lines += [
            "### Memory",
            "",
            f"Peak RSS across cases: **{memory['peak_mb']} MB** "
            f"(mean {memory['mean_peak_mb']} MB, {memory['cases_measured']} case(s) measured).",
            "",
        ]

    lines += ["## 8. Detection distribution", ""]
    dist = M.detection_distribution(run)
    lines += _table(["Bucket", "Count"], [[k, v] for k, v in sorted(dist.items())], align="lr")

    if history:
        lines += ["## 9. History", ""]
        lines += _table(
            ["Run", "Label", "Precision", "Recall", "F1", "Runtime"],
            [
                [r.metadata.run_id, r.metadata.label or "—",
                 _pct(M.overall(r).precision), _pct(M.overall(r).recall),
                 f"{M.overall(r).f1:.3f}", f"{M.runtime_stats(r)['total_seconds']:.0f}s"]
                for r in sorted(history, key=lambda r: r.metadata.created_at)
            ],
            align="llrrrr",
        )

    lines += ["## 10. Recommendations", ""]
    lines += [f"- {rec}" for rec in _recommendations(run)]
    lines += [""]

    return "\n".join(lines)


def _recommendations(run: RunResult) -> list[str]:
    """Derive next-step suggestions from what the numbers actually show."""
    recs: list[str] = []
    overall = M.overall(run)
    total_gt = sum(c.ground_truth_total for c in run.ok_cases())

    if run.metadata.synthetic:
        recs.append(
            "**Produce a real baseline first.** This run is synthetic; every "
            "recommendation below is illustrative until the suite is scanned live."
        )

    if total_gt < SMALL_SAMPLE_THRESHOLD:
        recs.append(
            f"**Grow the benchmark.** {total_gt} ground-truth entries is too few to "
            "distinguish a real improvement from noise. Import an OWASP Benchmark or "
            "Juliet subset (`benchmark/scripts/`) to get into the hundreds."
        )

    if overall.false_positives > overall.true_positives and overall.true_positives:
        recs.append(
            f"**Precision is the bottleneck** ({overall.false_positives} FP vs "
            f"{overall.true_positives} TP). Target the top FP class in section 4 with "
            "a prompt guardrail or a narrower sink regex before touching recall."
        )
    elif overall.false_negatives > overall.true_positives and overall.false_negatives:
        recs.append(
            f"**Recall is the bottleneck** ({overall.false_negatives} FN vs "
            f"{overall.true_positives} TP). Check sink-rule coverage for the classes in "
            "section 6, then consider multi-hop dataflow for taint crossing 2+ frames."
        )

    near = M.near_miss_false_negatives(run)
    if near:
        recs.append(
            f"**{len(near)} miss(es) scored close to the match threshold.** Triage these "
            "as an evaluation issue first -- raising `line_tolerance` or relaxing CWE "
            "matching may recover them without any detector change."
        )

    breakdown = M.stage_breakdown(run)
    if breakdown:
        slowest_stage, stats = next(iter(breakdown.items()))
        if stats["share_pct"] > 50:
            recs.append(
                f"**`{slowest_stage}` dominates runtime** ({stats['share_pct']}% of total). "
                "Any performance work should start there; optimizing other stages cannot "
                "move the total much."
            )

    failed = [c for c in run.cases if c.status == "error"]
    if failed:
        recs.append(
            f"**{len(failed)} case(s) failed to scan** and are excluded from every metric. "
            "Fix those before comparing runs -- a case that silently drops out inflates "
            "whichever metric it was worst at."
        )

    if not recs:
        recs.append("No structural issues stand out in this run; extend the benchmark and re-measure.")
    return recs
