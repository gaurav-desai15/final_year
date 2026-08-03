"""Interactive dashboard for browsing benchmark runs.

Launch it directly -- it re-execs itself under Streamlit if needed:

    python -m benchmark.dashboard
    python -m benchmark.dashboard --run baseline
    streamlit run benchmark/dashboard.py            # equivalent

Reads only the archived runs under `benchmark/results/`, so it never scans
anything, never calls Joern or an LLM, and is safe to poke at while a real
benchmark is running.

Charting notes (the parts that are decisions, not taste):

* **TP/FP/FN use the categorical palette, not green/amber/red.** The obvious
  encoding is status colors -- green for true positives, red for false
  negatives -- and it fails: green `#0ca30c` against red `#d03b3b` measures
  ΔE 4.1 under deuteranopia simulation, well under the ≥8 gate, so the two
  most important bars on the page would be indistinguishable to a red-green
  colorblind reader. The blue/orange/aqua categorical slots measure ΔE 9.2
  (light) / 9.4 (dark) and are used instead.
* **One palette, fixed slot order, assigned per chart.** Colors follow the
  entity, so filtering a chart never repaints the survivors.
* **Both themes are selected, not flipped.** The dark values are the same
  hues re-stepped for the dark surface and validated against it.
* Every chart has a table-view twin in an expander, so no value is reachable
  only by hovering a colored mark.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import altair as alt
import pandas as pd
import streamlit as st

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from benchmark import metrics as M  # noqa: E402
from benchmark.models import Metrics, RunResult  # noqa: E402
from benchmark.storage import RESULTS_DIR, list_runs  # noqa: E402

from cpgvd.ui_theme import (  # noqa: E402
    banner,
    colors,
    inject_css,
    meta_row,
    page_header,
    rule,
    stat_tiles,
    style_chart as style,
    theme_mode,
)

# Fixed slot assignment. TP/FP/FN keep these hues on every chart in the app.
OUTCOME_ORDER = ["True positives", "False positives", "False negatives"]
RATE_ORDER = ["Precision", "Recall", "F1"]


# --------------------------------------------------------------------------
# Data loading
# --------------------------------------------------------------------------


@st.cache_data(show_spinner=False)
def _load_run_json(path: str, mtime: float) -> dict:
    # mtime is in the cache key so a re-run of the benchmark invalidates it.
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_run(directory: Path) -> RunResult:
    path = directory / "run.json"
    return RunResult.model_validate(_load_run_json(str(path), path.stat().st_mtime))


def available_runs(results_dir: Path) -> list[Path]:
    return list_runs(results_dir)


# --------------------------------------------------------------------------
# Dataframe builders (pure -- unit-tested in tests/test_benchmark_dashboard.py)
# --------------------------------------------------------------------------


def outcome_dataframe(buckets: dict[str, Metrics], label: str = "Group") -> pd.DataFrame:
    """Long-form TP/FP/FN counts per bucket, for a stacked bar."""
    rows = []
    for name, m in buckets.items():
        rows.append({label: name, "Outcome": "True positives", "Count": m.true_positives})
        rows.append({label: name, "Outcome": "False positives", "Count": m.false_positives})
        rows.append({label: name, "Outcome": "False negatives", "Count": m.false_negatives})
    return pd.DataFrame(rows, columns=[label, "Outcome", "Count"])


def rate_dataframe(buckets: dict[str, Metrics], label: str = "Group") -> pd.DataFrame:
    """Precision/recall/F1 per bucket, plus the counts behind them.

    The counts ride along deliberately: a 100% precision built on one true
    positive should not look the same as one built on fifty, and the tooltip
    and table view are where that gets disclosed.
    """
    rows = []
    for name, m in buckets.items():
        rows.append({
            label: name,
            "Precision": round(m.precision, 4),
            "Recall": round(m.recall, 4),
            "F1": round(m.f1, 4),
            "TP": m.true_positives,
            "FP": m.false_positives,
            "FN": m.false_negatives,
            "Support": m.true_positives + m.false_negatives,
        })
    return pd.DataFrame(rows)


def stage_dataframe(run: RunResult) -> pd.DataFrame:
    breakdown = M.stage_breakdown(run)
    return pd.DataFrame([
        {
            "Stage": stage.replace("_", " "),
            "Total (s)": v["total_seconds"],
            "Mean (s)": v["mean_seconds"],
            "Share (%)": v["share_pct"],
        }
        for stage, v in breakdown.items()
    ])


def case_dataframe(run: RunResult) -> pd.DataFrame:
    rows = []
    for case in run.cases:
        m = case.metrics
        rows.append({
            "Case": case.case_id,
            "Dataset": case.dataset,
            "Status": case.status,
            "TP": m.true_positives,
            "FP": m.false_positives,
            "FN": m.false_negatives,
            "Precision": round(m.precision, 4),
            "Recall": round(m.recall, 4),
            "F1": round(m.f1, 4),
            "Runtime (s)": round(case.duration_seconds, 1),
            "Findings": case.findings_reported,
            "Ground truth": case.ground_truth_total,
        })
    return pd.DataFrame(rows)


def history_dataframe(runs: list[RunResult]) -> pd.DataFrame:
    """Precision/recall/F1 per run, oldest first, for the trend chart."""
    rows = []
    for run in sorted(runs, key=lambda r: r.metadata.created_at):
        m = M.overall(run)
        name = run.metadata.label or run.metadata.run_id
        for metric, value in (
            ("Precision", m.precision), ("Recall", m.recall), ("F1", m.f1)
        ):
            rows.append({
                "Run": name,
                "Order": run.metadata.created_at.isoformat(),
                "Metric": metric,
                "Value": round(value, 4),
                "Synthetic": run.metadata.synthetic,
            })
    return pd.DataFrame(rows, columns=["Run", "Order", "Metric", "Value", "Synthetic"])


def findings_dataframe(run: RunResult, kind: str) -> pd.DataFrame:
    """Flatten matches / false positives / false negatives across all cases."""
    rows: list[dict] = []
    for case in run.ok_cases():
        if kind == "tp":
            for m in case.matches:
                rows.append({
                    "Case": case.case_id, "Ground truth": m.ground_truth_id,
                    "CWE": m.ground_truth_cwe, "Category": m.ground_truth_category,
                    "Matched finding": m.finding_summary, "Score": m.score,
                    "Line delta": m.line_delta,
                })
        elif kind == "fp":
            for f in case.false_positives:
                rows.append({
                    "Case": case.case_id, "File": f"{f.file}:{f.start_line}",
                    "CWE": f.cwe, "Type": f.vulnerability_type, "Title": f.title,
                    "Severity": f.severity, "Confidence": f.confidence,
                    "Best score": f.best_score,
                })
        else:
            for f in case.false_negatives:
                rows.append({
                    "Case": case.case_id, "Ground truth": f.ground_truth_id,
                    "CWE": f.cwe, "Category": f.category,
                    "Location": f"{f.file}:{f.start_line or '?'}",
                    "Best score": f.best_score,
                    "Description": (f.description or "")[:160],
                })
    return pd.DataFrame(rows)


def comparison_dataframe(baseline: RunResult, candidate: RunResult) -> pd.DataFrame:
    """Signed metric deltas between two runs, for a diverging bar."""
    b, c = M.overall(baseline), M.overall(candidate)
    b_rt, c_rt = M.runtime_stats(baseline), M.runtime_stats(candidate)
    rows = [
        {"Metric": "Precision", "Baseline": b.precision, "Candidate": c.precision,
         "Delta": c.precision - b.precision, "Higher is better": True},
        {"Metric": "Recall", "Baseline": b.recall, "Candidate": c.recall,
         "Delta": c.recall - b.recall, "Higher is better": True},
        {"Metric": "F1", "Baseline": b.f1, "Candidate": c.f1,
         "Delta": c.f1 - b.f1, "Higher is better": True},
    ]
    counts = [
        ("True positives", b.true_positives, c.true_positives, True),
        ("False positives", b.false_positives, c.false_positives, False),
        ("False negatives", b.false_negatives, c.false_negatives, False),
        ("Total runtime (s)", b_rt["total_seconds"], c_rt["total_seconds"], False),
    ]
    for name, before, after, higher_better in counts:
        rows.append({"Metric": name, "Baseline": before, "Candidate": after,
                     "Delta": after - before, "Higher is better": higher_better})
    df = pd.DataFrame(rows)

    # An improvement is a rise in a good metric or a fall in a bad one. The
    # sign of Delta alone can't say which, so resolve it here rather than in
    # the chart -- fewer false positives is a good outcome with a negative
    # delta. Built as object dtype because an unchanged metric is None, which
    # a bool column can't hold.
    def _improved(row: pd.Series) -> bool | None:
        if row["Delta"] == 0:
            return None
        return bool((row["Delta"] > 0) == row["Higher is better"])

    df["Improvement"] = df.apply(_improved, axis=1).astype(object)
    return df


def detection_diff(baseline: RunResult, candidate: RunResult) -> tuple[list[str], list[str]]:
    """(newly detected, newly missed) ground-truth ids between two runs."""
    b = {m.ground_truth_id for c in baseline.ok_cases() for m in c.matches}
    c = {m.ground_truth_id for c_ in candidate.ok_cases() for m in c_.matches}
    return sorted(c - b), sorted(b - c)


# --------------------------------------------------------------------------
# Charts
# --------------------------------------------------------------------------


def _integer_ticks(maximum: int, target: int = 8) -> list[int]:
    """Whole-number tick positions up to `maximum`, at most ~`target` of them."""
    maximum = max(1, int(maximum))
    step = max(1, -(-maximum // target))
    return list(range(0, maximum + 1, step))


def outcome_chart(df: pd.DataFrame, label: str) -> alt.Chart:
    """Horizontal stacked bar of TP/FP/FN per group.

    Horizontal because CWE ids and category names are long, and stacked
    because the three outcomes together are the total evidence for that
    group -- the width tells you how much the number rests on.
    """
    c = colors()
    return alt.Chart(df).mark_bar(
        cornerRadiusEnd=4,
        # 2px surface gap between segments instead of a stroke around them.
        stroke=c["surface"], strokeWidth=2,
    ).encode(
        y=alt.Y(f"{label}:N", title=None, sort="-x"),
        # Counts are whole numbers. Naming the tick positions outright avoids
        # both the fractional ticks a continuous scale defaults to and the
        # duplicate labels ("0, 1, 1, 2, 2") that format="d" produces when Vega
        # places half-steps.
        x=alt.X("Count:Q", title="Count", stack=True,
                axis=alt.Axis(format="d", values=_integer_ticks(
                    int(df.groupby(label)["Count"].sum().max() or 1)))),
        color=alt.Color(
            "Outcome:N",
            title=None,
            scale=alt.Scale(domain=OUTCOME_ORDER, range=c["series"]),
            legend=alt.Legend(orient="top", direction="horizontal"),
        ),
        order=alt.Order("color_Outcome_sort_index:Q"),
        tooltip=[label, "Outcome", "Count"],
    ).properties(height=alt.Step(28))


def rate_chart(df: pd.DataFrame, label: str) -> alt.Chart:
    """Grouped bar of precision/recall/F1 per group."""
    c = colors()
    long = df.melt(
        id_vars=[label, "TP", "FP", "FN", "Support"],
        value_vars=RATE_ORDER, var_name="Metric", value_name="Value",
    )
    return alt.Chart(long).mark_bar(cornerRadiusEnd=4).encode(
        y=alt.Y(f"{label}:N", title=None, sort="-x"),
        x=alt.X("Value:Q", title=None, scale=alt.Scale(domain=[0, 1]),
                axis=alt.Axis(format="%")),
        yOffset=alt.YOffset("Metric:N", sort=RATE_ORDER),
        color=alt.Color(
            "Metric:N", title=None,
            scale=alt.Scale(domain=RATE_ORDER, range=c["series"]),
            legend=alt.Legend(orient="top", direction="horizontal"),
        ),
        tooltip=[label, "Metric", alt.Tooltip("Value:Q", format=".1%"),
                 "TP", "FP", "FN", "Support"],
    ).properties(height=alt.Step(16))


def stage_chart(df: pd.DataFrame) -> alt.Chart:
    """Where the time goes. One series, so one color -- a value ramp here
    would double-encode bar length as hue and tell you nothing new."""
    c = colors()
    return alt.Chart(df).mark_bar(cornerRadiusEnd=4, color=c["series"][0]).encode(
        y=alt.Y("Stage:N", title=None, sort="-x"),
        x=alt.X("Total (s):Q", title="Seconds across all cases"),
        tooltip=["Stage", "Total (s)", "Mean (s)", "Share (%)"],
    ).properties(height=alt.Step(26))


def history_chart(df: pd.DataFrame) -> alt.LayerChart:
    """Precision/recall/F1 across runs, with the endpoint directly labeled."""
    c = colors()
    scale = alt.Scale(domain=RATE_ORDER, range=c["series"])
    base = alt.Chart(df).encode(
        x=alt.X("Run:N", title=None, sort=alt.SortField("Order"),
                axis=alt.Axis(labelAngle=-30)),
        y=alt.Y("Value:Q", title=None, scale=alt.Scale(domain=[0, 1]),
                axis=alt.Axis(format="%")),
        color=alt.Color("Metric:N", title=None, scale=scale,
                        legend=alt.Legend(orient="top", direction="horizontal")),
    )
    line = base.mark_line(strokeWidth=2, point=alt.OverlayMarkDef(size=80, filled=True))
    hover = base.mark_point(size=200, opacity=0).encode(
        tooltip=["Run", "Metric", alt.Tooltip("Value:Q", format=".1%"), "Synthetic"]
    )
    # Direct-label only the last run, not every point.
    last = df["Order"].max() if not df.empty else None
    labels = base.transform_filter(alt.datum.Order == last).mark_text(
        align="left", dx=8, fontSize=11
    ).encode(text=alt.Text("Value:Q", format=".0%"))
    return alt.layer(line, hover, labels)


def delta_chart(df: pd.DataFrame) -> alt.Chart:
    """Diverging bar of metric changes, centered on zero.

    Only the three rate metrics are plotted -- counts and runtime live on
    different scales, and putting them on one axis would be the dual-axis
    mistake wearing a different hat. They're in the table below.
    """
    c = colors()
    rates = df[df["Metric"].isin(RATE_ORDER)].copy()
    rates["Direction"] = rates["Improvement"].map(
        {True: "Improvement", False: "Regression"}
    ).fillna("No change")
    return alt.Chart(rates).mark_bar(cornerRadiusEnd=4).encode(
        y=alt.Y("Metric:N", title=None, sort=RATE_ORDER),
        x=alt.X("Delta:Q", title="Change vs baseline (percentage points)",
                axis=alt.Axis(format="+.0%")),
        color=alt.Color(
            "Direction:N", title=None,
            scale=alt.Scale(
                domain=["Improvement", "Regression", "No change"],
                range=[c["positive"], c["negative"], c["muted"]],
            ),
            legend=alt.Legend(orient="top", direction="horizontal"),
        ),
        tooltip=["Metric", alt.Tooltip("Baseline:Q", format=".1%"),
                 alt.Tooltip("Candidate:Q", format=".1%"),
                 alt.Tooltip("Delta:Q", format="+.1%")],
    ).properties(height=alt.Step(34))


def _table_view(df: pd.DataFrame, caption: str = "Table view") -> None:
    """Every chart gets one: no value reachable only by hovering a mark."""
    with st.expander(caption):
        st.dataframe(df, width="stretch", hide_index=True)


def _chart_card(
    title: str,
    caption: str,
    chart: alt.Chart | alt.LayerChart,
    table: pd.DataFrame,
    table_caption: str = "Table view",
) -> None:
    """A chart in a bordered card, with its title, note and table-view twin."""
    with st.container(border=True):
        st.markdown(f"### {title}")
        if caption:
            st.caption(caption)
        st.altair_chart(style(chart), width="stretch")
        _table_view(table, table_caption)


# --------------------------------------------------------------------------
# App
# --------------------------------------------------------------------------


def _sidebar(results_dir: Path) -> tuple[RunResult | None, list[RunResult]]:
    with st.sidebar:
        st.header("Benchmark runs")

        directories = available_runs(results_dir)

        if not directories:
            st.warning("No archived runs found. Record one with `python -m benchmark.run`.")
            return None, []

        names = [p.name for p in directories]
        selected = st.selectbox("Run", names, index=0,
                                help="Newest first. Each run is an immutable archive.")
        run = load_run(results_dir / selected)

        history: list[RunResult] = []
        for directory in directories:
            try:
                history.append(load_run(directory))
            except Exception:  # noqa: BLE001 - a corrupt archive shouldn't blank the app
                continue

        rule()
        meta = run.metadata
        pairs = [
            ("Label", meta.label or "—"),
            ("Model", meta.model or "n/a"),
            ("Runner", meta.runner),
            ("Commit", (meta.git_commit[:12] or "unknown") + (" ⚠ dirty" if meta.git_dirty else "")),
            ("Cases", f"{len(run.ok_cases())}/{len(run.cases)}"),
        ]
        st.markdown(
            '<div class="cp-kv">'
            + "<br>".join(
                f'<span class="k">{k}</span> &nbsp;<span class="v">{v}</span>'
                for k, v in pairs
            )
            + "</div>",
            unsafe_allow_html=True,
        )
        if meta.notes:
            st.caption(meta.notes)

    return run, history


def _overview_tab(run: RunResult) -> None:
    overall = M.overall(run)
    total_gt = sum(c.ground_truth_total for c in run.ok_cases())

    stat_tiles([
        {"label": "F1 score", "value": f"{overall.f1:.3f}", "accent": True,
         "note": "harmonic mean of precision and recall"},
        {"label": "Precision", "value": f"{overall.precision:.1%}",
         "note": f"{overall.true_positives} of "
                 f"{overall.true_positives + overall.false_positives} reported"},
        {"label": "Recall", "value": f"{overall.recall:.1%}",
         "note": f"{overall.true_positives} of "
                 f"{overall.true_positives + overall.false_negatives} real"},
    ], hero_first=True)

    stat_tiles([
        {"label": "True positives", "value": overall.true_positives},
        {"label": "False positives", "value": overall.false_positives},
        {"label": "False negatives", "value": overall.false_negatives},
        {"label": "True negatives", "value": overall.true_negatives},
        {"label": "Ground truth", "value": total_gt},
    ])

    if total_gt < 20:
        banner(
            f"{total_gt} ground-truth entries. Precision and recall move in large "
            "jumps at this size — read this as a smoke test, not a performance "
            "measurement. Import an OWASP Benchmark or Juliet subset "
            "(<code>benchmark/scripts/</code>) for numbers worth citing.",
            kind="info", title="Small sample.",
        )

    by_dataset = M.by_dataset(run)
    if len(by_dataset) > 1:
        df = outcome_dataframe(by_dataset, "Dataset")
        _chart_card("Outcomes by dataset", "", outcome_chart(df, "Dataset"),
                    rate_dataframe(by_dataset, "Dataset"), "Table view — per dataset")

    with st.container(border=True):
        st.markdown("### Per case")
        st.dataframe(case_dataframe(run), width="stretch", hide_index=True)


def _classes_tab(run: RunResult) -> None:
    by_cwe = M.by_cwe(run)
    if not by_cwe:
        st.info("No per-CWE data in this run.")
        return

    df = outcome_dataframe(by_cwe, "CWE")
    _chart_card(
        "Outcomes by CWE",
        "Bar width is the total evidence for that class — a precision figure "
        "resting on two entries and one resting on fifty look very different here.",
        outcome_chart(df, "CWE"), df, "Table view — outcome counts",
    )

    rates = rate_dataframe(by_cwe, "CWE")
    _chart_card(
        "Precision / recall by CWE",
        "Support (TP + FN) is in the tooltip and table — a perfect score on two "
        "entries is not the same result as a perfect score on fifty.",
        rate_chart(rates, "CWE"), rates, "Table view — rates and support",
    )

    by_category = M.by_category(run)
    if by_category:
        cat_df = outcome_dataframe(by_category, "Category")
        _chart_card(
            "Outcomes by vulnerability category", "",
            outcome_chart(cat_df, "Category"), cat_df, "Table view — categories",
        )

    fns = M.common_false_negatives(run)
    if fns:
        st.subheader("Most-missed classes")
        st.caption(
            f"Top miss: **{fns[0][0]}** ({fns[0][1]}). Check whether "
            "`rules/sinks_sources.yaml` covers that sink at all — an unmatched "
            "sink is invisible to the LLM regardless of model quality."
        )
        st.dataframe(
            pd.DataFrame(fns, columns=["Missed class", "Count"]),
            width="stretch", hide_index=True,
        )


def _performance_tab(run: RunResult) -> None:
    runtime = M.runtime_stats(run)
    latency = M.detection_latency(run)

    stat_tiles([
        {"label": "Total runtime", "value": f"{runtime['total_seconds']:.0f}s", "accent": True},
        {"label": "Median per case", "value": f"{runtime['median_seconds']:.1f}s"},
        {"label": "Per finding", "value": f"{runtime['seconds_per_finding']:.1f}s"},
        {"label": "LLM per context", "value": f"{latency['llm_seconds_per_context']:.1f}s"},
        {"label": "Contexts analysed", "value": latency["contexts_analyzed"]},
    ])

    stages = stage_dataframe(run)
    if stages.empty:
        st.info(
            "No stage timings in this run. They come from the pipeline "
            "instrumentation — re-run with a current cpgvd to populate them."
        )
    else:
        top = stages.iloc[0]
        _chart_card(
            "Where the time goes",
            f"**{top['Stage']}** dominates at {top['Share (%)']}% of total. "
            "Performance work anywhere else can't move the total much.",
            stage_chart(stages), stages, "Table view — stage timings",
        )

    memory = M.memory_stats(run)
    if memory:
        st.caption(
            f"Peak RSS {memory['peak_mb']} MB (mean {memory['mean_peak_mb']} MB "
            f"across {memory['cases_measured']} case(s))."
        )

    st.subheader("Runtime per case")
    cases = case_dataframe(run).sort_values("Runtime (s)", ascending=False)
    st.dataframe(
        cases[["Case", "Runtime (s)", "Findings", "Ground truth", "F1"]],
        width="stretch", hide_index=True,
    )


def _history_tab(history: list[RunResult]) -> None:
    if len(history) < 2:
        st.info(
            "Only one run archived. Record another with a different `--label` "
            "to see a trend."
        )
        return

    df = history_dataframe(history)
    _chart_card(
        "Metrics across runs",
        "Only the latest run is labelled directly; hover any point for its exact value.",
        history_chart(df),
        df.pivot_table(index="Run", columns="Metric", values="Value").reset_index(),
        "Table view — history",
    )

    if df["Synthetic"].any():
        banner(
            "Some runs shown are <strong>synthetic</strong> (replayed from fixtures, "
            "not measured). They demonstrate the tooling and are not valid results.",
            kind="warn", title="⚠ Mixed history.",
        )


def _compare_tab(history: list[RunResult]) -> None:
    if len(history) < 2:
        st.info("Need at least two archived runs to compare.")
        return

    names = [r.metadata.label or r.metadata.run_id for r in history]
    cols = st.columns(2)
    baseline_idx = cols[0].selectbox("Baseline", range(len(names)),
                                     format_func=lambda i: names[i],
                                     index=len(names) - 1)
    candidate_idx = cols[1].selectbox("Candidate", range(len(names)),
                                      format_func=lambda i: names[i], index=0)
    if baseline_idx == candidate_idx:
        st.info("Pick two different runs.")
        return

    baseline, candidate = history[baseline_idx], history[candidate_idx]
    df = comparison_dataframe(baseline, candidate)

    _chart_card(
        "Change vs baseline",
        "Rates only — counts and runtime live on different scales, and plotting "
        "them on one axis would be the dual-axis mistake in disguise. They are "
        "in the table below.",
        delta_chart(df), df.drop(columns=["Higher is better"]),
        "Table view — all deltas",
    )

    detected, missed = detection_diff(baseline, candidate)
    cols = st.columns(2)
    with cols[0]:
        st.markdown("**Newly detected**")
        st.dataframe(pd.DataFrame({"Ground truth": detected or ["—"]}),
                     width="stretch", hide_index=True)
    with cols[1]:
        st.markdown("**Newly missed (regressions)**")
        st.dataframe(pd.DataFrame({"Ground truth": missed or ["—"]}),
                     width="stretch", hide_index=True)

    if detected or missed:
        st.caption(
            "This id-level diff is the part an aggregate F1 hides: a change can "
            "leave F1 flat while swapping *which* vulnerabilities it catches."
        )


def _details_tab(run: RunResult) -> None:
    tp = findings_dataframe(run, "tp")
    fp = findings_dataframe(run, "fp")
    fn = findings_dataframe(run, "fn")

    search = st.text_input("Filter (matches any column)", "")

    def _filter(df: pd.DataFrame) -> pd.DataFrame:
        if not search or df.empty:
            return df
        mask = df.astype(str).apply(
            lambda col: col.str.contains(search, case=False, na=False)
        ).any(axis=1)
        return df[mask]

    st.subheader(f"True positives ({len(tp)})")
    st.dataframe(_filter(tp), width="stretch", hide_index=True)

    st.subheader(f"False positives ({len(fp)})")
    if not fp.empty:
        st.caption(
            "`Best score` is how close each came to matching some ground truth. "
            "A high value is a near-miss worth checking against the matcher; a "
            "0.0 is an unambiguous false positive."
        )
    st.dataframe(_filter(fp), width="stretch", hide_index=True)

    st.subheader(f"False negatives ({len(fn)})")
    near = M.near_miss_false_negatives(run)
    if near:
        st.caption(
            f"{len(near)} miss(es) scored close to the match threshold — usually a "
            "*matching* problem (CWE label or line drift), not a detection failure. "
            "Triage those before tuning the detector."
        )
    st.dataframe(_filter(fn), width="stretch", hide_index=True)

    for name, df in (("true_positives", tp), ("false_positives", fp), ("false_negatives", fn)):
        if not df.empty:
            st.download_button(
                f"Download {name}.csv", df.to_csv(index=False),
                file_name=f"{run.metadata.run_id}_{name}.csv", mime="text/csv",
            )


def main() -> None:
    st.set_page_config(
        page_title="cpgvd · benchmark", page_icon="📊", layout="wide",
        initial_sidebar_state="expanded",
    )
    inject_css()

    results_dir = Path(st.query_params.get("results_dir", str(RESULTS_DIR)))
    run, history = _sidebar(results_dir)
    if run is None:
        st.stop()

    meta = run.metadata
    page_header(
        "Benchmark results",
        subtitle="Measured detection quality for cpgvd, scored against known ground truth.",
        eyebrow="cpgvd evaluation",
    )
    meta_row([
        ("Run", meta.run_id),
        ("Datasets", ", ".join(meta.datasets) or "—"),
        ("Cases", f"{len(run.ok_cases())}/{len(run.cases)}"),
        ("Generated", meta.created_at.strftime("%Y-%m-%d %H:%M UTC")),
    ])

    if meta.synthetic:
        banner(
            "These results were replayed from fixtures or archived reports rather "
            "than produced by a live scan. They demonstrate that the framework "
            "works and must not be cited as cpgvd's detection quality. Run the "
            "suite with Joern and an LLM backend for real figures.",
            kind="bad", title="⚠ Synthetic run — not a measurement.",
        )

    failed = [c for c in run.cases if c.status == "error"]
    if failed:
        banner(
            f"{len(failed)} case(s) failed to scan and are excluded from every "
            "metric: " + ", ".join(f"<code>{c.case_id}</code>" for c in failed),
            kind="warn", title="Incomplete run.",
        )

    tabs = st.tabs(["Overview", "Vulnerability classes", "Performance",
                    "History", "Compare", "Details"])
    with tabs[0]:
        _overview_tab(run)
    with tabs[1]:
        _classes_tab(run)
    with tabs[2]:
        _performance_tab(run)
    with tabs[3]:
        _history_tab(history)
    with tabs[4]:
        _compare_tab(history)
    with tabs[5]:
        _details_tab(run)


def _relaunch_under_streamlit() -> int:
    """Re-exec this file via `streamlit run` when invoked as a plain script.

    Lets `python -m benchmark.dashboard` work the way people expect, instead
    of printing Streamlit's "missing ScriptRunContext" warnings and rendering
    nothing.
    """
    import shutil
    import subprocess

    if shutil.which("streamlit") is None:
        print(
            'error: streamlit is not installed. Run: pip install -e ".[dashboard]"',
            file=sys.stderr,
        )
        return 2
    cmd = [sys.executable, "-m", "streamlit", "run", str(Path(__file__).resolve())]
    extra = sys.argv[1:]
    if extra:
        cmd += ["--"] + extra
    return subprocess.run(cmd, check=False).returncode


def _running_under_streamlit() -> bool:
    try:
        from streamlit.runtime import exists

        return exists()
    except Exception:  # noqa: BLE001 - older/newer Streamlit internals
        return False


if __name__ == "__main__":
    if _running_under_streamlit():
        main()
    else:
        raise SystemExit(_relaunch_under_streamlit())
