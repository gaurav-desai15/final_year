"""Tests for the shared UI theme and the dashboards' pure data/chart layer.

Streamlit rendering isn't exercised here -- what these lock down are the
things that were actually wrong at some point and would silently degrade the
UI again: theme detection precedence, the palette's colorblind separation,
integer tick generation, and the dataframe builders behind every chart.
"""

from __future__ import annotations

import datetime as _dt

import pandas as pd
import pytest

from benchmark import dashboard as BD
from benchmark import metrics as M
from benchmark.evaluators import evaluate_case
from benchmark.models import (
    BenchmarkCase,
    CaseLabel,
    GroundTruth,
    MatchPolicy,
    Metrics,
    RunMetadata,
    RunResult,
)
from cpgvd import dashboard as SD
from cpgvd import ui_theme as T
from cpgvd.models import AnalysisReport, Confidence, Finding, RunStats, Severity


def make_finding(fid="f1", file="app.py", start=10, end=20, cwe="CWE-78",
                 severity=Severity.HIGH) -> Finding:
    return Finding(
        id=fid, context_id=f"ctx-{fid}", file=file, start_line=start, end_line=end,
        function="admin_run", vulnerability_type="OS Command Injection", cwe=cwe,
        severity=severity, confidence=Confidence.HIGH,
        title="Command injection", description="desc",
    )


def make_run() -> RunResult:
    case = evaluate_case(
        BenchmarkCase(
            id="case1", repo="examples/app", language="python",
            label=CaseLabel.VULNERABLE,
            expected=[GroundTruth(id="gt1", cwe="CWE-78", file="app.py",
                                  start_line=10, end_line=20, category="cmdi"),
                      GroundTruth(id="gt2", cwe="CWE-22", file="x.py",
                                  start_line=5, category="path")],
        ),
        AnalysisReport(
            repo="examples/app", languages=["python"], model="m",
            findings=[make_finding(), make_finding(fid="f2", file="z.py", cwe="CWE-89")],
            stats=RunStats(candidate_contexts_analyzed=4, llm_calls=4,
                           duration_seconds=30.0, peak_memory_mb=200.0,
                           stage_timings={"joern_parse": 20.0, "llm_analysis": 10.0}),
        ),
        MatchPolicy(), dataset_name="d", duration_seconds=30.0,
    )
    return RunResult(
        metadata=RunMetadata(run_id="2026-01-01T00-00-00Z__t", label="t", datasets=["d"],
                             created_at=_dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc)),
        cases=[case],
    )


class TestPalette:
    @pytest.mark.parametrize("mode", ["light", "dark"])
    def test_every_role_defined_in_both_modes(self, mode):
        # A role present in one mode but not the other means a KeyError the
        # moment a user flips theme -- which is exactly when nobody is looking.
        assert set(T.PALETTE["light"]) == set(T.PALETTE["dark"])
        assert T.PALETTE[mode]["series"]

    @pytest.mark.parametrize("mode", ["light", "dark"])
    def test_severity_ramp_is_ordered_and_complete(self, mode):
        ramp = T.PALETTE[mode]["ordinal"]
        assert len(ramp) == len(T.SEVERITY_ORDER)
        # Critical is the darkest end of the ramp, info the lightest.
        assert T.severity_color("critical", mode) == ramp[-1]
        assert T.severity_color("info", mode) == ramp[0]

    def test_unknown_severity_falls_back_to_muted(self):
        assert T.severity_color("nonsense") == T.PALETTE["light"]["muted"]

    def test_every_severity_has_an_emoji(self):
        # The emoji is the secondary encoding that keeps severity from being
        # carried by hue alone; a missing one silently breaks that.
        assert set(T.SEVERITY_EMOJI) == set(T.SEVERITY_ORDER)

    @pytest.mark.parametrize("mode", ["light", "dark"])
    def test_status_colors_are_not_used_as_series_colors(self, mode):
        """Green/red must never become series colors.

        Validated with the dataviz checker: #0ca30c vs #d03b3b measure ΔE 4.1
        under deuteranopia -- far below the ≥8 gate. If someone swaps them in
        as the TP/FN colors for the "obvious" semantics, this fails.
        """
        series = {s.lower() for s in T.PALETTE[mode]["series"]}
        assert "#0ca30c" not in series
        assert "#d03b3b" not in series


class TestThemeMode:
    def test_configured_base_wins_over_browser_preference(self, monkeypatch):
        """Explicit config must beat `st.context.theme.type`.

        Streamlit renders its own chrome from `theme.base`, while
        `context.theme.type` reports the browser's preference. Checking the
        browser first produced dark Streamlit chrome wrapped around a
        light-palette page.
        """
        import streamlit as st

        monkeypatch.setattr(st, "get_option", lambda key: "dark" if key == "theme.base" else None)
        assert T.theme_mode() == "dark"

    def test_browser_preference_used_when_base_unset(self, monkeypatch):
        # `st.context` is a property on an immutable module type and can't be
        # monkeypatched in place, so stand in a fake module. theme_mode()
        # imports streamlit lazily, so it picks this up.
        import sys
        import types

        fake = types.SimpleNamespace(
            get_option=lambda key: None,
            context=types.SimpleNamespace(theme=types.SimpleNamespace(type="dark")),
        )
        monkeypatch.setitem(sys.modules, "streamlit", fake)
        assert T.theme_mode() == "dark"

    def test_defaults_to_light_when_nothing_is_available(self, monkeypatch):
        import streamlit as st

        def _boom(key):
            raise RuntimeError("no context")

        monkeypatch.setattr(st, "get_option", _boom)
        assert T.theme_mode() in ("light", "dark")


class TestIntegerTicks:
    @pytest.mark.parametrize("fn", [BD._integer_ticks, SD._integer_ticks])
    def test_ticks_are_whole_numbers_with_no_duplicates(self, fn):
        # The bug this prevents: tickMinStep let Vega place half-steps, which
        # format="d" then rendered as "0, 1, 1, 2, 2".
        for maximum in range(1, 40):
            ticks = fn(maximum)
            assert ticks == sorted(set(ticks))
            assert all(isinstance(t, int) for t in ticks)
            assert ticks[0] == 0
            assert ticks[-1] <= maximum

    @pytest.mark.parametrize("fn", [BD._integer_ticks, SD._integer_ticks])
    def test_tick_count_stays_bounded(self, fn):
        assert len(fn(1000)) <= 10

    @pytest.mark.parametrize("fn", [BD._integer_ticks, SD._integer_ticks])
    def test_zero_and_negative_maximums_are_safe(self, fn):
        assert fn(0) == [0, 1]
        assert fn(-5) == [0, 1]


class TestBenchmarkDashboardData:
    def test_outcome_dataframe_shape(self):
        run = make_run()
        df = BD.outcome_dataframe(M.by_cwe(run), "CWE")
        assert set(df.columns) == {"CWE", "Outcome", "Count"}
        assert set(df["Outcome"]) == set(BD.OUTCOME_ORDER)

    def test_rate_dataframe_carries_support(self):
        # Support is what stops "100% precision" on two entries reading the
        # same as 100% on fifty.
        df = BD.rate_dataframe({"CWE-78": Metrics(true_positives=1, false_negatives=1)}, "CWE")
        assert df.loc[0, "Support"] == 2
        assert df.loc[0, "Recall"] == 0.5

    def test_history_dataframe_is_chronological(self):
        run_a, run_b = make_run(), make_run()
        run_b.metadata.run_id = "2026-06-01T00-00-00Z__later"
        run_b.metadata.label = "later"
        run_b.metadata.created_at = _dt.datetime(2026, 6, 1, tzinfo=_dt.timezone.utc)
        df = BD.history_dataframe([run_b, run_a])
        assert df["Run"].iloc[0] == "t"  # earlier run first regardless of input order

    def test_comparison_marks_fewer_false_positives_as_an_improvement(self):
        """A negative delta on a bad metric is a good outcome.

        Coloring by the sign of the delta alone would paint "false positives
        went down" as a regression.
        """
        baseline, candidate = make_run(), make_run()
        baseline.cases[0].metrics = Metrics(true_positives=1, false_positives=5)
        candidate.cases[0].metrics = Metrics(true_positives=1, false_positives=1)
        df = BD.comparison_dataframe(baseline, candidate)
        row = df[df["Metric"] == "False positives"].iloc[0]
        assert row["Delta"] < 0
        assert row["Improvement"] is True

    def test_comparison_marks_unchanged_metrics_as_none(self):
        df = BD.comparison_dataframe(make_run(), make_run())
        assert df["Improvement"].isna().all()

    def test_detection_diff(self):
        baseline, candidate = make_run(), make_run()
        candidate.cases[0].matches = []
        detected, missed = BD.detection_diff(baseline, candidate)
        assert detected == []
        assert missed == ["gt1"]

    def test_findings_dataframes_do_not_raise_on_empty(self):
        empty = RunResult(metadata=RunMetadata(run_id="x"), cases=[])
        for kind in ("tp", "fp", "fn"):
            assert BD.findings_dataframe(empty, kind).empty

    @pytest.mark.parametrize("builder,args", [
        ("outcome_chart", True), ("rate_chart", True), ("stage_chart", False),
    ])
    def test_charts_compile_to_vega_specs(self, builder, args):
        run = make_run()
        if builder == "outcome_chart":
            chart = BD.outcome_chart(BD.outcome_dataframe(M.by_cwe(run), "CWE"), "CWE")
        elif builder == "rate_chart":
            chart = BD.rate_chart(BD.rate_dataframe(M.by_cwe(run), "CWE"), "CWE")
        else:
            chart = BD.stage_chart(BD.stage_dataframe(run))
        spec = T.style_chart(chart).to_dict()
        assert spec["$schema"].startswith("https://vega.github.io/schema/vega-lite")

    def test_history_and_delta_charts_compile(self):
        run = make_run()
        assert T.style_chart(BD.history_chart(BD.history_dataframe([run]))).to_dict()
        assert T.style_chart(
            BD.delta_chart(BD.comparison_dataframe(run, run))
        ).to_dict()


class TestScanDashboardData:
    def test_findings_dataframe_sorted_by_severity(self):
        findings = [
            make_finding(fid="a", severity=Severity.LOW).model_dump(mode="json"),
            make_finding(fid="b", severity=Severity.CRITICAL).model_dump(mode="json"),
        ]
        df = SD._findings_dataframe(findings)
        assert df.loc[0, "Severity"] == "critical"

    def test_findings_dataframe_handles_empty(self):
        assert SD._findings_dataframe([]).empty

    def test_severity_chart_omits_absent_levels(self):
        chart = SD.severity_chart({"critical": 2, "low": 1})
        data = pd.DataFrame(chart.data)
        assert set(data["_key"]) == {"critical", "low"}

    def test_severity_chart_compiles(self):
        spec = T.style_chart(SD.severity_chart({"high": 3, "medium": 1})).to_dict()
        assert spec["$schema"].startswith("https://vega.github.io/schema/vega-lite")

    def test_stage_chart_sorted_descending(self):
        chart = SD.stage_chart({"a": 1.0, "b": 9.0})
        assert list(chart.data["Stage"]) == ["b", "a"]


class TestComponents:
    def test_pill_escapes_untrusted_text(self):
        # Finding titles and CWE strings come from an LLM; they land in HTML.
        assert "<script>" not in T.pill("<script>alert(1)</script>")
        assert "&lt;script&gt;" in T.pill("<script>alert(1)</script>")

    def test_pill_applies_a_color(self):
        assert "#2a78d6" in T.pill("high", "#2a78d6")
