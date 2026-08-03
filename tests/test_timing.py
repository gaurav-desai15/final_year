"""Tests for pipeline stage instrumentation."""

from __future__ import annotations

import pytest

from cpgvd.models import AnalysisReport, RunStats
from cpgvd.report import to_markdown
from cpgvd.timing import STAGE_JOERN_PARSE, STAGE_ORDER, StageTimer, peak_memory_mb


class TestStageTimer:
    def test_records_a_stage(self):
        timer = StageTimer()
        with timer.stage("x"):
            pass
        assert "x" in timer.stages
        assert timer.stages["x"] >= 0.0

    def test_reentering_a_stage_accumulates(self):
        timer = StageTimer()
        for _ in range(3):
            timer.record("x", 1.0)
        assert timer.stages["x"] == 3.0

    def test_timing_survives_an_exception(self):
        """A failed run must still report where its time went."""
        timer = StageTimer()
        with pytest.raises(ValueError):
            with timer.stage("x"):
                raise ValueError("boom")
        assert "x" in timer.stages

    def test_merge_from_timer_and_dict(self):
        a, b = StageTimer(), StageTimer()
        a.record("x", 1.0)
        b.record("x", 2.0)
        b.record("y", 3.0)
        a.merge(b)
        a.merge({"y": 1.0})
        assert a.stages == {"x": 3.0, "y": 4.0}

    def test_total(self):
        timer = StageTimer()
        timer.record("a", 1.5)
        timer.record("b", 2.5)
        assert timer.total() == 4.0

    def test_as_dict_uses_canonical_order_then_custom(self):
        timer = StageTimer()
        timer.record("custom_stage", 1.0)
        timer.record("llm_analysis", 2.0)
        timer.record(STAGE_JOERN_PARSE, 3.0)
        keys = list(timer.as_dict())
        assert keys.index(STAGE_JOERN_PARSE) < keys.index("llm_analysis")
        assert keys[-1] == "custom_stage"

    def test_negative_durations_are_clamped(self):
        timer = StageTimer()
        timer.record("x", -5.0)
        assert timer.stages["x"] == 0.0

    def test_stage_order_has_no_duplicates(self):
        assert len(STAGE_ORDER) == len(set(STAGE_ORDER))


class TestPeakMemory:
    def test_returns_a_non_negative_number(self):
        # 0.0 is the documented "not measured" value on unsupported platforms.
        assert peak_memory_mb() >= 0.0


class TestRunStatsIntegration:
    def test_stage_timings_default_to_empty(self):
        """Reports predating instrumentation must still load."""
        stats = RunStats()
        assert stats.stage_timings == {}
        assert stats.stage_seconds("anything") == 0.0

    def test_stage_seconds_lookup(self):
        stats = RunStats(stage_timings={"joern_parse": 12.0})
        assert stats.stage_seconds("joern_parse") == 12.0
        assert stats.stage_seconds("missing") == 0.0

    def test_old_report_json_without_timings_still_parses(self):
        report = AnalysisReport.model_validate({
            "repo": "x", "languages": ["python"], "model": "m",
            "findings": [],
            "stats": {"functions_discovered": 3, "duration_seconds": 1.0},
        })
        assert report.stats.stage_timings == {}
        assert report.stats.peak_memory_mb == 0.0

    def test_markdown_renders_a_breakdown_table(self):
        report = AnalysisReport(
            repo="x", languages=["python"], model="m",
            stats=RunStats(duration_seconds=10.0, peak_memory_mb=128.0,
                           stage_timings={"joern_parse": 6.0, "llm_analysis": 4.0}),
        )
        markdown = to_markdown(report)
        assert "## Runtime breakdown" in markdown
        assert "joern_parse" in markdown
        assert "60.0%" in markdown
        assert "128 MB" in markdown

    def test_markdown_omits_breakdown_when_untimed(self):
        report = AnalysisReport(repo="x", languages=["python"], model="m")
        assert "## Runtime breakdown" not in to_markdown(report)
