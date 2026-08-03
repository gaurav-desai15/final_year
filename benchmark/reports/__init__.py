"""Markdown rendering for benchmark runs, comparisons, and the analysis doc."""

from .markdown import (
    render_analysis_document,
    render_comparison,
    render_multi_version_table,
    render_run_report,
)

__all__ = [
    "render_run_report",
    "render_comparison",
    "render_multi_version_table",
    "render_analysis_document",
]
