"""Stage-level timing and memory instrumentation for the analysis pipeline.

The benchmark framework (see `benchmark/`) needs a runtime breakdown per
stage -- "how much of a scan is Joern vs. the LLM?" is one of the things a
performance change has to be measured against. Rather than have the
benchmark wrap the pipeline from outside (which can only see total wall
time), the pipeline records its own stage timings into an `AnalysisReport`,
so any report.json -- benchmark-produced or not -- carries the breakdown.

Timings are plain wall-clock seconds keyed by stage name. Nothing here
raises: instrumentation must never be the reason a scan fails.
"""

from __future__ import annotations

import logging
import time
from contextlib import contextmanager
from typing import Iterator

logger = logging.getLogger(__name__)

# Canonical stage names. Benchmark reports key off these, so they're
# constants rather than inline strings scattered through the CLI.
STAGE_REPO_ACQUISITION = "repo_acquisition"
STAGE_JOERN_PARSE = "joern_parse"
STAGE_CPG_LOAD = "cpg_load"
STAGE_CANDIDATE_EXTRACTION = "candidate_extraction"
STAGE_CONTEXT_EXTRACTION = "context_extraction"
STAGE_LLM_ANALYSIS = "llm_analysis"
STAGE_DEDUPLICATION = "deduplication"
STAGE_REPORT_GENERATION = "report_generation"

# Order used when rendering breakdown tables.
STAGE_ORDER = [
    STAGE_REPO_ACQUISITION,
    STAGE_JOERN_PARSE,
    STAGE_CPG_LOAD,
    STAGE_CANDIDATE_EXTRACTION,
    STAGE_CONTEXT_EXTRACTION,
    STAGE_LLM_ANALYSIS,
    STAGE_DEDUPLICATION,
    STAGE_REPORT_GENERATION,
]


class StageTimer:
    """Accumulates wall-clock seconds per named pipeline stage.

    Re-entering the same stage name adds to that stage's total rather than
    replacing it, so a stage split across several code blocks (or repeated
    per candidate) still reports one aggregate number.
    """

    def __init__(self) -> None:
        self.stages: dict[str, float] = {}

    @contextmanager
    def stage(self, name: str) -> Iterator[None]:
        """Time the enclosed block and attribute it to `name`.

        The timing is recorded even if the block raises, so a partial run
        still reports where its time went before it failed.
        """
        start = time.monotonic()
        try:
            yield
        finally:
            self.record(name, time.monotonic() - start)

    def record(self, name: str, seconds: float) -> None:
        self.stages[name] = self.stages.get(name, 0.0) + max(0.0, seconds)

    def merge(self, other: dict[str, float] | "StageTimer") -> None:
        """Fold another timer's (or dict's) stages into this one."""
        source = other.stages if isinstance(other, StageTimer) else other
        for name, seconds in source.items():
            self.record(name, seconds)

    def total(self) -> float:
        return sum(self.stages.values())

    def as_dict(self) -> dict[str, float]:
        """Stages in canonical order first, then any custom ones."""
        ordered = {name: self.stages[name] for name in STAGE_ORDER if name in self.stages}
        for name, seconds in self.stages.items():
            ordered.setdefault(name, seconds)
        return ordered


def peak_memory_mb() -> float:
    """Peak resident set size of this process in MB, or 0.0 if unavailable.

    Uses `resource.getrusage`, which is POSIX-only and reports kilobytes on
    Linux but bytes on macOS. Returns 0.0 rather than raising on platforms
    (or in environments) where it isn't available -- callers treat 0.0 as
    "not measured".
    """
    try:
        import resource  # noqa: PLC0415 - POSIX-only, imported lazily on purpose
        import sys

        raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    except Exception:  # noqa: BLE001 - instrumentation must never break a scan
        logger.debug("Peak memory measurement unavailable", exc_info=True)
        return 0.0

    # Linux reports KB, macOS/BSD report bytes.
    divisor = 1024.0 if sys.platform != "darwin" else 1024.0 * 1024.0
    return round(raw / divisor, 2)
