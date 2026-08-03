"""Re-scores cpgvd reports that already exist on disk.

Two uses:

1. **Re-evaluation without re-scanning.** Scanning a suite costs Joern parses
   and LLM calls; changing a match tolerance shouldn't. Point this runner at
   a previous run's archived reports and the whole suite re-scores in
   milliseconds. This is also how you check that a metric movement came from
   the detector and not from the evaluation harness.
2. **Running the framework where cpgvd can't run.** CI (or a machine without
   Joern/Ollama) can still exercise loading, matching, metrics, and report
   generation against fixture reports.

Reports are looked up per case id under `<source>/raw/<case_id>/cpgvd_output/
report.json`, falling back to `<source>/<case_id>.json` so a directory of
hand-written fixtures works too.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from cpgvd.models import AnalysisReport

from ..models import BenchmarkCase
from .base import BaseRunner, RunnerError, RunnerOutcome

logger = logging.getLogger(__name__)


class ReplayRunner(BaseRunner):
    """Serves archived `report.json` files instead of scanning."""

    name = "replay"

    def __init__(self, *, source: str | Path, **options: object) -> None:
        super().__init__(**options)
        self.source = Path(source)
        if not self.source.exists():
            raise RunnerError(f"Replay source does not exist: {self.source}")

    def describe(self) -> dict[str, str]:
        return {"runner": self.name, "source": str(self.source)}

    def _candidate_paths(self, case: BenchmarkCase) -> list[Path]:
        return [
            self.source / "raw" / case.id / "cpgvd_output" / "report.json",
            self.source / "raw" / case.id / "report.json",
            self.source / case.id / "report.json",
            self.source / f"{case.id}.json",
        ]

    def run_case(self, case: BenchmarkCase, artifacts_dir: Path) -> RunnerOutcome:
        start = time.monotonic()
        for path in self._candidate_paths(case):
            if path.exists():
                report = _load_report(path)
                # Copy into this run's archive so the replay is self-contained
                # and can itself be replayed later.
                artifacts_dir = Path(artifacts_dir)
                archived = artifacts_dir / "cpgvd_output" / "report.json"
                archived.parent.mkdir(parents=True, exist_ok=True)
                archived.write_text(report.model_dump_json(indent=2), encoding="utf-8")
                return RunnerOutcome(
                    report=report,
                    # The original scan's duration, not the replay's: replaying
                    # takes no meaningful time and reporting ~0s would corrupt
                    # every runtime metric downstream.
                    duration_seconds=report.stats.duration_seconds,
                    raw_report_path=str(archived),
                    extra={"replayed_from": str(path), "replay_seconds": f"{time.monotonic() - start:.4f}"},
                )

        raise RunnerError(
            f"No archived report for case '{case.id}'. Looked in: "
            + ", ".join(str(p) for p in self._candidate_paths(case))
        )


def _load_report(path: Path) -> AnalysisReport:
    try:
        return AnalysisReport.model_validate(json.loads(path.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, ValueError) as exc:
        raise RunnerError(f"Could not parse report at {path}: {exc}") from exc
