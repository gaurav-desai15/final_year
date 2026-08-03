"""The runner interface every benchmark backend implements."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from cpgvd.models import AnalysisReport

from ..models import BenchmarkCase


class RunnerError(RuntimeError):
    """A case could not be scanned. Recorded on the case, never fatal to the run."""


@dataclass
class RunnerOutcome:
    """What a runner produces for one case."""

    report: AnalysisReport
    duration_seconds: float
    raw_report_path: str = ""
    stdout: str = ""
    extra: dict[str, str] = field(default_factory=dict)


class BaseRunner(ABC):
    """Produces an `AnalysisReport` for a benchmark case.

    Implementations must be safe to call repeatedly and must write any
    artifacts they generate under the `artifacts_dir` they're handed, so a
    run archives completely.
    """

    name: str = "base"

    def __init__(self, **options: object) -> None:
        self.options = options

    @abstractmethod
    def run_case(self, case: BenchmarkCase, artifacts_dir: Path) -> RunnerOutcome:
        """Scan `case`, archiving raw output under `artifacts_dir`."""

    def describe(self) -> dict[str, str]:
        """Metadata about this runner's configuration, for the run manifest."""
        return {"runner": self.name}
