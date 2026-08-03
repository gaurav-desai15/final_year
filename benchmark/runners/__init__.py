"""Runners produce an `AnalysisReport` for a benchmark case.

Two implementations ship:

* `CpgvdRunner` -- the real thing: shells out to `cpgvd analyze`. This is
  what a measured benchmark run uses.
* `ReplayRunner` -- re-scores reports that already exist on disk, with no
  Joern/LLM involvement. Used to re-evaluate an archived run under a changed
  matching policy, and to exercise the framework in environments without a
  Joern install.

Both satisfy `BaseRunner`, so `benchmark.run` doesn't care which is in play.
"""

from .base import BaseRunner, RunnerError, RunnerOutcome
from .cpgvd_runner import CpgvdRunner
from .replay_runner import ReplayRunner

RUNNERS: dict[str, type[BaseRunner]] = {
    "cpgvd": CpgvdRunner,
    "replay": ReplayRunner,
}

__all__ = ["BaseRunner", "RunnerError", "RunnerOutcome", "CpgvdRunner", "ReplayRunner", "RUNNERS"]
