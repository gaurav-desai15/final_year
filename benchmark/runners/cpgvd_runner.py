"""Runs the real cpgvd pipeline against a benchmark case.

Invokes `cpgvd analyze` as a subprocess rather than importing the CLI
in-process. That costs a little startup time per case but buys three things
that matter for a benchmark: a crash in one case can't take down the run, a
per-case timeout is enforceable, and the measured command is exactly the one
a user would type (so the numbers describe the shipped tool, not a private
code path).
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import sys
import time
from pathlib import Path

from cpgvd.models import AnalysisReport

from ..loader import resolve_repo
from ..models import BenchmarkCase
from .base import BaseRunner, RunnerError, RunnerOutcome

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_S = 3600.0


class CpgvdRunner(BaseRunner):
    """Scans each case with a live `cpgvd analyze` subprocess."""

    name = "cpgvd"

    def __init__(
        self,
        *,
        provider: str | None = None,
        model: str | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        extra_args: list[str] | None = None,
        **options: object,
    ) -> None:
        super().__init__(**options)
        self.provider = provider
        self.model = model
        self.timeout_s = timeout_s
        self.extra_args = list(extra_args or [])

    def describe(self) -> dict[str, str]:
        return {
            "runner": self.name,
            "provider": self.provider or "(config default)",
            "model": self.model or "(config default)",
            "extra_args": " ".join(self.extra_args),
            "timeout_s": str(self.timeout_s),
        }

    def _command(self, case: BenchmarkCase, output_dir: Path) -> list[str]:
        cmd = [
            self._executable(),
            "analyze",
            resolve_repo(case.repo),
            "--output-dir",
            str(output_dir),
        ]
        if case.ref:
            cmd += ["--ref", case.ref]
        if case.language:
            cmd += ["--language", case.language]
        if self.provider:
            cmd += ["--provider", self.provider]
        if self.model:
            cmd += ["--model", self.model]
        cmd += case.analyze_args
        cmd += self.extra_args
        return cmd

    @staticmethod
    def _executable() -> str:
        """Prefer the installed `cpgvd` script; fall back to `python -m`."""
        return shutil.which("cpgvd") or sys.executable

    def run_case(self, case: BenchmarkCase, artifacts_dir: Path) -> RunnerOutcome:
        artifacts_dir = Path(artifacts_dir)
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        output_dir = artifacts_dir / "cpgvd_output"

        cmd = self._command(case, output_dir)
        if cmd[0] == sys.executable:
            # `cpgvd` isn't on PATH (e.g. not pip-installed); call the module.
            cmd = [sys.executable, "-m", "cpgvd.cli"] + cmd[1:]

        logger.info("Case %s: %s", case.id, " ".join(cmd))
        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RunnerError(
                f"cpgvd timed out after {self.timeout_s:.0f}s on case '{case.id}'"
            ) from exc
        duration = time.monotonic() - start

        combined = (proc.stdout or "") + (proc.stderr or "")
        (artifacts_dir / "stdout.log").write_text(combined, encoding="utf-8")
        (artifacts_dir / "command.txt").write_text(" ".join(cmd), encoding="utf-8")

        report_path = output_dir / "report.json"
        if proc.returncode != 0 and not report_path.exists():
            raise RunnerError(
                f"cpgvd exited {proc.returncode} on case '{case.id}'. "
                f"Last output: {combined.strip()[-800:] or '(none)'}"
            )
        if not report_path.exists():
            raise RunnerError(f"cpgvd produced no report.json for case '{case.id}'")

        report = _load_report(report_path)
        return RunnerOutcome(
            report=report,
            duration_seconds=duration,
            raw_report_path=str(report_path),
            stdout=combined,
            extra={"returncode": str(proc.returncode)},
        )


def _load_report(path: Path) -> AnalysisReport:
    try:
        return AnalysisReport.model_validate(json.loads(path.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, ValueError) as exc:
        raise RunnerError(f"Could not parse cpgvd report at {path}: {exc}") from exc
