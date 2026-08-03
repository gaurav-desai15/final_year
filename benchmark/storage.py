"""Archiving and retrieving benchmark runs.

Every run lands in its own timestamped directory under `benchmark/results/`
and is never modified afterwards -- that immutability is what makes the
regression history trustworthy months later when the numbers go into a
write-up.

Layout of one archived run:

    benchmark/results/2026-08-03T18-22-05Z__baseline/
        manifest.json      run metadata (what was run, with what, at what commit)
        run.json           the full RunResult: every match, FP, FN, timing
        metrics.json       aggregated metrics (machine-readable)
        report.md          the human-readable summary
        raw/<case_id>/     the untouched cpgvd output for that case

Runs are addressed by directory name, or by the aliases `latest` (most recent)
and any run's `--label` (most recent run carrying it, e.g. `baseline`).
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
import re
import subprocess
from pathlib import Path

from .metrics import summarize
from .models import RunResult

logger = logging.getLogger(__name__)

RESULTS_DIR = Path(__file__).parent / "results"
_TIMESTAMP_FMT = "%Y-%m-%dT%H-%M-%SZ"
_LABEL_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def new_run_id(label: str = "", now: _dt.datetime | None = None) -> str:
    """A sortable, filesystem-safe id: `<utc-timestamp>[__<label>]`."""
    now = now or _dt.datetime.now(_dt.timezone.utc)
    stamp = now.strftime(_TIMESTAMP_FMT)
    if not label:
        return stamp
    return f"{stamp}__{_LABEL_SAFE_RE.sub('-', label).strip('-')}"


def git_state(repo_root: Path | None = None) -> tuple[str, bool]:
    """(commit sha, dirty) for the working tree, or ("", False) if unavailable.

    Recorded in the manifest so a result can be traced back to the exact code
    that produced it -- the single most important reproducibility field.
    """
    root = repo_root or Path(__file__).resolve().parent.parent
    try:
        sha = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root, capture_output=True, text=True, check=True, timeout=10,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=root, capture_output=True, text=True, check=True, timeout=10,
        ).stdout.strip()
        return sha, bool(status)
    except (subprocess.SubprocessError, OSError):
        logger.debug("git state unavailable", exc_info=True)
        return "", False


def run_dir(run_id: str, results_dir: Path | None = None) -> Path:
    return (Path(results_dir) if results_dir else RESULTS_DIR) / run_id


def save_run(
    run: RunResult, *, results_dir: Path | None = None, report_markdown: str = ""
) -> Path:
    """Write a run's manifest, full result, metrics, and report to its directory."""
    directory = run_dir(run.metadata.run_id, results_dir)
    directory.mkdir(parents=True, exist_ok=True)

    (directory / "manifest.json").write_text(
        run.metadata.model_dump_json(indent=2), encoding="utf-8"
    )
    (directory / "run.json").write_text(run.model_dump_json(indent=2), encoding="utf-8")
    (directory / "metrics.json").write_text(
        json.dumps(summarize(run), indent=2, default=str), encoding="utf-8"
    )
    if report_markdown:
        (directory / "report.md").write_text(report_markdown, encoding="utf-8")

    return directory


def load_run(run_id: str, results_dir: Path | None = None) -> RunResult:
    """Load an archived run by directory name or alias."""
    directory = resolve_run(run_id, results_dir)
    path = directory / "run.json"
    if not path.exists():
        raise FileNotFoundError(f"No run.json in {directory}")
    return RunResult.model_validate(json.loads(path.read_text(encoding="utf-8")))


def list_runs(results_dir: Path | None = None) -> list[Path]:
    """Archived run directories, newest first (ids sort chronologically)."""
    base = Path(results_dir) if results_dir else RESULTS_DIR
    if not base.exists():
        return []
    return sorted(
        (p for p in base.iterdir() if p.is_dir() and (p / "run.json").exists()),
        key=lambda p: p.name,
        reverse=True,
    )


def resolve_run(name: str, results_dir: Path | None = None) -> Path:
    """Resolve a run directory name, `latest`, or a label to a directory.

    Label resolution picks the most recent run carrying that label, so
    `compare baseline latest` keeps working after the baseline is re-measured
    on better hardware.
    """
    base = Path(results_dir) if results_dir else RESULTS_DIR
    runs = list_runs(base)
    if not runs:
        raise FileNotFoundError(f"No archived benchmark runs under {base}")

    if name == "latest":
        return runs[0]

    exact = base / name
    if exact.is_dir() and (exact / "run.json").exists():
        return exact

    for directory in runs:  # newest first
        manifest = directory / "manifest.json"
        if not manifest.exists():
            continue
        try:
            label = json.loads(manifest.read_text(encoding="utf-8")).get("label", "")
        except json.JSONDecodeError:
            continue
        if label == name:
            return directory

    available = ", ".join(p.name for p in runs[:10])
    raise FileNotFoundError(f"No run matching '{name}'. Available: {available}")
