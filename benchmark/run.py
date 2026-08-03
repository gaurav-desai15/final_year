"""Benchmark runner entrypoint: `python -m benchmark.run`.

Scans every case in the selected datasets, scores the findings against ground
truth, and archives a timestamped, immutable result directory.

    python -m benchmark.run                              # every dataset, live scan
    python -m benchmark.run --dataset bundled-examples   # one dataset
    python -m benchmark.run --label baseline             # name the run
    python -m benchmark.run --provider anthropic --model claude-opus-4-8
    python -m benchmark.run --runner replay --replay-source benchmark/fixtures

A case that fails to scan is recorded with `status="error"` and excluded from
metrics rather than aborting the suite -- one broken repo shouldn't cost you
the other nineteen scans.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Make `benchmark` importable when run as a script from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from .evaluators import evaluate_case  # noqa: E402
from .loader import DatasetError, load_datasets  # noqa: E402
from .metrics import overall  # noqa: E402
from .models import (  # noqa: E402
    CaseResult,
    MatchPolicy,
    RunMetadata,
    RunResult,
)
from .reports import render_run_report  # noqa: E402
from .runners import RUNNERS, RunnerError  # noqa: E402
from .storage import git_state, new_run_id, save_run  # noqa: E402

logger = logging.getLogger("benchmark.run")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m benchmark.run",
        description="Run the cpgvd benchmark suite and archive the results.",
    )
    parser.add_argument(
        "--dataset", action="append", default=None,
        help="Dataset name (file stem in benchmark/datasets/). Repeatable. Default: all.",
    )
    parser.add_argument("--case", action="append", default=None,
                        help="Run only these case ids. Repeatable.")
    parser.add_argument("--label", default="",
                        help="Label for this run (e.g. 'baseline', 'prompt-v2'). "
                             "Used by `compare` to address the run by name.")
    parser.add_argument("--notes", default="", help="Free-text note stored in the manifest.")

    parser.add_argument("--runner", choices=sorted(RUNNERS), default="cpgvd",
                        help="'cpgvd' performs live scans; 'replay' re-scores archived reports.")
    parser.add_argument("--replay-source", default=None,
                        help="Directory of archived reports (required for --runner replay).")

    parser.add_argument("--provider", default=None, help="LLM provider passed to cpgvd.")
    parser.add_argument("--model", default=None, help="Model id passed to cpgvd.")
    parser.add_argument("--timeout", type=float, default=3600.0,
                        help="Per-case timeout in seconds (default: 3600).")
    parser.add_argument("--analyze-arg", action="append", default=None,
                        help="Extra flag appended to every `cpgvd analyze`. Repeatable.")

    parser.add_argument("--line-tolerance", type=int, default=None,
                        help="Override the match policy's line tolerance.")
    parser.add_argument("--require-cwe", action="store_true",
                        help="Require the CWE to match for a finding to count as a TP.")
    parser.add_argument("--min-score", type=float, default=None,
                        help="Override the minimum match score (0-1).")

    parser.add_argument("--results-dir", default=None,
                        help="Where to archive the run (default: benchmark/results).")
    parser.add_argument("--dry-run", action="store_true",
                        help="List the cases that would run, then exit.")
    parser.add_argument("--synthetic", action="store_true",
                        help="Mark this run as a non-measurement (demonstration only). "
                             "Implied by --runner replay.")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def build_policy(args: argparse.Namespace) -> MatchPolicy:
    policy = MatchPolicy()
    overrides: dict[str, object] = {}
    if args.line_tolerance is not None:
        overrides["line_tolerance"] = args.line_tolerance
    if args.require_cwe:
        overrides["require_cwe"] = True
    if args.min_score is not None:
        overrides["min_score"] = args.min_score
    return policy.merged_with(overrides)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)-7s %(name)s: %(message)s",
    )

    try:
        datasets = load_datasets(args.dataset)
    except DatasetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    selected = [
        (ds, case)
        for ds in datasets
        for case in ds.active_cases()
        if not args.case or case.id in args.case
    ]
    if not selected:
        print("error: no cases selected", file=sys.stderr)
        return 2

    if args.dry_run:
        print(f"{len(selected)} case(s) would run:")
        for ds, case in selected:
            print(f"  {ds.name}/{case.id}  repo={case.repo}  gt={len(case.expected)}")
        return 0

    try:
        runner = _build_runner(args)
    except RunnerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    policy = build_policy(args)
    run_id = new_run_id(args.label)
    commit, dirty = git_state()

    metadata = RunMetadata(
        run_id=run_id,
        label=args.label,
        datasets=[ds.name for ds in datasets],
        runner=args.runner,
        provider=args.provider or "",
        model=args.model or "",
        git_commit=commit,
        git_dirty=dirty,
        command=" ".join(["python", "-m", "benchmark.run"] + (argv or sys.argv[1:])),
        match_policy=policy,
        notes=args.notes,
        synthetic=args.synthetic or args.runner == "replay",
    )

    results_dir = Path(args.results_dir) if args.results_dir else None
    run_directory = (results_dir or Path(__file__).parent / "results") / run_id
    raw_dir = run_directory / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    case_results: list[CaseResult] = []
    for index, (dataset, case) in enumerate(selected, start=1):
        logger.info("[%d/%d] %s/%s", index, len(selected), dataset.name, case.id)
        dataset_policy = policy.merged_with(dataset.match_policy)
        artifacts = raw_dir / case.id
        try:
            outcome = runner.run_case(case, artifacts)
        except RunnerError as exc:
            logger.error("  failed: %s", exc)
            case_results.append(
                CaseResult(
                    case_id=case.id, dataset=dataset.name, repo=case.repo,
                    label=case.label, status="error", error=str(exc),
                    ground_truth_total=len(case.expected),
                )
            )
            continue
        except Exception as exc:  # noqa: BLE001 - one bad case must not kill the suite
            logger.exception("  unexpected failure")
            case_results.append(
                CaseResult(
                    case_id=case.id, dataset=dataset.name, repo=case.repo,
                    label=case.label, status="error", error=f"{type(exc).__name__}: {exc}",
                    ground_truth_total=len(case.expected),
                )
            )
            continue

        result = evaluate_case(
            case, outcome.report, dataset_policy,
            dataset_name=dataset.name,
            duration_seconds=outcome.duration_seconds,
            raw_report_path=outcome.raw_report_path,
        )
        case_results.append(result)
        logger.info(
            "  TP=%d FP=%d FN=%d  precision=%.2f recall=%.2f  %.1fs",
            result.metrics.true_positives, result.metrics.false_positives,
            result.metrics.false_negatives, result.metrics.precision,
            result.metrics.recall, result.duration_seconds,
        )

    run = RunResult(metadata=metadata, cases=case_results)
    report_md = render_run_report(run)
    directory = save_run(run, results_dir=results_dir, report_markdown=report_md)

    summary = overall(run)
    print()
    print(f"Run archived: {directory}")
    print(
        f"  TP={summary.true_positives} FP={summary.false_positives} "
        f"FN={summary.false_negatives} TN={summary.true_negatives}"
    )
    print(
        f"  precision={summary.precision:.3f} recall={summary.recall:.3f} f1={summary.f1:.3f}"
    )
    print(f"  report: {directory / 'report.md'}")
    if metadata.synthetic:
        print("  NOTE: run marked synthetic -- not a valid measurement of detection quality.")
    return 0


def _build_runner(args: argparse.Namespace):
    if args.runner == "replay":
        if not args.replay_source:
            raise RunnerError("--runner replay requires --replay-source")
        return RUNNERS["replay"](source=args.replay_source)
    return RUNNERS["cpgvd"](
        provider=args.provider,
        model=args.model,
        timeout_s=args.timeout,
        extra_args=args.analyze_arg or [],
    )


if __name__ == "__main__":
    raise SystemExit(main())
