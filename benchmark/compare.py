"""Compare archived benchmark runs: `python -m benchmark.compare`.

    python -m benchmark.compare baseline latest        # two-run regression report
    python -m benchmark.compare --all                  # every run, one table
    python -m benchmark.compare baseline latest -o docs/COMPARISON.md

Runs are addressed by directory name, by `latest`, or by the `--label` they
were given (most recent wins), so `baseline latest` keeps working forever.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from .reports import render_comparison, render_multi_version_table  # noqa: E402
from .storage import list_runs, load_run  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m benchmark.compare",
        description="Compare archived benchmark runs and report metric/runtime deltas.",
    )
    parser.add_argument("baseline", nargs="?", default="baseline",
                        help="Baseline run: directory name, label, or 'latest'.")
    parser.add_argument("candidate", nargs="?", default="latest",
                        help="Candidate run: directory name, label, or 'latest'.")
    parser.add_argument("--all", action="store_true",
                        help="Ignore the two positional args; table every archived run.")
    parser.add_argument("--runs", action="append", default=None,
                        help="With --all, restrict to these runs. Repeatable.")
    parser.add_argument("--results-dir", default=None)
    parser.add_argument("-o", "--output", default=None,
                        help="Write the report here instead of stdout.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    results_dir = Path(args.results_dir) if args.results_dir else None

    try:
        if args.all:
            names = args.runs or [p.name for p in list_runs(results_dir)]
            if not names:
                print("error: no archived runs found", file=sys.stderr)
                return 2
            runs = [load_run(name, results_dir) for name in names]
            markdown = render_multi_version_table(runs)
        else:
            baseline = load_run(args.baseline, results_dir)
            candidate = load_run(args.candidate, results_dir)
            if baseline.metadata.run_id == candidate.metadata.run_id:
                print(
                    f"error: '{args.baseline}' and '{args.candidate}' resolve to the same run "
                    f"({baseline.metadata.run_id}). Record a second run first.",
                    file=sys.stderr,
                )
                return 2
            markdown = render_comparison(baseline, candidate)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(markdown, encoding="utf-8")
        print(f"Wrote {out}")
    else:
        print(markdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
