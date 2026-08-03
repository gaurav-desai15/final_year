"""Generate `docs/RESULT_ANALYSIS.md` from an archived run.

    python -m benchmark.analyze                  # latest run -> docs/RESULT_ANALYSIS.md
    python -m benchmark.analyze --run baseline
    python -m benchmark.analyze --no-history -o /tmp/analysis.md

The document is derived entirely from the archived run, so it can be
regenerated for any past run without re-scanning anything.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from .reports import render_analysis_document  # noqa: E402
from .storage import list_runs, load_run  # noqa: E402

DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent / "docs" / "RESULT_ANALYSIS.md"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m benchmark.analyze",
        description="Generate the result-analysis document from an archived benchmark run.",
    )
    parser.add_argument("--run", default="latest",
                        help="Run to analyze: directory name, label, or 'latest'.")
    parser.add_argument("--results-dir", default=None)
    parser.add_argument("-o", "--output", default=None,
                        help=f"Output path (default: {DEFAULT_OUTPUT}).")
    parser.add_argument("--no-history", action="store_true",
                        help="Omit the cross-run history table.")
    parser.add_argument("--history-limit", type=int, default=10,
                        help="How many past runs to include in the history table.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    results_dir = Path(args.results_dir) if args.results_dir else None

    try:
        run = load_run(args.run, results_dir)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    history = []
    if not args.no_history:
        for directory in list_runs(results_dir)[: args.history_limit]:
            try:
                history.append(load_run(directory.name, results_dir))
            except (FileNotFoundError, ValueError):
                continue

    markdown = render_analysis_document(run, history=history or None)
    output = Path(args.output) if args.output else DEFAULT_OUTPUT
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(markdown, encoding="utf-8")
    print(f"Wrote {output} (from run {run.metadata.run_id})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
