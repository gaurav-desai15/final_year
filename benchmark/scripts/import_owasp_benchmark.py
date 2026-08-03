#!/usr/bin/env python3
"""Convert the OWASP Benchmark into a cpgvd benchmark dataset.

The OWASP Benchmark ships its own ground truth as
`expectedresults-1.2.csv`, mapping each generated test case to a CWE and a
true/false "real vulnerability" flag. Deriving our dataset from that file
rather than hand-labelling is the point: the labels are the suite's, not
ours, so nobody has to take our word for them.

Usage:

    git clone https://github.com/OWASP-Benchmark/BenchmarkJava /tmp/benchmark
    python benchmark/scripts/import_owasp_benchmark.py \\
        --source /tmp/benchmark \\
        --output benchmark/datasets/owasp-benchmark.yaml \\
        --limit 200

`--limit` matters: the full suite is ~2700 test cases, and at even a few
seconds of LLM time each that is a multi-day run. Start with a stratified
sample (`--limit` keeps an even spread across CWEs) and scale up once the
pipeline is stable.

Caveat worth recording in your write-up: the Benchmark is Java, and
cpgvd's rule coverage for Java is thinner than for Python/JavaScript. Low
recall here may be a rules-coverage result rather than a model result --
check `rules/sinks_sources.yaml` before concluding anything about the LLM.
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def find_expected_results(source: Path) -> Path:
    """Locate the suite's own ground-truth CSV."""
    candidates = sorted(source.glob("expectedresults-*.csv"))
    if not candidates:
        candidates = sorted(source.rglob("expectedresults-*.csv"))
    if not candidates:
        raise SystemExit(
            f"No expectedresults-*.csv under {source}. Is this an OWASP Benchmark checkout?"
        )
    return candidates[-1]


def read_ground_truth(csv_path: Path) -> list[dict[str, str]]:
    """Parse the CSV into normalized rows.

    Column names have drifted between Benchmark versions, so match them
    case-insensitively by prefix rather than by exact string.
    """
    rows: list[dict[str, str]] = []
    with csv_path.open(newline="", encoding="utf-8") as handle:
        for raw in csv.DictReader(handle):
            keys = {k.strip().lower(): k for k in raw if k}
            def get(prefix: str) -> str:
                for lowered, original in keys.items():
                    if lowered.startswith(prefix):
                        return (raw[original] or "").strip()
                return ""

            name = get("# test name") or get("test name") or get("testname")
            if not name:
                continue
            rows.append({
                "name": name,
                "category": get("category"),
                "real": get("real vulnerability").lower(),
                "cwe": get("cwe"),
            })
    return rows


def locate_test_file(source: Path, test_name: str) -> Path | None:
    matches = list(source.rglob(f"{test_name}.java"))
    return matches[0] if matches else None


def stratified_sample(rows: list[dict[str, str]], limit: int) -> list[dict[str, str]]:
    """Take up to `limit` rows spread evenly across CWEs.

    Sampling the first N rows instead would over-represent whichever CWE
    happens to sort first and make the per-CWE table useless.
    """
    if limit <= 0 or len(rows) <= limit:
        return rows
    by_cwe: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_cwe[row["cwe"] or "unknown"].append(row)

    selected: list[dict[str, str]] = []
    index = 0
    while len(selected) < limit:
        added = False
        for bucket in by_cwe.values():
            if index < len(bucket):
                selected.append(bucket[index])
                added = True
                if len(selected) >= limit:
                    break
        if not added:
            break
        index += 1
    return selected


def build_dataset(source: Path, limit: int, include_safe: bool) -> dict:
    csv_path = find_expected_results(source)
    rows = read_ground_truth(csv_path)
    if not rows:
        raise SystemExit(f"No usable rows in {csv_path}")

    if not include_safe:
        rows = [r for r in rows if r["real"] == "true"]
    rows = stratified_sample(rows, limit)

    cases = []
    missing = 0
    for row in rows:
        path = locate_test_file(source, row["name"])
        if path is None:
            missing += 1
            continue
        rel = path.relative_to(source).as_posix()
        is_real = row["real"] == "true"
        case: dict = {
            "id": f"owasp-{row['name']}",
            "repo": str(source),
            "language": "java",
            "label": "vulnerable" if is_real else "safe",
            "description": f"OWASP Benchmark {row['name']} ({row['category']}).",
            "scope_paths": [rel],
            "expected": [],
        }
        if is_real:
            case["expected"].append({
                "id": f"owasp-{row['name']}-gt",
                "cwe": f"CWE-{row['cwe']}" if row["cwe"] else "",
                "category": row["category"],
                "file": rel,
                "function": row["name"],
                "description": (
                    f"OWASP Benchmark asserts {row['name']} contains a real "
                    f"{row['category']} vulnerability (CWE-{row['cwe']})."
                ),
                "tags": ["owasp-benchmark"],
            })
        cases.append(case)

    if missing:
        print(f"warning: {missing} test case(s) had no .java file and were skipped",
              file=sys.stderr)

    return {
        "name": "owasp-benchmark",
        "description": (
            "OWASP Benchmark test cases, with ground truth taken directly from the "
            f"suite's own {csv_path.name}. Generated by "
            "benchmark/scripts/import_owasp_benchmark.py."
        ),
        "version": csv_path.stem.replace("expectedresults-", ""),
        "source_url": "https://github.com/OWASP-Benchmark/BenchmarkJava",
        "verified": True,
        "default_language": "java",
        # The suite has no line-level ground truth -- one file is one test case
        # -- so line matching is disabled and file+CWE carry the decision.
        "match_policy": {
            "require_file": True,
            "line_tolerance": 100000,
            "weights": {"file": 1.0, "cwe": 1.0, "line": 0.0, "function": 0.5, "sink": 0.0},
        },
        "cases": cases,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--source", required=True, type=Path,
                        help="Path to an OWASP Benchmark checkout.")
    parser.add_argument("--output", type=Path,
                        default=REPO_ROOT / "benchmark" / "datasets" / "owasp-benchmark.yaml")
    parser.add_argument("--limit", type=int, default=200,
                        help="Max test cases to include, stratified across CWEs (0 = all).")
    parser.add_argument("--include-safe", action="store_true",
                        help="Also include the suite's non-vulnerable cases, as `safe` "
                             "cases that contribute true negatives.")
    args = parser.parse_args(argv)

    source = args.source.resolve()
    if not source.exists():
        raise SystemExit(f"Source not found: {source}")

    dataset = build_dataset(source, args.limit, args.include_safe)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        yaml.safe_dump(dataset, sort_keys=False, width=100), encoding="utf-8"
    )
    real = sum(1 for c in dataset["cases"] if c["label"] == "vulnerable")
    print(f"Wrote {args.output}: {len(dataset['cases'])} case(s), {real} vulnerable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
