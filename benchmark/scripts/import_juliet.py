#!/usr/bin/env python3
"""Convert a subset of the NIST Juliet Test Suite into a benchmark dataset.

Juliet encodes its ground truth in the code itself: every test case file
contains `bad()` functions (the vulnerability) and `good*()` functions (the
fixed variants), and the filename carries the CWE
(`CWE78_OS_Command_Injection__*.c`). That convention is machine-readable, so
this importer derives labels from the source rather than asking anyone to
hand-label thousands of files.

Usage:

    # download + unzip Juliet (C/C++ or Java) from
    # https://samate.nist.gov/SARD/test-suites
    python benchmark/scripts/import_juliet.py \\
        --source /tmp/juliet/testcases \\
        --language c \\
        --cwe 78 --cwe 89 --cwe 134 \\
        --limit 100 \\
        --output benchmark/datasets/juliet-c.yaml

Both halves are emitted: the `bad` function becomes a ground-truth entry,
and the `good` functions in the same file are left unlisted, so reporting
them counts as a false positive. That pairing is what makes Juliet a
precision test and not just a recall test -- which is exactly the axis
this project claims to improve.

Caveat for the write-up: Juliet cases are synthetic and stylised. Good
Juliet numbers do not transfer directly to real code, and the suite is
known to be easier than production repositories. Report it alongside real
CVE cases, not instead of them.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

_CWE_FROM_NAME_RE = re.compile(r"CWE(\d+)_([A-Za-z0-9_]+?)__", re.IGNORECASE)
# Juliet's own naming convention: `bad` is the vulnerable variant; `goodG2B`,
# `goodB2G`, `good1` etc. are the fixed ones.
_BAD_FUNC_RE = re.compile(r"^\s*(?:[\w:*&<>\s]+?\s)?(\w*bad\w*)\s*\(", re.MULTILINE)

_EXT_BY_LANGUAGE = {
    "c": (".c", ".cpp", ".cc"),
    "cpp": (".cpp", ".cc", ".c"),
    "java": (".java",),
    "csharp": (".cs",),
}


def parse_cwe(path: Path) -> tuple[str, str]:
    """('CWE-78', 'OS_Command_Injection') from a Juliet filename."""
    match = _CWE_FROM_NAME_RE.search(path.name)
    if not match:
        return "", ""
    return f"CWE-{match.group(1)}", match.group(2).replace("_", " ").strip()


def find_bad_functions(text: str) -> list[tuple[str, int]]:
    """Locate `*bad*` function definitions and their 1-based line numbers."""
    results = []
    for match in _BAD_FUNC_RE.finditer(text):
        name = match.group(1)
        # `good...B2G` style helpers can contain "bad" as a substring in some
        # variants; exclude anything that also announces itself as good.
        if "good" in name.lower():
            continue
        line = text.count("\n", 0, match.start()) + 1
        results.append((name, line))
    return results


def collect_files(source: Path, language: str, cwes: list[str]) -> list[Path]:
    extensions = _EXT_BY_LANGUAGE.get(language, (".c",))
    wanted = {f"CWE-{c.lstrip('CWEcwe-')}" for c in cwes} if cwes else set()

    files = []
    for path in sorted(source.rglob("*")):
        if path.suffix.lower() not in extensions or not path.is_file():
            continue
        # Juliet splits some cases across `*a.c`, `*b.c` helper files; the
        # primary file is the one carrying the bad function, which the
        # per-file check below already enforces.
        cwe, _ = parse_cwe(path)
        if not cwe:
            continue
        if wanted and cwe not in wanted:
            continue
        files.append(path)
    return files


def build_dataset(source: Path, language: str, cwes: list[str], limit: int) -> dict:
    files = collect_files(source, language, cwes)
    if not files:
        raise SystemExit(
            f"No Juliet files matched under {source} "
            f"(language={language}, cwes={cwes or 'all'})."
        )

    cases = []
    skipped = 0
    for path in files:
        if limit and len(cases) >= limit:
            break
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            skipped += 1
            continue

        bad_functions = find_bad_functions(text)
        if not bad_functions:
            skipped += 1
            continue

        cwe, category = parse_cwe(path)
        rel = path.relative_to(source).as_posix()
        case_id = f"juliet-{path.stem}"

        cases.append({
            "id": case_id,
            "repo": str(path.parent),
            "language": language,
            "label": "mixed",  # the file holds both a bad and good variant
            "description": f"Juliet test case {path.name} ({cwe} {category}).",
            "scope_paths": [path.name],
            "expected": [
                {
                    "id": f"{case_id}-{name}",
                    "cwe": cwe,
                    "category": category.lower().replace(" ", "-"),
                    "file": path.name,
                    "start_line": line,
                    "function": name,
                    "description": (
                        f"Juliet marks `{name}` in {path.name} as the vulnerable "
                        f"variant for {cwe}. The `good*` functions in the same file "
                        "are the fixed variants and must NOT be reported."
                    ),
                    "tags": ["juliet", "synthetic"],
                }
                for name, line in bad_functions
            ],
        })

    if skipped:
        print(f"warning: skipped {skipped} file(s) with no detectable bad function",
              file=sys.stderr)

    return {
        "name": f"juliet-{language}",
        "description": (
            "NIST Juliet Test Suite subset. Ground truth derived from Juliet's own "
            "bad/good function naming convention by "
            "benchmark/scripts/import_juliet.py. Synthetic code -- report alongside "
            "real-world cases, not instead of them."
        ),
        "source_url": "https://samate.nist.gov/SARD/test-suites",
        "verified": True,
        "default_language": language,
        "match_policy": {
            # Juliet functions are short and the bad/good variants sit close
            # together in one file, so the tolerance is tight on purpose:
            # matching a `good` variant to the `bad` ground truth would turn a
            # false positive into a false "true positive" and hide the exact
            # failure mode this suite exists to expose.
            "line_tolerance": 15,
            "require_file": True,
            "weights": {"file": 1.0, "line": 1.5, "cwe": 1.0, "function": 1.0, "sink": 0.0},
        },
        "cases": cases,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--source", required=True, type=Path,
                        help="Path to the Juliet `testcases` directory.")
    parser.add_argument("--language", default="c", choices=sorted(_EXT_BY_LANGUAGE))
    parser.add_argument("--cwe", action="append", default=None,
                        help="Restrict to these CWE numbers (e.g. --cwe 78). Repeatable.")
    parser.add_argument("--limit", type=int, default=100,
                        help="Max test cases to include (0 = all). Juliet is huge; "
                             "a full run costs days of LLM time.")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)

    source = args.source.resolve()
    if not source.exists():
        raise SystemExit(f"Source not found: {source}")

    dataset = build_dataset(source, args.language, args.cwe or [], args.limit)
    output = args.output or (
        REPO_ROOT / "benchmark" / "datasets" / f"juliet-{args.language}.yaml"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(yaml.safe_dump(dataset, sort_keys=False, width=100), encoding="utf-8")

    gt = sum(len(c["expected"]) for c in dataset["cases"])
    print(f"Wrote {output}: {len(dataset['cases'])} case(s), {gt} ground-truth entries.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
