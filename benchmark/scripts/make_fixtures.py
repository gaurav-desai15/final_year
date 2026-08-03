#!/usr/bin/env python3
"""Generate the synthetic cpgvd reports used to exercise the framework.

These fixtures are **not measurements**. They are hand-authored
`AnalysisReport` files representing a plausible cpgvd run over the bundled
example apps, and they exist so that the loader, matcher, metrics, storage,
comparison and document generators can be tested end-to-end on a machine
with no Joern install and no LLM backend -- which includes CI.

Any run produced from them is marked `synthetic: true`, and every report the
framework renders from such a run carries a warning banner. Do not cite
numbers derived from this directory.

The fixtures deliberately encode a realistic mix of outcomes -- true
positives, a false positive on each app's *safe* sibling call site, and a
missed cross-function case -- so the reports and comparison tooling have
something non-trivial to render. Two variants are produced so the comparison
and regression-tracking paths can be demonstrated:

    baseline/  an initial run
    improved/  the same suite after a hypothetical precision fix

Usage:  python benchmark/scripts/make_fixtures.py
"""

from __future__ import annotations

import datetime as _dt
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

FIXTURES_DIR = REPO_ROOT / "benchmark" / "fixtures"

_NOW = _dt.datetime(2026, 8, 3, 12, 0, 0, tzinfo=_dt.timezone.utc)


def _finding(
    fid: str, file: str, start: int, end: int, function: str, vuln: str, cwe: str,
    severity: str, confidence: str, title: str, description: str,
    context_reasoning: str = "", data_flow_summary: str = "",
) -> dict:
    return {
        "id": fid,
        "context_id": f"ctx-{fid}",
        "file": file,
        "start_line": start,
        "end_line": end,
        "function": function,
        "vulnerability_type": vuln,
        "cwe": cwe,
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "description": description,
        "context_reasoning": context_reasoning,
        "data_flow_summary": data_flow_summary,
        "suggested_fix": "",
        "model": "qwen2.5-coder:7b",
    }


def _report(repo: str, languages: list[str], findings: list[dict], stats: dict) -> dict:
    return {
        "repo": repo,
        "commit_sha": "0" * 40,
        "languages": languages,
        "model": "qwen2.5-coder:7b",
        "generated_at": _NOW.isoformat(),
        "findings": findings,
        "stats": stats,
    }


def _stats(*, contexts: int, llm_calls: int, duration: float, stages: dict[str, float]) -> dict:
    return {
        "functions_discovered": 8,
        "candidate_contexts_analyzed": contexts,
        "sink_matches": contexts + 2,
        "llm_calls": llm_calls,
        "llm_input_tokens": llm_calls * 2400,
        "llm_output_tokens": llm_calls * 480,
        "duration_seconds": duration,
        "stage_timings": stages,
        "peak_memory_mb": 412.5,
    }


# --------------------------------------------------------------------------
# Baseline variant: 3 TP, 2 FP (both on safe sibling call sites), 2 FN.
# --------------------------------------------------------------------------

PYTHON_BASELINE = _report(
    repo="examples/vulnerable_app/python",
    languages=["python"],
    findings=[
        _finding(
            "py-f1", "app.py", 43, 51, "app.py:<module>.admin_run",
            "OS Command Injection", "CWE-78", "critical", "high",
            "Unvalidated query parameter reaches os.popen",
            "The `cmd` query parameter is passed directly to run_diagnostic, which "
            "calls os.popen on it with no allowlisting or argument-vector escaping.",
            context_reasoning="run_diagnostic alone is undecidable; the caller shows "
                              "request.args flows in unvalidated.",
            data_flow_summary="request.args.get('cmd') -> run_diagnostic(command) -> os.popen",
        ),
        _finding(
            "py-f2", "app.py", 60, 70, "app.py:<module>.get_user",
            "SQL Injection", "CWE-89", "high", "high",
            "Path segment interpolated into SQL and executed",
            "`user_id` comes from the URL path and is interpolated into a query "
            "string by build_user_query, which get_user then executes.",
            context_reasoning="The concatenation and the execution live in different "
                              "functions; the callee's f-string is only dangerous "
                              "because of this caller's input.",
            data_flow_summary="URL path segment -> build_user_query -> cursor.execute",
        ),
        # FALSE POSITIVE: the allowlisted, safe route. This is the exact failure
        # mode the project claims to reduce, so the fixture includes it.
        _finding(
            "py-f3", "app.py", 33, 40, "app.py:<module>.status",
            "OS Command Injection", "CWE-78", "high", "medium",
            "Shell command executed in request handler",
            "The status route reaches os.popen via run_diagnostic.",
            context_reasoning="Reported from the sink pattern without accounting for "
                              "the ALLOWED_DIAGNOSTICS membership check above it.",
            data_flow_summary="name -> ALLOWED_DIAGNOSTICS lookup -> run_diagnostic",
        ),
    ],
    stats=_stats(
        contexts=5, llm_calls=5, duration=48.6,
        stages={
            "repo_acquisition": 0.4, "joern_parse": 21.3, "cpg_load": 3.9,
            "candidate_extraction": 1.8, "context_extraction": 2.4,
            "llm_analysis": 18.1, "deduplication": 0.02, "report_generation": 0.05,
        },
    ),
)

JAVASCRIPT_BASELINE = _report(
    repo="examples/vulnerable_app/javascript",
    languages=["javascript"],
    findings=[
        _finding(
            "js-f1", "app.js", 35, 38, "app.js::program:anonymous",
            "OS Command Injection", "CWE-78", "critical", "high",
            "Query parameter reaches child_process.exec",
            "`req.query.cmd` is forwarded to runReport, which calls exec on it.",
            context_reasoning="runReport is reached from both an allowlisted route and "
                              "this unvalidated one; only the caller distinguishes them.",
            data_flow_summary="req.query.cmd -> runReport(command) -> exec",
        ),
        # FALSE POSITIVE: the canonicalised, safe file route.
        _finding(
            "js-f2", "app.js", 55, 64, "app.js::program:anonymous",
            "Path Traversal", "CWE-22", "medium", "low",
            "User-controlled filename reaches fs.readFile",
            "req.params.filename is used to build a path passed to fs.readFile.",
            context_reasoning="Flagged on the sink pattern; the startsWith containment "
                              "check on the resolved path was not accounted for.",
            data_flow_summary="req.params.filename -> path.resolve -> fs.readFile",
        ),
    ],
    stats=_stats(
        contexts=4, llm_calls=4, duration=39.2,
        stages={
            "repo_acquisition": 0.3, "joern_parse": 17.8, "cpg_load": 3.1,
            "candidate_extraction": 1.4, "context_extraction": 1.9,
            "llm_analysis": 14.6, "deduplication": 0.01, "report_generation": 0.04,
        },
    ),
)

# --------------------------------------------------------------------------
# Improved variant: the safe-sibling false positives are gone and the
# previously missed path-traversal case is now detected. Used to demonstrate
# comparison, regression tracking, and the multi-version table.
# --------------------------------------------------------------------------

PYTHON_IMPROVED = _report(
    repo="examples/vulnerable_app/python",
    languages=["python"],
    findings=[
        PYTHON_BASELINE["findings"][0],
        PYTHON_BASELINE["findings"][1],
        _finding(
            "py-f4", "app.py", 54, 57, "app.py:<module>.build_user_query",
            "SQL Injection", "CWE-89", "high", "medium",
            "Query string built by concatenation",
            "build_user_query interpolates its parameter into SQL. Its only caller "
            "passes an attacker-controlled path segment.",
            context_reasoning="Judged vulnerable only after inspecting the caller; in "
                              "isolation this function is a string builder.",
            data_flow_summary="get_user(user_id) -> build_user_query -> f-string SQL",
        ),
    ],
    stats=_stats(
        contexts=5, llm_calls=5, duration=52.1,
        stages={
            "repo_acquisition": 0.4, "joern_parse": 21.0, "cpg_load": 3.8,
            "candidate_extraction": 1.7, "context_extraction": 2.5,
            "llm_analysis": 22.6, "deduplication": 0.03, "report_generation": 0.05,
        },
    ),
)

JAVASCRIPT_IMPROVED = _report(
    repo="examples/vulnerable_app/javascript",
    languages=["javascript"],
    findings=[
        JAVASCRIPT_BASELINE["findings"][0],
        _finding(
            "js-f3", "app.js", 45, 51, "app.js::program:anonymous",
            "Path Traversal", "CWE-22", "high", "high",
            "Unconstrained path join reaches fs.readFile",
            "req.params.filename is joined onto UPLOAD_ROOT with no canonicalisation, "
            "so `../` sequences escape the upload directory.",
            context_reasoning="Distinguished from the sibling route below it, which "
                              "resolves the path and checks containment first.",
            data_flow_summary="req.params.filename -> path.join(UPLOAD_ROOT, ...) -> fs.readFile",
        ),
    ],
    stats=_stats(
        contexts=4, llm_calls=4, duration=41.7,
        stages={
            "repo_acquisition": 0.3, "joern_parse": 17.5, "cpg_load": 3.2,
            "candidate_extraction": 1.4, "context_extraction": 2.0,
            "llm_analysis": 17.2, "deduplication": 0.01, "report_generation": 0.04,
        },
    ),
)


VARIANTS: dict[str, dict[str, dict]] = {
    "baseline": {
        "example-flask-python": PYTHON_BASELINE,
        "example-express-javascript": JAVASCRIPT_BASELINE,
    },
    "improved": {
        "example-flask-python": PYTHON_IMPROVED,
        "example-express-javascript": JAVASCRIPT_IMPROVED,
    },
}


def write_fixtures(base: Path = FIXTURES_DIR) -> list[Path]:
    written = []
    for variant, cases in VARIANTS.items():
        for case_id, report in cases.items():
            path = base / variant / "raw" / case_id / "cpgvd_output" / "report.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(report, indent=2), encoding="utf-8")
            written.append(path)

    readme = base / "README.md"
    readme.write_text(
        "# Benchmark fixtures\n\n"
        "**Synthetic. Not measurements.** Hand-authored cpgvd reports used to\n"
        "exercise the benchmark framework where Joern and an LLM backend are not\n"
        "available (CI, and any machine without a local model). Regenerate with:\n\n"
        "```bash\npython benchmark/scripts/make_fixtures.py\n```\n\n"
        "Runs produced from these are flagged `synthetic: true` and every rendered\n"
        "report carries a warning banner. Never cite figures derived from them.\n",
        encoding="utf-8",
    )
    written.append(readme)
    return written


if __name__ == "__main__":
    for path in write_fixtures():
        print(f"wrote {path.relative_to(REPO_ROOT)}")
