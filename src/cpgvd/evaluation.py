"""Score the control-absence detector against the mutation corpus.

For one app:

  1. Run the detector on the UNMUTATED tree. Every finding here is a false
     positive -- nothing was removed. This count is the negative control the
     plan calls non-negotiable: the false-positive rate on unmutated originals.
  2. For each mutation: apply it, run the detector, and check whether a finding
     lands within `match_window` lines of the removed control (and isn't one
     the baseline already reported). Hit -> true positive, miss -> false
     negative. Restore the file.
  3. Aggregate precision / recall / F1 overall and per operator / control class.

Mutations are line-count preserving, so a label's line range maps straight
onto the mutant with no offset bookkeeping.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable

from .config import Config
from .cpg_client import CpgClient
from .models import (
    EvalReport,
    EvalSummary,
    Finding,
    MutationEvalResult,
    MutationRecord,
)
from .mutation import mutation_applied
from .pipeline import RuleSets, _rawify, analyze_contexts, ensure_cpg, extract_contexts, joern_session
from .models import RunStats

logger = logging.getLogger(__name__)
Progress = Callable[[str], None]


def _noop(_m: str) -> None:
    pass


# vulnerability_type / cwe -> the control class the finding is claiming.
_CONTROL_CLASS_HINTS = {
    "authentication": ("authenticat", "not logged in", "unauthenticated", "cwe-306", "login"),
    "authorization": ("authoriz", "role", "privilege", "admin", "rbac", "cwe-862", "cwe-863", "cwe-285"),
    "ownership": ("ownership", "idor", "insecure direct object", "cwe-639", "other user", "belongs to"),
    "session": ("session",),
    "validation": ("validation", "unvalidated", "input validation", "cwe-20"),
}


def _finding_control_classes(f: Finding) -> set[str]:
    blob = f"{f.vulnerability_type} {f.cwe} {f.title} {f.description} {f.data_flow_summary}".lower()
    return {cls for cls, needles in _CONTROL_CLASS_HINTS.items() if any(n in blob for n in needles)}


def _same_file(finding_file: str, label_file: str) -> bool:
    ff = finding_file.replace("\\", "/")
    return ff == label_file or ff.endswith("/" + label_file) or Path(ff).name == Path(label_file).name


def _score_one(
    rec: MutationRecord,
    findings: list[Finding],
    baseline_line_keys: set[tuple[str, int]],
    window: int,
) -> MutationEvalResult:
    res = MutationEvalResult(
        record_id=rec.id,
        operator=rec.operator,
        control_class=rec.control_class,
        file=rec.file,
        line=rec.start_line,
        route_path=rec.route_path,
        n_findings=len(findings),
    )
    lo, hi = rec.start_line - window, rec.end_line + window
    for f in findings:
        if not _same_file(f.file, rec.file):
            continue
        if (Path(f.file).name, f.start_line) in baseline_line_keys:
            continue  # the detector reports this line even with the control present
        if not (lo <= f.start_line <= hi or lo <= f.end_line <= hi):
            continue
        res.detected = True
        res.matched_title = f.title
        res.matched_line = f.start_line
        res.matched_control_ok = rec.control_class in _finding_control_classes(f)
        if res.matched_control_ok:
            break  # prefer a class-matching finding
    return res


def _rate(tp: int, fp: int, fn: int) -> dict:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3)}


def _analyze(client: CpgClient, repo_path: Path, config: Config, rulesets: RuleSets, stats: RunStats) -> list[Finding]:
    cpg_path = ensure_cpg(repo_path, config, "javascript", stats)
    client.load_cpg(cpg_path)
    _, absence_ctx = extract_contexts(
        client, repo_path, "javascript", config, rulesets,
        mode="absence", no_dataflow=True, stats=stats,
    )
    if config.grounding == "raw":
        absence_ctx = [_rawify(c, repo_path) for c in absence_ctx]
    return analyze_contexts(config, [], absence_ctx, stats)


def run_eval(
    repo_path: Path,
    records: list[MutationRecord],
    config: Config,
    *,
    app: str,
    commit_sha: str = "",
    match_window: int = 20,
    progress: Progress = _noop,
) -> EvalReport:
    repo_path = Path(repo_path)
    config.keep_cpg = True  # cache per-mutant CPGs so a re-run is cheap
    rulesets = RuleSets.load("absence")
    model = config.ollama_model if config.llm_provider == "ollama" else config.model

    with joern_session(config) as client:
        progress("baseline: analysing the unmutated tree")
        baseline = _analyze(client, repo_path, config, rulesets, RunStats())
        baseline_line_keys = {(Path(f.file).name, f.start_line) for f in baseline}
        progress(f"baseline: {len(baseline)} finding(s) (all are false positives)")

        results: list[MutationEvalResult] = []
        for i, rec in enumerate(records, 1):
            try:
                with mutation_applied(repo_path, rec):
                    findings = _analyze(client, repo_path, config, rulesets, RunStats())
            except (OSError, ValueError) as e:
                progress(f"[{i}/{len(records)}] {rec.id}: skipped ({e})")
                continue
            res = _score_one(rec, findings, baseline_line_keys, match_window)
            results.append(res)
            progress(
                f"[{i}/{len(records)}] {rec.operator} {rec.control_class} "
                f"{'HIT' if res.detected else 'miss'}"
                + (f" (class {'ok' if res.matched_control_ok else 'mismatch'})" if res.detected else "")
            )

    summary = _summarize(app, commit_sha, records, results, len(baseline))
    return EvalReport(
        model=model,
        mode="absence",
        grounding=config.grounding,
        match_window=match_window,
        summary=summary,
        results=results,
        baseline_findings=baseline,
    )


def _summarize(
    app: str,
    commit_sha: str,
    records: list[MutationRecord],
    results: list[MutationEvalResult],
    baseline_fp: int,
) -> EvalSummary:
    tp = sum(1 for r in results if r.detected)
    fn = len(results) - tp
    # A run's false positives: baseline findings (control present, still flagged)
    # plus any mutant finding that didn't line up with the removed control.
    stray = sum(max(0, r.n_findings - (1 if r.detected else 0)) for r in results)
    fp = baseline_fp + stray

    def bucket(key: Callable[[MutationEvalResult], str]) -> dict[str, dict]:
        out: dict[str, dict] = {}
        for r in results:
            b = out.setdefault(key(r), {"tp": 0, "fn": 0})
            b["tp" if r.detected else "fn"] += 1
        for b in out.values():
            total = b["tp"] + b["fn"]
            b["recall"] = round(b["tp"] / total, 3) if total else 0.0
        return dict(sorted(out.items()))

    overall = _rate(tp, fp, fn)
    return EvalSummary(
        app=app,
        commit_sha=commit_sha,
        n_mutations=len(results),
        baseline_fp=baseline_fp,
        tp=tp,
        fp=fp,
        fn=fn,
        recall=overall["recall"],
        precision=overall["precision"],
        f1=overall["f1"],
        by_operator=bucket(lambda r: r.operator),
        by_control_class=bucket(lambda r: r.control_class),
    )
