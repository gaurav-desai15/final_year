"""Score the control-absence detector on a held-out app against its own
published vulnerability list.

The mutation corpus (`evaluation.py`) is built by *removing* controls we
inserted the labels for -- useful, but the apps in it are also the apps we
tune the rules and prompt against. This module is the other half of B6: a
held-out app (OWASP Juice Shop) whose missing controls are described by an
*external* authority -- Juice Shop's challenge list, cross-referenced with the
`vuln-code-snippet vuln-line` markers in its own source. We never tune against
it, so the number is not self-graded.

There is no baseline/negative-control step here: nothing was mutated, so we
cannot call a stray finding a false positive with confidence (Juice Shop is
deliberately riddled with vulnerabilities our labels don't enumerate). We
report recall against the labelled set, per control class, plus the count of
findings that matched no label (context, not a clean FP rate).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable

import yaml

from .config import Config
from .evaluation import _analyze, _finding_control_classes, _same_file
from .models import Finding, HeldoutLabel, HeldoutLabelResult, HeldoutReport, RunStats
from .pipeline import RuleSets, joern_session

logger = logging.getLogger(__name__)
Progress = Callable[[str], None]


def _noop(_m: str) -> None:
    pass


def load_labels(path: Path) -> tuple[str, str, list[HeldoutLabel]]:
    """Parse a held-out label file. Returns (app, commit_sha, labels)."""
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    app = doc.get("app") or Path(path).stem
    commit = str(doc.get("commit", ""))
    labels = [HeldoutLabel.model_validate(row) for row in doc.get("labels", [])]
    return app, commit, labels


def _score_label(label: HeldoutLabel, findings: list[Finding], window: int) -> HeldoutLabelResult:
    res = HeldoutLabelResult(
        challenge=label.challenge,
        control_class=label.control_class,
        file=label.file,
        line=label.line,
    )
    lo, hi = label.line - window, label.line + window
    for f in findings:
        if not _same_file(f.file, label.file):
            continue
        if not (lo <= f.start_line <= hi or lo <= f.end_line <= hi):
            continue
        classes = _finding_control_classes(f)
        # Prefer a class-matching finding if there is one; otherwise take the
        # first positional hit.
        if not res.detected or (label.control_class in classes and not res.matched_control_ok):
            res.detected = True
            res.matched_title = f.title
            res.matched_line = f.start_line
            res.matched_control_ok = label.control_class in classes
        if res.matched_control_ok:
            break
    return res


def _label_spans(labels: list[HeldoutLabel], window: int) -> list[tuple[str, int, int]]:
    return [(Path(lab.file).name, lab.line - window, lab.line + window) for lab in labels]


def score_heldout(
    repo_path: Path,
    labels: list[HeldoutLabel],
    config: Config,
    *,
    app: str,
    commit_sha: str = "",
    match_window: int = 20,
    progress: Progress = _noop,
) -> HeldoutReport:
    repo_path = Path(repo_path)
    config.keep_cpg = True
    rulesets = RuleSets.load("absence")
    model = config.ollama_model if config.llm_provider == "ollama" else config.model

    with joern_session(config) as client:
        progress(f"analysing {app} ({'raw' if config.grounding == 'raw' else 'cpg'})")
        findings, _ctx = _analyze(client, repo_path, config, rulesets, RunStats())
    progress(f"{len(findings)} finding(s); scoring against {len(labels)} label(s)")

    results = [_score_label(lab, findings, match_window) for lab in labels]
    for lab, r in zip(labels, results):
        progress(
            f"  {lab.challenge}: {'HIT' if r.detected else 'miss'}"
            + (f" (class {'ok' if r.matched_control_ok else 'mismatch'})" if r.detected else "")
        )

    n_detected = sum(1 for r in results if r.detected)
    class_ok = sum(1 for r in results if r.matched_control_ok)

    # Findings that didn't land near any label -- reported as context, not a
    # false-positive rate (see module docstring).
    spans = _label_spans(labels, match_window)
    unmatched = 0
    for f in findings:
        fname = Path(f.file).name
        if not any(fname == n and lo <= f.start_line <= hi for n, lo, hi in spans):
            unmatched += 1

    by_class: dict[str, dict] = {}
    for r in results:
        b = by_class.setdefault(r.control_class, {"tp": 0, "fn": 0})
        b["tp" if r.detected else "fn"] += 1
    for b in by_class.values():
        t = b["tp"] + b["fn"]
        b["recall"] = round(b["tp"] / t, 3) if t else 0.0

    return HeldoutReport(
        app=app,
        commit_sha=commit_sha,
        model=model,
        grounding=config.grounding,
        match_window=match_window,
        n_labels=len(labels),
        n_detected=n_detected,
        recall=round(n_detected / len(labels), 3) if labels else 0.0,
        class_ok_rate=round(class_ok / n_detected, 3) if n_detected else 0.0,
        n_findings_total=len(findings),
        n_findings_unmatched=unmatched,
        by_control_class=dict(sorted(by_class.items())),
        results=results,
        findings=findings,
    )
