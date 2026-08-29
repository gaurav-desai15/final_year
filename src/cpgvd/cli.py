"""Command-line entrypoint: repo -> CPG -> context -> LLM -> report."""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from .config import Config
from .joern_runner import check_joern_available
from .llm_providers import check_ollama_available
from .models import AnalysisReport
from .pipeline import RuleSets, run_pipeline
from .repo_manager import RepoManager
from .report import write_report

console = Console()


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(message)s",
        handlers=[RichHandler(console=console, show_path=verbose)],
    )


@click.group()
def main() -> None:
    """cpgvd: CPG-based, context-aware vulnerability detector."""


@main.command()
@click.argument("repo")
@click.option("--language", default=None, help="Force a language instead of auto-detecting (e.g. python, javascript, java).")
@click.option("--ref", default=None, help="Branch, tag, or commit to check out.")
@click.option("--output-dir", default=None, type=click.Path(path_type=Path), help="Where to write reports.")
@click.option(
    "--provider",
    type=click.Choice(["ollama", "anthropic"]),
    default=None,
    help="LLM backend: 'ollama' (free, local, default) or 'anthropic' (paid, needs ANTHROPIC_API_KEY).",
)
@click.option("--model", default=None, help="Model ID for the selected provider (Ollama tag or Claude model ID).")
@click.option("--rules", "rules_path", default=None, type=click.Path(exists=True, path_type=Path), help="Custom sinks_sources.yaml.")
@click.option(
    "--mode",
    type=click.Choice(["injection", "absence", "both"]),
    default="injection",
    help="'injection' (taint -> sink, default), 'absence' (missing access control), or 'both'.",
)
@click.option(
    "--grounding",
    type=click.Choice(["cpg", "raw"]),
    default="cpg",
    help="'cpg' (default): LLM sees the CPG context slice. 'raw': whole source file -- the ungrounded H2 baseline.",
)
@click.option("--max-contexts", default=None, type=int, help="Cap on how many candidate functions get sent to the LLM.")
@click.option("--no-dataflow", is_flag=True, help="Skip Joern dataflow queries (faster, less precise). Implied by --mode absence.")
@click.option("--keep-repo", is_flag=True, help="Don't delete a cloned repo after analysis.")
@click.option(
    "--keep-cpg/--no-keep-cpg",
    "keep_cpg",
    default=True,
    help="Cache the generated cpg.bin under the work dir for reuse (default: keep). "
    "--no-keep-cpg deletes it after the run.",
)
@click.option("-v", "--verbose", is_flag=True)
def analyze(
    repo: str,
    language: str | None,
    ref: str | None,
    output_dir: Path | None,
    provider: str | None,
    model: str | None,
    rules_path: Path | None,
    mode: str,
    grounding: str,
    max_contexts: int | None,
    no_dataflow: bool,
    keep_repo: bool,
    keep_cpg: bool,
    verbose: bool,
) -> None:
    """Analyze REPO (a GitHub URL or local path) for context-aware vulnerabilities."""
    _setup_logging(verbose)
    start = time.monotonic()

    config = Config()
    if output_dir:
        config.output_dir = output_dir
    if provider:
        config.llm_provider = provider
    if model:
        if config.llm_provider == "ollama":
            config.ollama_model = model
        else:
            config.model = model
    if max_contexts:
        config.max_contexts = max_contexts
    config.keep_cpg = keep_cpg
    config.grounding = grounding

    active_model = config.ollama_model if config.llm_provider == "ollama" else config.model

    check_joern_available(config)
    if config.llm_provider == "ollama":
        check_ollama_available(config)
        console.print(f"[bold]Using free local LLM via Ollama:[/bold] {active_model}")
    else:
        console.print(f"[bold]Using Claude API (paid):[/bold] {active_model}")

    repo_manager = RepoManager(config.work_dir)
    console.print(f"[bold]Acquiring[/bold] {repo}...")
    _t = time.monotonic()
    repo_info = repo_manager.acquire(repo, ref=ref)
    clone_seconds = time.monotonic() - _t
    lang = language or repo_info.primary_language
    if not lang:
        raise click.ClickException(
            "Could not detect a language for this repo; pass --language explicitly."
        )
    console.print(
        f"  path={repo_info.path} commit={repo_info.commit_sha[:12] or 'n/a'} "
        f"language={lang} (detected: {', '.join(repo_info.languages) or 'none'})"
    )

    rulesets = RuleSets.load(mode, rules_path)
    if mode in ("injection", "both") and lang not in rulesets.rules:
        console.print(f"[yellow]Warning:[/yellow] no sink/source rules for language '{lang}'.")
    if mode in ("absence", "both") and lang not in rulesets.absence_rules:
        console.print(f"[yellow]Warning:[/yellow] no control-absence rules for language '{lang}'.")

    try:
        outcome = run_pipeline(
            repo_info.path,
            config,
            mode=mode,
            lang=lang,
            rulesets=rulesets,
            no_dataflow=no_dataflow,
            progress=lambda m: console.print(m),
        )
        from .metrics import compression_summary, grounded_findings_ratio

        metrics = {
            "compression": compression_summary(outcome.contexts, repo_info.path),
            "grounded_findings": grounded_findings_ratio(outcome.findings, outcome.contexts),
        }
    finally:
        if not keep_repo:
            repo_manager.cleanup(repo_info)

    stats = outcome.stats
    stats.clone_seconds = clone_seconds
    stats.duration_seconds = time.monotonic() - start
    findings = outcome.findings

    report = AnalysisReport(
        repo=repo_info.source,
        commit_sha=repo_info.commit_sha,
        languages=repo_info.languages or [lang],
        model=active_model,
        findings=findings,
        stats=stats,
        contexts=outcome.contexts,
        metrics=metrics,
    )

    paths = write_report(report, config.output_dir)
    _print_summary(report, paths)


@main.group()
def corpus() -> None:
    """Build and inspect the mutation corpus for the control-absence eval."""


@corpus.command("mutate")
@click.argument("repo")
@click.option("--app", default=None, help="Corpus name for this app (default: repo basename).")
@click.option("--ref", default=None, help="Branch/tag/commit to check out.")
@click.option(
    "--out",
    type=click.Path(path_type=Path),
    default=None,
    help="JSONL labels output (default: corpus/labels/<app>.jsonl).",
)
@click.option("--verify/--no-verify", default=True, help="Drop mutations whose mutant fails `node --check`.")
@click.option("--keep-repo", is_flag=True, help="Don't delete a cloned repo afterwards.")
@click.option("-v", "--verbose", is_flag=True)
def corpus_mutate(
    repo: str,
    app: str | None,
    ref: str | None,
    out: Path | None,
    verify: bool,
    keep_repo: bool,
    verbose: bool,
) -> None:
    """Enumerate M1-M5 control-removal mutations for REPO and write JSONL labels.

    REPO is a GitHub URL or local path. Each label is exact ground truth: file,
    line range, route path, control class, and the original source removed.
    """
    _setup_logging(verbose)
    from .corpus import summarize_json, write_labels
    from .mutation import find_mutations, verify_mutations

    config = Config()
    repo_manager = RepoManager(config.work_dir)
    console.print(f"[bold]Acquiring[/bold] {repo}...")
    repo_info = repo_manager.acquire(repo, ref=ref)
    app_name = app or repo_info.path.name

    try:
        records = find_mutations(
            repo_info.path, app_name, commit_sha=repo_info.commit_sha, repo=repo_info.source
        )
        console.print(f"  {len(records)} candidate mutations")
        if verify:
            records = verify_mutations(repo_info.path, records)
            console.print(f"  {len(records)} survive `node --check`")
    finally:
        if not keep_repo:
            repo_manager.cleanup(repo_info)

    out_path = out or (Path("corpus/labels") / f"{app_name}.jsonl")
    write_labels(records, out_path)
    console.print(f"[bold]Wrote[/bold] {out_path}")
    console.print_json(summarize_json(records))


@corpus.command("collect")
@click.option("--from-list", "from_list", type=click.Path(exists=True, path_type=Path), default=None, help="A file of repo URLs (one per line) -- skip GitHub search.")
@click.option("--min-stars", default=50, show_default=True)
@click.option("--pushed-after", default="2024-01-01", show_default=True, help="ISO date; repo must have activity since.")
@click.option("--limit", default=35, show_default=True, help="How many screened apps to keep.")
@click.option("--max-search", default=180, show_default=True, help="How many search hits to screen.")
@click.option("--dest", type=click.Path(path_type=Path), default=Path("corpus/repos"), show_default=True)
@click.option("--manifest", type=click.Path(path_type=Path), default=Path("corpus/manifest.jsonl"), show_default=True)
@click.option("--mutate/--no-mutate", default=True, help="Also run the mutation harness on each app.")
@click.option("--verify/--no-verify", default=True, help="Drop mutations that fail `node --check`.")
@click.option("--min-mutations", default=5, show_default=True, help="Drop cloned apps that yield fewer mutations (frameworks / boilerplates).")
@click.option("-v", "--verbose", is_flag=True)
def corpus_collect(
    from_list: Path | None,
    min_stars: int,
    pushed_after: str,
    limit: int,
    max_search: int,
    dest: Path,
    manifest: Path,
    mutate: bool,
    verify: bool,
    min_mutations: int,
    verbose: bool,
) -> None:
    """Collect Express+auth apps, clone them, and (by default) mutate.

    Either from GitHub search (needs GITHUB_TOKEN for a real run) or from a
    curated URL list via --from-list.
    """
    _setup_logging(verbose)
    import shutil

    from .corpus import summarize, write_labels
    from .corpus_collect import (
        GitHubClient, candidate_from_url, clone_candidate, find_candidates,
        parse_repo_list, screen_local, token_from_env, write_manifest,
    )
    from .mutation import find_mutations, verify_mutations

    if from_list:
        urls = parse_repo_list(from_list.read_text(encoding="utf-8"))
        cands = [candidate_from_url(u) for u in urls]
        console.print(f"[bold]From list:[/bold] {len(cands)} repos -- screening after clone")
        screen_after_clone = True
    else:
        token = token_from_env()
        if not token:
            console.print("[yellow]No GITHUB_TOKEN set[/yellow] -- expect rate limiting after ~10 requests.")
        console.print(f"[bold]Searching[/bold] stars>={min_stars}, pushed>={pushed_after} ...")
        cands = find_candidates(
            GitHubClient(token=token),
            min_stars=min_stars, pushed_after=pushed_after, max_search=max_search, limit=limit,
        )
        console.print(f"  {len(cands)} apps passed API screening")
        screen_after_clone = False

    all_records: list = []
    kept: list = []
    for i, cand in enumerate(cands, 1):
        try:
            clone_candidate(cand, dest)
        except Exception as e:  # noqa: BLE001 - a dead repo shouldn't kill the batch
            console.print(f"  [{i}/{len(cands)}] {cand.full_name}: clone failed ({e})")
            continue
        if screen_after_clone and not screen_local(cand, Path(cand.local_path)):
            console.print(f"  [{i}/{len(cands)}] {cand.full_name}: not an Express+auth app / non-permissive -- dropped")
            shutil.rmtree(cand.local_path, ignore_errors=True)
            continue
        if not mutate:
            kept.append(cand)
            console.print(f"  [{i}/{len(cands)}] {cand.full_name}: cloned")
            continue
        records = find_mutations(
            Path(cand.local_path), cand.app, commit_sha=cand.commit_sha, repo=cand.clone_url
        )
        if verify:
            records = verify_mutations(Path(cand.local_path), records)
        if len(records) < min_mutations:
            console.print(f"  [{i}/{len(cands)}] {cand.full_name}: only {len(records)} mutations -- dropped")
            shutil.rmtree(cand.local_path, ignore_errors=True)
            continue
        kept.append(cand)
        write_labels(records, Path("corpus/labels") / f"{cand.app}.jsonl")
        all_records.extend(records)
        console.print(f"  [{i}/{len(cands)}] {cand.full_name}: {len(records)} mutations")

    write_manifest(kept, manifest)
    console.print(f"[bold]Manifest:[/bold] {manifest}  ({len(kept)} apps kept)")
    if mutate and all_records:
        console.print_json(data=summarize(all_records))


@corpus.command("eval")
@click.argument("labels", type=click.Path(exists=True, path_type=Path))
@click.option("--repo", "repo_override", default=None, help="App repo URL/path (single-file only; default: from the labels).")
@click.option("--ref", default=None, help="Ref to check out (default: the labels' commit SHA).")
@click.option("--max-mutations", default=None, type=int, help="Cap mutations per app (for a quick run).")
@click.option("--match-window", default=20, show_default=True, help="Lines of slack when matching a finding to a removed control.")
@click.option("--grounding", type=click.Choice(["cpg", "raw"]), default="cpg", show_default=True, help="'raw' = ungrounded whole-file baseline (H2).")
@click.option("--out-dir", type=click.Path(path_type=Path), default=Path("corpus/eval"), show_default=True)
@click.option("--skip-existing", is_flag=True, help="Skip an app whose <app>[-raw].json is already in --out-dir (resume a paced run).")
@click.option("--keep-repo", is_flag=True)
@click.option("-v", "--verbose", is_flag=True)
def corpus_eval(
    labels: Path,
    repo_override: str | None,
    ref: str | None,
    max_mutations: int | None,
    match_window: int,
    grounding: str,
    out_dir: Path,
    skip_existing: bool,
    keep_repo: bool,
    verbose: bool,
) -> None:
    """Score the control-absence detector against mutation labels.

    LABELS is a JSONL file or a directory of them. For each app: run the
    detector on the unmutated tree (findings there are the FP negative
    control), then once per mutation, and report precision / recall / F1
    overall and per operator. A directory run also writes an aggregate.
    """
    _setup_logging(verbose)
    import json as _json

    from .corpus import read_labels
    from .evaluation import run_eval

    label_files = sorted(labels.glob("*.jsonl")) if labels.is_dir() else [labels]
    if not label_files:
        raise click.ClickException(f"No .jsonl label files under {labels}")

    config = Config()
    config.grounding = grounding
    check_joern_available(config)
    if config.llm_provider == "ollama":
        check_ollama_available(config)
    out_dir.mkdir(parents=True, exist_ok=True)
    suffix = "" if grounding == "cpg" else "-raw"

    repo_manager = RepoManager(config.work_dir)
    summaries = []
    for lf in label_files:
        records = read_labels(lf)
        if not records:
            continue
        if max_mutations:
            records = records[:max_mutations]
        app = records[0].app
        existing = out_dir / f"{app}{suffix}.json"
        if skip_existing and existing.exists():
            from .models import EvalReport

            summaries.append(EvalReport.model_validate_json(existing.read_text()).summary)
            console.print(f"[dim]{app}: already done, using {existing.name}[/dim]")
            continue
        # Prefer an already-cloned repo under corpus/repos/<app> -- no network,
        # and no re-clone per app. Fall back to the labels' URL.
        local = Path("corpus/repos") / app
        src = repo_override or (str(local) if local.is_dir() else records[0].repo)
        if not src:
            console.print(f"[yellow]{app}: labels have no repo; skipping[/yellow]")
            continue
        commit_sha = records[0].commit_sha
        is_local = Path(src).is_dir()
        console.print(
            f"\n[bold]=== {app} ({len(records)} mutations, grounding={grounding}) ==="
            f"[/bold]  {'(local clone)' if is_local else src}"
        )
        if is_local:
            # undo any mutation a previous crashed run left applied in place
            subprocess.run(["git", "-C", src, "checkout", "--", "."], capture_output=True, check=False)
        repo_info = repo_manager.acquire(src, ref=None if is_local else (ref or commit_sha or None))
        try:
            report = run_eval(
                repo_info.path, records, config, app=app,
                commit_sha=commit_sha or repo_info.commit_sha,
                match_window=match_window, progress=lambda m: console.print(m),
            )
        finally:
            if not keep_repo and not is_local:
                repo_manager.cleanup(repo_info)
        (out_dir / f"{app}{suffix}.json").write_text(report.model_dump_json(indent=2), encoding="utf-8")
        s = report.summary
        summaries.append(s)
        console.print(
            f"  {app}: precision={s.precision:.2f} recall={s.recall:.2f} f1={s.f1:.2f} "
            f"baseline_fp={s.baseline_fp}"
        )

    if not summaries:
        raise click.ClickException("No apps evaluated.")

    tp = sum(s.tp for s in summaries)
    fp = sum(s.fp for s in summaries)
    fn = sum(s.fn for s in summaries)
    base = sum(s.baseline_fp for s in summaries)
    n_mut = sum(s.n_mutations for s in summaries)
    tp_raw = round(sum(s.recall_raw * s.n_mutations for s in summaries))
    by_op: dict[str, dict] = {}
    for s in summaries:
        for op, b in s.by_operator.items():
            d = by_op.setdefault(op, {"tp": 0, "fn": 0})
            d["tp"] += b["tp"]
            d["fn"] += b["fn"]
    for b in by_op.values():
        t = b["tp"] + b["fn"]
        b["recall"] = round(b["tp"] / t, 3) if t else 0.0
    prec = round(tp / (tp + fp), 3) if (tp + fp) else 0.0
    rec = round(tp / (tp + fn), 3) if (tp + fn) else 0.0
    f1 = round(2 * prec * rec / (prec + rec), 3) if (prec + rec) else 0.0
    def _mean(vals):
        vals = [v for v in vals if v is not None]
        return round(sum(vals) / len(vals), 4) if vals else None

    agg = {
        "grounding": grounding,
        "apps": len(summaries),
        "mutations": n_mut,
        "tp": tp, "fp": fp, "fn": fn,
        "baseline_fp_total": base,
        "precision": prec, "recall": rec, "f1": f1,
        "recall_raw": round(tp_raw / n_mut, 3) if n_mut else 0.0,
        "compression_slice_over_file_mean": _mean(
            [s.compression.get("slice_over_file_mean") for s in summaries]
        ),
        "grounded_findings_ratio_mean": _mean(
            [s.grounded_findings.get("ratio") for s in summaries]
        ),
        "by_operator": dict(sorted(by_op.items())),
        "per_app": {
            s.app: {
                "precision": s.precision, "recall": s.recall, "recall_raw": s.recall_raw,
                "f1": s.f1, "baseline_fp": s.baseline_fp,
                "slice_over_file": s.compression.get("slice_over_file_mean"),
                "grounded_ratio": s.grounded_findings.get("ratio"),
            }
            for s in summaries
        },
    }
    agg_path = out_dir / f"_aggregate{suffix}.json"
    agg_path.write_text(_json.dumps(agg, indent=2), encoding="utf-8")

    table = Table(title=f"AGGREGATE ({grounding}): {len(summaries)} apps, {tp + fn} mutations")
    for col in ("bucket", "TP", "FN", "recall"):
        table.add_column(col, justify="right" if col != "bucket" else "left")
    table.add_row("OVERALL", str(tp), str(fn), f"{rec:.2f}")
    for op, b in sorted(by_op.items()):
        table.add_row(op, str(b["tp"]), str(b["fn"]), f"{b['recall']:.2f}")
    console.print(table)
    console.print(
        f"[bold]precision={prec:.2f}  recall={rec:.2f} (raw {agg['recall_raw']:.2f})  "
        f"f1={f1:.2f}  FP on unmutated originals: {base}[/bold]\n{agg_path}"
    )


@corpus.command("eval-semgrep")
@click.argument("labels", type=click.Path(exists=True, path_type=Path))
@click.option("--repo", "repo_override", default=None)
@click.option("--ref", default=None)
@click.option("--max-mutations", default=None, type=int)
@click.option("--match-window", default=20, show_default=True)
@click.option("--out-dir", type=click.Path(path_type=Path), default=Path("corpus/eval"), show_default=True)
@click.option("--skip-existing", is_flag=True)
@click.option("--keep-repo", is_flag=True)
@click.option("-v", "--verbose", is_flag=True)
def corpus_eval_semgrep(
    labels: Path, repo_override, ref, max_mutations, match_window, out_dir, skip_existing, keep_repo, verbose
) -> None:
    """Rule-only baseline (plan comparative axis 2): score Semgrep's
    unprotected-route rule against the same mutation labels. Fast -- no Joern,
    no LLM, no cooldown needed."""
    _setup_logging(verbose)
    import json as _json

    from .baselines import semgrep_available
    from .corpus import read_labels
    from .evaluation import run_eval_semgrep

    if not semgrep_available():
        raise click.ClickException("semgrep not on PATH -- `pip install semgrep`.")

    label_files = sorted(labels.glob("*.jsonl")) if labels.is_dir() else [labels]
    out_dir.mkdir(parents=True, exist_ok=True)
    repo_manager = RepoManager(Config().work_dir)
    summaries = []
    for lf in label_files:
        records = read_labels(lf)
        if not records:
            continue
        if max_mutations:
            records = records[:max_mutations]
        app = records[0].app
        existing = out_dir / f"{app}-semgrep.json"
        if skip_existing and existing.exists():
            from .models import EvalReport

            summaries.append(EvalReport.model_validate_json(existing.read_text()).summary)
            continue
        src = repo_override or records[0].repo
        if not src:
            continue
        repo_info = repo_manager.acquire(src, ref=ref or records[0].commit_sha or None)
        try:
            report = run_eval_semgrep(
                repo_info.path, records, app=app,
                commit_sha=records[0].commit_sha or repo_info.commit_sha,
                match_window=match_window, progress=lambda m: console.print(m),
            )
        finally:
            if not keep_repo:
                repo_manager.cleanup(repo_info)
        existing.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        s = report.summary
        summaries.append(s)
        console.print(f"  {app}: precision={s.precision:.2f} recall={s.recall:.2f} f1={s.f1:.2f} baseline_fp={s.baseline_fp}")

    if not summaries:
        raise click.ClickException("nothing evaluated")
    tp = sum(s.tp for s in summaries); fp = sum(s.fp for s in summaries); fn = sum(s.fn for s in summaries)
    prec = round(tp / (tp + fp), 3) if (tp + fp) else 0.0
    rec = round(tp / (tp + fn), 3) if (tp + fn) else 0.0
    f1 = round(2 * prec * rec / (prec + rec), 3) if (prec + rec) else 0.0
    agg = {
        "detector": "semgrep", "apps": len(summaries), "mutations": tp + fn,
        "tp": tp, "fp": fp, "fn": fn, "baseline_fp_total": sum(s.baseline_fp for s in summaries),
        "precision": prec, "recall": rec, "f1": f1,
        "by_operator": {},
        "per_app": {s.app: {"precision": s.precision, "recall": s.recall, "f1": s.f1, "baseline_fp": s.baseline_fp} for s in summaries},
    }
    for s in summaries:
        for op, b in s.by_operator.items():
            d = agg["by_operator"].setdefault(op, {"tp": 0, "fn": 0})
            d["tp"] += b["tp"]; d["fn"] += b["fn"]
    for b in agg["by_operator"].values():
        t = b["tp"] + b["fn"]
        b["recall"] = round(b["tp"] / t, 3) if t else 0.0
    (out_dir / "_aggregate-semgrep.json").write_text(_json.dumps(agg, indent=2), encoding="utf-8")
    console.print(
        f"[bold]SEMGREP baseline: precision={prec:.2f} recall={rec:.2f} f1={f1:.2f} "
        f"FP-on-originals={agg['baseline_fp_total']}[/bold]"
    )


@corpus.command("report")
@click.option("--eval-dir", type=click.Path(exists=True, path_type=Path), default=Path("corpus/eval"), show_default=True)
@click.option("--out", type=click.Path(path_type=Path), default=Path("corpus/eval/RESULTS.md"), show_default=True)
def corpus_report(eval_dir: Path, out: Path) -> None:
    """Roll every eval JSON into one Markdown comparison table (cpgvd grounded
    vs ungrounded vs semgrep, overall + per operator, H3/H5)."""
    from .results import build_markdown

    md = build_markdown(eval_dir)
    out.write_text(md, encoding="utf-8")
    console.print(md)
    console.print(f"\n[bold]Written:[/bold] {out}")


@corpus.command("stats")
@click.argument("labels", nargs=-1, type=click.Path(exists=True, path_type=Path))
@click.option("--holdout-frac", default=0.3, show_default=True)
def corpus_stats(labels: tuple[Path, ...], holdout_frac: float) -> None:
    """Summarize one or more JSONL label files and show the by-app split."""
    from .corpus import read_labels, split_by_app, summarize

    records = []
    for path in labels or (Path("corpus/labels"),):
        if path.is_dir():
            for jsonl in sorted(path.glob("*.jsonl")):
                records += read_labels(jsonl)
        else:
            records += read_labels(path)

    train, holdout = split_by_app(records, holdout_frac=holdout_frac)
    console.print_json(
        data={
            "total": summarize(records),
            "train": summarize(train),
            "holdout": summarize(holdout),
        }
    )


@main.command()
@click.option(
    "--report",
    "report_path",
    default="cpgvd_output/report.json",
    type=click.Path(path_type=Path),
    help="Path to a report.json written by `cpgvd analyze`.",
)
def dashboard(report_path: Path) -> None:
    """Launch a Streamlit dashboard to browse a report.json interactively.

    Requires the 'dashboard' extra: pip install -e ".[dashboard]"
    """
    if shutil.which("streamlit") is None:
        raise click.ClickException(
            "streamlit isn't installed. Run: pip install -e \".[dashboard]\""
        )
    dashboard_script = Path(__file__).parent / "dashboard.py"
    cmd = [sys.executable, "-m", "streamlit", "run", str(dashboard_script), "--", "--report", str(report_path)]
    console.print(f"[bold]Launching dashboard[/bold] for {report_path} ...")
    subprocess.run(cmd, check=False)


def _print_summary(report: AnalysisReport, paths: dict[str, Path]) -> None:
    table = Table(title=f"cpgvd: {len(report.findings)} finding(s) in {report.repo}")
    table.add_column("Severity")
    table.add_column("Type")
    table.add_column("Location")
    table.add_column("Confidence")

    from .report import sorted_findings

    for f in sorted_findings(report):
        table.add_row(f.severity.value.upper(), f.vulnerability_type, f"{f.file}:{f.start_line}", f.confidence.value)

    console.print(table)

    breakdown = report.stats.stage_breakdown()
    if breakdown:
        timing = Table(title=f"Stage timings (total {report.stats.duration_seconds:.1f}s)")
        timing.add_column("Stage")
        timing.add_column("Seconds", justify="right")
        for name, secs in breakdown:
            timing.add_row(name, f"{secs:.1f}")
        console.print(timing)

    console.print(f"\nReports written to:\n  {paths['markdown']}\n  {paths['json']}\n  {paths['sarif']}")


if __name__ == "__main__":
    main()
