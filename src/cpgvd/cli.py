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
@click.option("--repo", "repo_override", default=None, help="App repo URL/path (default: taken from the labels).")
@click.option("--ref", default=None, help="Ref to check out (default: the labels' commit SHA).")
@click.option("--max-mutations", default=None, type=int, help="Cap mutations evaluated (for a quick run).")
@click.option("--match-window", default=20, show_default=True, help="Lines of slack when matching a finding to a removed control.")
@click.option("--grounding", type=click.Choice(["cpg", "raw"]), default="cpg", show_default=True, help="'raw' = ungrounded whole-file baseline (H2).")
@click.option("--out", type=click.Path(path_type=Path), default=None, help="Eval report JSON (default: corpus/eval/<app>[-raw].json).")
@click.option("--keep-repo", is_flag=True)
@click.option("-v", "--verbose", is_flag=True)
def corpus_eval(
    labels: Path,
    repo_override: str | None,
    ref: str | None,
    max_mutations: int | None,
    match_window: int,
    grounding: str,
    out: Path | None,
    keep_repo: bool,
    verbose: bool,
) -> None:
    """Score the control-absence detector against a JSONL of mutation labels.

    Runs the detector once on the unmutated tree (its findings are the
    false-positive negative control), then once per mutation, and reports
    precision / recall / F1 overall and per operator / control class.
    """
    _setup_logging(verbose)
    from .corpus import read_labels
    from .evaluation import run_eval

    records = read_labels(labels)
    if not records:
        raise click.ClickException(f"No mutation labels in {labels}")
    if max_mutations:
        records = records[:max_mutations]
    app = records[0].app
    src = repo_override or records[0].repo
    if not src:
        raise click.ClickException("Labels have no `repo`; pass --repo explicitly.")
    commit_sha = records[0].commit_sha

    config = Config()
    config.grounding = grounding
    check_joern_available(config)
    if config.llm_provider == "ollama":
        check_ollama_available(config)

    repo_manager = RepoManager(config.work_dir)
    console.print(f"[bold]Acquiring[/bold] {src} @ {(ref or commit_sha or 'HEAD')[:12]}")
    repo_info = repo_manager.acquire(src, ref=ref or commit_sha or None)

    try:
        report = run_eval(
            repo_info.path,
            records,
            config,
            app=app,
            commit_sha=commit_sha or repo_info.commit_sha,
            match_window=match_window,
            progress=lambda m: console.print(m),
        )
    finally:
        if not keep_repo:
            repo_manager.cleanup(repo_info)

    suffix = "" if grounding == "cpg" else "-raw"
    out_path = out or (Path("corpus/eval") / f"{app}{suffix}.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")

    s = report.summary
    table = Table(title=f"control-absence eval: {app} ({s.n_mutations} mutations)")
    table.add_column("bucket")
    table.add_column("TP", justify="right")
    table.add_column("FN", justify="right")
    table.add_column("recall", justify="right")
    for name, b in {"OVERALL": {"tp": s.tp, "fn": s.fn, "recall": s.recall}, **s.by_operator}.items():
        table.add_row(name, str(b["tp"]), str(b["fn"]), f"{b['recall']:.2f}")
    console.print(table)
    console.print(
        f"precision={s.precision:.2f}  recall={s.recall:.2f}  f1={s.f1:.2f}  "
        f"[bold]false positives on the unmutated original: {s.baseline_fp}[/bold]"
    )
    console.print(f"\nFull report: {out_path}")


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
