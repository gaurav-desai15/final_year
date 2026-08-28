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
from .context_extractor import ContextExtractor
from .cpg_client import CpgClient
from .joern_runner import JoernServer, check_joern_available, parse_repo_to_cpg
from .llm_analyzer import LlmAnalyzer
from .llm_providers import check_ollama_available
from .models import AnalysisReport, RunStats
from .repo_manager import RepoManager, source_fingerprint
from .report import write_report
from .rules import DEFAULT_RULES_PATH, load_absence_rules, load_rules

console = Console()


def _accumulate_usage(stats: RunStats, usage) -> None:
    stats.llm_calls += usage.calls
    stats.llm_input_tokens += usage.input_tokens
    stats.llm_output_tokens += usage.output_tokens


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

    active_model = config.ollama_model if config.llm_provider == "ollama" else config.model

    check_joern_available(config)
    if config.llm_provider == "ollama":
        check_ollama_available(config)
        console.print(f"[bold]Using free local LLM via Ollama:[/bold] {active_model}")
    else:
        console.print(f"[bold]Using Claude API (paid):[/bold] {active_model}")

    stats = RunStats()
    findings = []

    repo_manager = RepoManager(config.work_dir)
    console.print(f"[bold]Acquiring[/bold] {repo}...")
    _t = time.monotonic()
    repo_info = repo_manager.acquire(repo, ref=ref)
    stats.clone_seconds = time.monotonic() - _t
    lang = language or repo_info.primary_language
    if not lang:
        raise click.ClickException(
            "Could not detect a language for this repo; pass --language explicitly."
        )
    console.print(
        f"  path={repo_info.path} commit={repo_info.commit_sha[:12] or 'n/a'} "
        f"language={lang} (detected: {', '.join(repo_info.languages) or 'none'})"
    )

    want_injection = mode in ("injection", "both")
    want_absence = mode in ("absence", "both")

    rules = load_rules(rules_path or DEFAULT_RULES_PATH)
    absence_rules = load_absence_rules() if want_absence else {}
    if want_injection and lang not in rules:
        console.print(
            f"[yellow]Warning:[/yellow] no sink/source rules for language '{lang}'; "
            "the CPG will still be built, but no candidate functions will be shortlisted."
        )
    if want_absence and lang not in absence_rules:
        console.print(
            f"[yellow]Warning:[/yellow] no control-absence rules for language '{lang}'."
        )

    # Cache the CPG under a content-addressed name so re-running the same repo
    # state (and, crucially for the mutation corpus, a *specific* mutant) skips
    # the most expensive stage. See `source_fingerprint` for why not the SHA.
    fingerprint = source_fingerprint(repo_info.path)
    cpg_path = config.work_dir / f"{repo_info.path.name}-{fingerprint[:16]}.cpg.bin"
    if cpg_path.exists() and cpg_path.stat().st_size > 0:
        console.print(f"[bold]Reusing cached CPG[/bold] {cpg_path.name}")
    else:
        console.print("[bold]Parsing repo into a Code Property Graph with Joern...[/bold]")
        _t = time.monotonic()
        parse_repo_to_cpg(repo_info.path, cpg_path, config, language=lang)
        stats.cpg_build_seconds = time.monotonic() - _t

    try:
        with JoernServer(config) as server:
            client = CpgClient(server.host, server.port)
            console.print("[bold]Loading CPG into the Joern query server...[/bold]")
            _t = time.monotonic()
            client.load_cpg(cpg_path)
            stats.cpg_load_seconds = time.monotonic() - _t

            _t = time.monotonic()
            extractor = ContextExtractor(client, repo_info.path, rules, absence_rules)
            extractor.load()
            stats.functions_discovered = len(extractor.methods)

            injection_contexts: list = []
            absence_contexts: list = []

            if want_injection:
                sink_candidates = extractor.find_sink_candidates(lang)
                source_calls = extractor.find_source_calls(lang)
                stats.sink_matches = sum(len(v) for v in sink_candidates.values())
                console.print(
                    f"  {stats.functions_discovered} functions, {len(extractor.calls)} calls, "
                    f"{stats.sink_matches} sink pattern matches across {len(sink_candidates)} functions"
                )
                prioritized = sorted(sink_candidates.items(), key=lambda kv: len(kv[1]), reverse=True)
                for full_name, hits in prioritized[: config.max_contexts]:
                    method = extractor.method_by_full_name(full_name)
                    if method is None:
                        continue
                    relevant_sources = [
                        c for c in source_calls if c.containing_method_full_name == full_name
                    ]
                    injection_contexts.append(
                        extractor.build_function_context(
                            method,
                            lang,
                            hits,
                            relevant_sources,
                            include_dataflow=not no_dataflow,
                            max_related=config.max_related_functions,
                        )
                    )

            if want_absence:
                triggers = extractor.find_control_triggers(lang)
                trigger_count = sum(len(v) for v in triggers.values())
                console.print(
                    f"  {trigger_count} control-trigger matches across {len(triggers)} functions"
                )
                prioritized_t = sorted(triggers.items(), key=lambda kv: len(kv[1]), reverse=True)
                for full_name, hits in prioritized_t[: config.max_contexts]:
                    method = extractor.method_by_full_name(full_name)
                    if method is None:
                        continue
                    absence_contexts.append(
                        extractor.build_absence_context(
                            method, lang, hits, max_related=config.max_related_functions
                        )
                    )

            contexts = injection_contexts + absence_contexts
            stats.candidate_contexts_analyzed = len(contexts)
            stats.dataflow_seconds = extractor.dataflow_seconds
            # The context phase includes the dataflow queries; report the two
            # separately so a slow run points at the right culprit.
            stats.context_extraction_seconds = max(
                0.0, (time.monotonic() - _t) - extractor.dataflow_seconds
            )

        findings = []
        _t = time.monotonic()
        if injection_contexts:
            console.print(
                f"[bold]Analyzing {len(injection_contexts)} injection candidates with {active_model}...[/bold]"
            )
            inj = LlmAnalyzer(config, mode="injection")
            findings += inj.analyze_many(injection_contexts)
            _accumulate_usage(stats, inj.usage)
        if absence_contexts:
            console.print(
                f"[bold]Analyzing {len(absence_contexts)} control-absence candidates with {active_model}...[/bold]"
            )
            absn = LlmAnalyzer(config, mode="absence")
            findings += absn.analyze_many(absence_contexts)
            _accumulate_usage(stats, absn.usage)
        stats.llm_seconds = time.monotonic() - _t
    finally:
        if not keep_cpg and cpg_path.exists():
            cpg_path.unlink(missing_ok=True)
        if not keep_repo:
            repo_manager.cleanup(repo_info)

    stats.duration_seconds = time.monotonic() - start

    report = AnalysisReport(
        repo=repo_info.source,
        commit_sha=repo_info.commit_sha,
        languages=repo_info.languages or [lang],
        model=active_model,
        findings=findings,
        stats=stats,
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
