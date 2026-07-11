"""Command-line entrypoint: repo -> CPG -> context -> LLM -> report."""

from __future__ import annotations

import logging
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
from .models import AnalysisReport, RunStats
from .repo_manager import RepoManager
from .report import write_report
from .rules import DEFAULT_RULES_PATH, load_rules

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
@click.option("--model", default=None, help="Claude model ID to use.")
@click.option("--rules", "rules_path", default=None, type=click.Path(exists=True, path_type=Path), help="Custom sinks_sources.yaml.")
@click.option("--max-contexts", default=None, type=int, help="Cap on how many candidate functions get sent to the LLM.")
@click.option("--no-dataflow", is_flag=True, help="Skip Joern dataflow queries (faster, less precise).")
@click.option("--keep-repo", is_flag=True, help="Don't delete a cloned repo after analysis.")
@click.option("--keep-cpg", is_flag=True, help="Don't delete the generated cpg.bin after analysis.")
@click.option("-v", "--verbose", is_flag=True)
def analyze(
    repo: str,
    language: str | None,
    ref: str | None,
    output_dir: Path | None,
    model: str | None,
    rules_path: Path | None,
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
    if model:
        config.model = model
    if max_contexts:
        config.max_contexts = max_contexts
    if keep_cpg:
        config.keep_cpg = True

    check_joern_available(config)

    repo_manager = RepoManager(config.work_dir)
    console.print(f"[bold]Acquiring[/bold] {repo}...")
    repo_info = repo_manager.acquire(repo, ref=ref)
    lang = language or repo_info.primary_language
    if not lang:
        raise click.ClickException(
            "Could not detect a language for this repo; pass --language explicitly."
        )
    console.print(
        f"  path={repo_info.path} commit={repo_info.commit_sha[:12] or 'n/a'} "
        f"language={lang} (detected: {', '.join(repo_info.languages) or 'none'})"
    )

    rules = load_rules(rules_path or DEFAULT_RULES_PATH)
    if lang not in rules:
        console.print(
            f"[yellow]Warning:[/yellow] no sink/source rules for language '{lang}'; "
            "the CPG will still be built, but no candidate functions will be shortlisted."
        )

    cpg_path = config.work_dir / f"{repo_info.path.name}.cpg.bin"
    console.print("[bold]Parsing repo into a Code Property Graph with Joern...[/bold]")
    parse_repo_to_cpg(repo_info.path, cpg_path, config, language=lang)

    stats = RunStats()
    findings = []

    try:
        with JoernServer(config) as server:
            client = CpgClient(server.host, server.port)
            console.print("[bold]Loading CPG into the Joern query server...[/bold]")
            client.load_cpg(cpg_path)

            extractor = ContextExtractor(client, repo_info.path, rules)
            extractor.load()
            stats.functions_discovered = len(extractor.methods)

            sink_candidates = extractor.find_sink_candidates(lang)
            source_calls = extractor.find_source_calls(lang)
            stats.sink_matches = sum(len(v) for v in sink_candidates.values())
            console.print(
                f"  {stats.functions_discovered} functions, {len(extractor.calls)} calls, "
                f"{stats.sink_matches} sink pattern matches across {len(sink_candidates)} functions"
            )

            prioritized = sorted(sink_candidates.items(), key=lambda kv: len(kv[1]), reverse=True)
            contexts = []
            for full_name, hits in prioritized[: config.max_contexts]:
                method = extractor.method_by_full_name(full_name)
                if method is None:
                    continue
                relevant_sources = [
                    c for c in source_calls if c.containing_method_full_name == full_name
                ] or source_calls  # fall back to any known source calls in the repo
                context = extractor.build_function_context(
                    method,
                    lang,
                    hits,
                    relevant_sources,
                    include_dataflow=not no_dataflow,
                    max_related=config.max_related_functions,
                )
                contexts.append(context)
            stats.candidate_contexts_analyzed = len(contexts)

        console.print(f"[bold]Analyzing {len(contexts)} candidate functions with {config.model}...[/bold]")
        analyzer = LlmAnalyzer(config)
        findings = analyzer.analyze_many(contexts)
        stats.llm_calls = analyzer.usage.calls
        stats.llm_input_tokens = analyzer.usage.input_tokens
        stats.llm_output_tokens = analyzer.usage.output_tokens
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
        model=config.model,
        findings=findings,
        stats=stats,
    )

    paths = write_report(report, config.output_dir)
    _print_summary(report, paths)


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
    console.print(f"\nReports written to:\n  {paths['markdown']}\n  {paths['json']}\n  {paths['sarif']}")


if __name__ == "__main__":
    main()
