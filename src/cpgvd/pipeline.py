"""The analysis pipeline as a reusable unit: CPG -> Joern session -> context
extraction -> LLM.

`cli.analyze` is a thin wrapper over this. The mutation evaluator
(`cli.corpus eval`) reuses the same steps but holds ONE Joern server open
across many mutant repos -- the single biggest saving for a 600-run job, since
a cold JVM per run is ~15s of pure overhead.
"""

from __future__ import annotations

import logging
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator

from .config import Config
from .context_extractor import ContextExtractor
from .cpg_client import CpgClient
from .joern_runner import JoernServer, parse_repo_to_cpg
from .llm_analyzer import LlmAnalyzer
from .models import Finding, FunctionContext, RunStats
from .repo_manager import source_fingerprint
from .rules import (
    DEFAULT_RULES_PATH,
    AbsenceRules,
    LanguageRules,
    load_absence_rules,
    load_rules,
)

logger = logging.getLogger(__name__)

Progress = Callable[[str], None]


def _noop(_msg: str) -> None:
    pass


@dataclass
class AnalysisOutcome:
    findings: list[Finding] = field(default_factory=list)
    contexts: list[FunctionContext] = field(default_factory=list)
    stats: RunStats = field(default_factory=RunStats)


@dataclass
class RuleSets:
    rules: dict[str, LanguageRules]
    absence_rules: dict[str, AbsenceRules]

    @classmethod
    def load(cls, mode: str, rules_path: Path | None = None) -> "RuleSets":
        want_absence = mode in ("absence", "both")
        return cls(
            rules=load_rules(rules_path or DEFAULT_RULES_PATH),
            absence_rules=load_absence_rules() if want_absence else {},
        )


def cpg_path_for(repo_path: Path, config: Config) -> Path:
    """Content-addressed CPG path for the current state of `repo_path`."""
    fp = source_fingerprint(repo_path)
    return config.work_dir / f"{Path(repo_path).name}-{fp[:16]}.cpg.bin"


def ensure_cpg(repo_path: Path, config: Config, lang: str, stats: RunStats, progress: Progress = _noop) -> Path:
    cpg_path = cpg_path_for(repo_path, config)
    if cpg_path.exists() and cpg_path.stat().st_size > 0:
        progress(f"Reusing cached CPG {cpg_path.name}")
        return cpg_path
    progress("Parsing repo into a Code Property Graph with Joern...")
    t = time.monotonic()
    parse_repo_to_cpg(Path(repo_path), cpg_path, config, language=lang)
    stats.cpg_build_seconds += time.monotonic() - t
    return cpg_path


@contextmanager
def joern_session(config: Config) -> Iterator[CpgClient]:
    with JoernServer(config) as server:
        yield CpgClient(server.host, server.port)


def _prioritize_absence(items: list[tuple[str, list]]) -> list[tuple[str, list]]:
    """Route handlers first (a missing control on a route is the headline
    case), then by trigger count."""
    def key(kv: tuple[str, list]) -> tuple:
        has_route = any(getattr(h, "operation", "") == "route" for h in kv[1])
        return (0 if has_route else 1, -len(kv[1]))

    return sorted(items, key=key)


def extract_contexts(
    client: CpgClient,
    repo_path: Path,
    lang: str,
    config: Config,
    rulesets: RuleSets,
    *,
    mode: str,
    no_dataflow: bool,
    stats: RunStats,
    progress: Progress = _noop,
) -> tuple[list[FunctionContext], list[FunctionContext]]:
    want_injection = mode in ("injection", "both")
    want_absence = mode in ("absence", "both")

    t = time.monotonic()
    extractor = ContextExtractor(client, Path(repo_path), rulesets.rules, rulesets.absence_rules)
    extractor.load()
    stats.functions_discovered = len(extractor.methods)

    injection_contexts: list[FunctionContext] = []
    absence_contexts: list[FunctionContext] = []

    if want_injection:
        sink_candidates = extractor.find_sink_candidates(lang)
        source_calls = extractor.find_source_calls(lang)
        stats.sink_matches = sum(len(v) for v in sink_candidates.values())
        progress(
            f"  {stats.functions_discovered} functions, {len(extractor.calls)} calls, "
            f"{stats.sink_matches} sink matches across {len(sink_candidates)} functions"
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
        progress(
            f"  {sum(len(v) for v in triggers.values())} control-trigger matches "
            f"across {len(triggers)} functions"
        )
        for full_name, hits in _prioritize_absence(list(triggers.items()))[: config.max_contexts]:
            method = extractor.method_by_full_name(full_name)
            if method is None:
                continue
            absence_contexts.append(
                extractor.build_absence_context(
                    method, lang, hits, max_related=config.max_related_functions
                )
            )

    stats.candidate_contexts_analyzed = len(injection_contexts) + len(absence_contexts)
    stats.dataflow_seconds += extractor.dataflow_seconds
    stats.context_extraction_seconds += max(
        0.0, (time.monotonic() - t) - extractor.dataflow_seconds
    )
    return injection_contexts, absence_contexts


def analyze_contexts(
    config: Config,
    injection_contexts: list[FunctionContext],
    absence_contexts: list[FunctionContext],
    stats: RunStats,
    progress: Progress = _noop,
) -> list[Finding]:
    findings: list[Finding] = []
    t = time.monotonic()
    if injection_contexts:
        progress(f"Analyzing {len(injection_contexts)} injection candidates...")
        inj = LlmAnalyzer(config, mode="injection")
        findings += inj.analyze_many(injection_contexts)
        _add_usage(stats, inj.usage)
    if absence_contexts:
        progress(f"Analyzing {len(absence_contexts)} control-absence candidates...")
        absn = LlmAnalyzer(config, mode="absence")
        findings += absn.analyze_many(absence_contexts)
        _add_usage(stats, absn.usage)
    stats.llm_seconds += time.monotonic() - t
    return findings


def _add_usage(stats: RunStats, usage) -> None:
    stats.llm_calls += usage.calls
    stats.llm_input_tokens += usage.input_tokens
    stats.llm_output_tokens += usage.output_tokens


def run_pipeline(
    repo_path: Path,
    config: Config,
    *,
    mode: str,
    lang: str,
    rulesets: RuleSets | None = None,
    no_dataflow: bool = False,
    client: CpgClient | None = None,
    progress: Progress = _noop,
) -> AnalysisOutcome:
    """CPG -> Joern -> context -> LLM for one repo state.

    If `client` is given the caller owns the Joern server and it is reused;
    this call still (re)loads the CPG for `repo_path`'s current contents.
    """
    rulesets = rulesets or RuleSets.load(mode, None)
    stats = RunStats()
    cpg_path = ensure_cpg(Path(repo_path), config, lang, stats, progress)

    def _work(cl: CpgClient) -> tuple[list[FunctionContext], list[FunctionContext]]:
        t = time.monotonic()
        cl.load_cpg(cpg_path)
        stats.cpg_load_seconds += time.monotonic() - t
        return extract_contexts(
            cl, repo_path, lang, config, rulesets,
            mode=mode, no_dataflow=no_dataflow, stats=stats, progress=progress,
        )

    if client is not None:
        inj_ctx, abs_ctx = _work(client)
    else:
        with joern_session(config) as cl:
            inj_ctx, abs_ctx = _work(cl)

    findings = analyze_contexts(config, inj_ctx, abs_ctx, stats, progress)
    if not config.keep_cpg:
        cpg_path.unlink(missing_ok=True)
    return AnalysisOutcome(findings=findings, contexts=inj_ctx + abs_ctx, stats=stats)
