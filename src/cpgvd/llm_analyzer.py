"""Context-aware vulnerability detection using an LLM.

This is the "reasoning" half of the pipeline. Where the CPG-side code
(`context_extractor.py`) only has coarse, syntactic sink/source pattern
matching, this module hands the *actual* code, the *actual* call graph
neighborhood, and any *actual* CPG data-flow paths to an LLM, and asks it
to judge whether that combination constitutes a real, exploitable
vulnerability -- the kind of judgment call that needs to see how a
function is really used, not just what it contains.

The LLM backend is pluggable (see `llm_providers.py`): by default this
runs against a free, local Ollama model, with an optional paid Claude API
backend for higher-quality analysis. Neither the prompt nor the
finding-parsing logic below cares which one is behind `complete_json`.
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import re
import threading
import uuid
from dataclasses import dataclass

from .config import Config
from .llm_providers import BaseProvider, LlmProviderError, build_provider
from .models import Confidence, Finding, FunctionContext, Severity

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are a senior application security engineer performing context-aware \
static analysis. You will be shown one candidate function from a Code \
Property Graph (CPG)-based scan, along with:

- The function's own source code.
- Its direct callers and callees (1-hop call graph neighborhood).
- The file's imports/dependencies.
- Static sink/source patterns that a lightweight regex pass matched inside it.
- Data-flow paths computed by Joern's dataflow engine, if any were found,
  showing a concrete chain of statements from a candidate taint source to
  a candidate sink.

Your job is to decide whether this function, *in the context shown*, has a \
real, exploitable vulnerability -- not whether the sink pattern merely \
appears. Specifically:

- A sink pattern match is NOT itself a vulnerability. `os.system(cmd)` is \
  safe if `cmd` is a hardcoded constant, and dangerous if `cmd` is built \
  from a caller-supplied parameter with no validation/allowlisting.
- Use the callers to determine whether attacker-controlled input can reach \
  this function's parameters, and whether an intervening caller already \
  sanitizes, validates, allowlists, or parameterizes the value.
- Use the callees and data-flow paths to determine whether taint from this \
  function's inputs actually reaches a dangerous sink, or is normalized or \
  independently constrained beforehand (e.g., cast to a validated enum, \
  passed through a safe parameterized-query API, or path-canonicalized \
  and checked against a base directory).
- Only report something you can justify from the concrete evidence you were \
  shown. If the context is insufficient to tell (e.g., a caller is missing \
  or the value's origin is unclear), lower your confidence rather than \
  omitting a plausible finding -- but say so explicitly in \
  `context_reasoning`.
- Do not report generic code-quality issues, style nits, or purely \
  theoretical/defense-in-depth suggestions with no plausible attacker-\
  controlled path. This is a vulnerability scanner, not a linter.
- Internal consistency is mandatory. If your own analysis concludes that \
  the value reaching the sink is hardcoded, that no data-flow path from \
  attacker-controlled input exists, or that the sink is otherwise \
  unreachable by an attacker, then there is NO finding -- do not report \
  it "just in case", and never with high severity or confidence. A \
  finding whose own `data_flow_summary` argues against exploitability \
  must be omitted entirely.
- Hardcoded configuration values (dev-tooling script tags, local \
  hostnames, test fixtures) are not vulnerabilities unless attacker \
  input demonstrably reaches them.
- A redirect, query, command, or other sink whose argument is a \
  hardcoded string literal or a fixed relative path (e.g. \
  `res.redirect("/login")`) is NOT a vulnerability -- the target is not \
  attacker-controllable. Only report Open Redirect when the redirect \
  target is built from request input.
- Do NOT report a data-access / repository / DAO function as "Broken \
  Authentication", "Missing Authorization", or IDOR merely because it \
  accepts an id/user parameter and performs no auth check of its own. \
  Persistence-layer functions legitimately delegate authentication and \
  authorization to their callers (route handlers / middleware). Report \
  an access-control finding only when the shown caller context \
  demonstrates that the entry point actually reaches this function \
  without any auth/ownership check. If the callers that would enforce \
  auth are not shown, say so in `context_reasoning` and lower your \
  confidence -- do not assert Broken Authentication at high confidence \
  from the data-access function alone.
- Do not emit multiple near-identical findings for the same underlying \
  weakness across sibling functions in one file. Report the single \
  strongest instance.
- `context_reasoning` must explain what in the surrounding call graph or \
  data flow made this finding require *this* context to see -- i.e. why a \
  single-function, no-context scan would have missed or misjudged it. If \
  the vulnerability is obvious from the function alone, say so plainly \
  rather than inventing a cross-function justification.
- If you find nothing worth reporting, return an empty `findings` array. \
  Do not pad output with low-value findings to seem thorough.

Respond with JSON only, matching the given schema exactly -- no prose \
before or after the JSON object.

Line numbers in findings must be absolute file line numbers (matching the \
line numbers shown next to the target function's code, not 1-indexed \
relative to the snippet)."""

_FINDING_ITEM_SCHEMA = {
    "type": "object",
    "properties": {
        "vulnerability_type": {
            "type": "string",
            "description": (
                "Short human name only, e.g. 'SQL Injection'. Do NOT include a CWE "
                "identifier here -- put that in the separate `cwe` field."
            ),
        },
        "cwe": {"type": "string", "description": "CWE identifier, e.g. 'CWE-89', or empty string if not applicable"},
        "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "title": {"type": "string"},
        "description": {"type": "string", "description": "What the vulnerability is and how it could be exploited"},
        "context_reasoning": {
            "type": "string",
            "description": "Why call-graph/data-flow context was needed to reach this conclusion",
        },
        "data_flow_summary": {"type": "string", "description": "Source -> sink chain in plain language"},
        "suggested_fix": {"type": "string"},
        "start_line": {"type": "integer"},
        "end_line": {"type": "integer"},
    },
    "required": [
        "vulnerability_type",
        "cwe",
        "severity",
        "confidence",
        "title",
        "description",
        "context_reasoning",
        "data_flow_summary",
        "suggested_fix",
        "start_line",
        "end_line",
    ],
    "additionalProperties": False,
}

RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {"type": "array", "items": _FINDING_ITEM_SCHEMA},
    },
    "required": ["findings"],
    "additionalProperties": False,
}


@dataclass
class AnalyzerUsage:
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0


_CWE_SUFFIX_RE = re.compile(r"\s*\(cwe-\d+\)\s*$", re.IGNORECASE)


def _clean_vulnerability_type(vulnerability_type: str) -> str:
    """Strip a trailing "(CWE-N)" from `vulnerability_type`.

    Local models sometimes embed the CWE id here despite the schema
    instructing them to use the separate `cwe` field instead, producing a
    doubled "SQL Injection (CWE-89) (CWE-89)" once report.py appends the
    `cwe` field on its own -- observed on a real Ollama/qwen2.5-coder run.
    """
    return _CWE_SUFFIX_RE.sub("", vulnerability_type).strip()


# Phrases that assert the *absence* of an attacker-controlled path. A model
# (the local ones especially) sometimes writes exactly this in its own
# data_flow_summary/context_reasoning and still emits a high-confidence
# finding -- observed on a real Ollama/qwen2.5-coder NodeGoat run, where a
# hardcoded dev-tooling config value was reported as high-severity XSS while
# the summary said "There are no data flow paths leading from a potential
# taint source to this sink". Such a finding contradicts itself and is
# dropped. Patterns are kept narrow (assertions of absence only) so that
# e.g. "no evidence of sanitization" in a genuine finding never matches.
_NO_ATTACKER_PATH_RE = re.compile(
    "|".join(
        [
            r"\bno data[- ]?flow paths?\b",
            r"\bnot (?:dynamically generated or )?influenced by (?:external|user|attacker)",
            r"\bcannot be (?:controlled|influenced) by (?:an? )?attacker",
            r"\bno (?:attacker|user)[- ]controlled (?:input|data|value)",
            r"\bnot reachable by (?:an? )?attacker",
        ]
    ),
    re.IGNORECASE,
)


def _asserts_no_attacker_path(item: dict) -> bool:
    """True if the finding's own reasoning says no attacker path exists."""
    text = f"{item.get('data_flow_summary', '')} {item.get('context_reasoning', '')}"
    return bool(_NO_ATTACKER_PATH_RE.search(text))


_CWE_ID_RE = re.compile(r"cwe-\d+", re.IGNORECASE)

_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}
_CONFIDENCE_RANK = {Confidence.HIGH: 2, Confidence.MEDIUM: 1, Confidence.LOW: 0}


def _dedupe_key_class(finding: Finding) -> str:
    """The 'same vulnerability class' half of the dedupe key: the bare CWE id
    when present (models format the cwe field inconsistently, e.g. 'CWE-94'
    vs 'CWE-94: Improper Control...'), else the vulnerability type."""
    m = _CWE_ID_RE.search(finding.cwe)
    if m:
        return m.group(0).upper()
    return finding.vulnerability_type.strip().lower()


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse duplicate findings for the same underlying vulnerability.

    The same sink is often analyzed once per related candidate function (a
    caller and its callee both shortlist it), yielding near-identical
    findings. Two findings are duplicates when they're in the same file,
    the same vulnerability class, and their line ranges overlap; the one
    with the highest severity (then confidence) wins.
    """
    ranked = sorted(
        findings,
        key=lambda f: (_SEVERITY_RANK[f.severity], _CONFIDENCE_RANK[f.confidence]),
        reverse=True,
    )
    kept: list[Finding] = []
    for f in ranked:
        is_dup = any(
            k.file == f.file
            and _dedupe_key_class(k) == _dedupe_key_class(f)
            and k.start_line <= f.end_line
            and f.start_line <= k.end_line
            for k in kept
        )
        if is_dup:
            logger.info("Deduplicating finding %r at %s:%s", f.title, f.file, f.start_line)
        else:
            kept.append(f)
    return kept


def _extract_json_object(text: str) -> str:
    """Best-effort cleanup of an LLM's JSON response.

    Structured-output modes (Anthropic's `output_config.format`, Ollama's
    `format: <schema>`) should already return clean JSON, but local models
    in particular sometimes wrap it in a markdown code fence or add a
    stray sentence -- strip that instead of failing the whole context.
    """
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
        text = text.strip()
    if not text.startswith("{"):
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end != -1 and end > start:
            text = text[start : end + 1]
    return text


class LlmAnalyzer:
    def __init__(self, config: Config, provider: BaseProvider | None = None):
        self.config = config
        self.provider = provider or build_provider(config)
        self.usage = AnalyzerUsage()
        self._usage_lock = threading.Lock()

    def analyze_context(self, context: FunctionContext) -> list[Finding]:
        user_text = context.to_prompt_text(max_related_chars=self.config.max_context_chars)

        result = self.provider.complete_json(SYSTEM_PROMPT, user_text, RESPONSE_SCHEMA)

        with self._usage_lock:
            self.usage.calls += 1
            self.usage.input_tokens += result.input_tokens
            self.usage.output_tokens += result.output_tokens

        if result.refused:
            logger.warning("Model refused to analyze context %s", context.context_id)
            return []

        if not result.text:
            logger.warning("No text content in response for context %s", context.context_id)
            return []

        try:
            parsed = json.loads(_extract_json_object(result.text))
        except json.JSONDecodeError:
            logger.exception("Failed to parse LLM JSON output for context %s", context.context_id)
            return []

        model_name = self.config.ollama_model if self.config.llm_provider == "ollama" else self.config.model

        findings = []
        for item in parsed.get("findings", []):
            if _asserts_no_attacker_path(item):
                logger.info(
                    "Dropping self-contradictory finding %r in %s: its own reasoning "
                    "states no attacker-controlled path exists",
                    item.get("title", item.get("vulnerability_type", "?")),
                    context.context_id,
                )
                continue
            vulnerability_type = _clean_vulnerability_type(item["vulnerability_type"])
            findings.append(
                Finding(
                    id=str(uuid.uuid4()),
                    context_id=context.context_id,
                    file=context.file,
                    start_line=item.get("start_line") or context.start_line,
                    end_line=item.get("end_line") or context.end_line,
                    function=context.full_name,
                    vulnerability_type=vulnerability_type,
                    cwe=item.get("cwe", ""),
                    severity=Severity(item["severity"]),
                    confidence=Confidence(item["confidence"]),
                    title=item.get("title") or vulnerability_type,
                    description=item["description"],
                    context_reasoning=item.get("context_reasoning", ""),
                    data_flow_summary=item.get("data_flow_summary", ""),
                    suggested_fix=item.get("suggested_fix", ""),
                    model=model_name,
                )
            )
        return findings

    def analyze_many(self, contexts: list[FunctionContext]) -> list[Finding]:
        if not contexts:
            return []
        findings: list[Finding] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.llm_concurrency) as pool:
            future_to_ctx = {pool.submit(self._safe_analyze, ctx): ctx for ctx in contexts}
            for future in concurrent.futures.as_completed(future_to_ctx):
                findings.extend(future.result())
        return dedupe_findings(findings)

    def _safe_analyze(self, context: FunctionContext) -> list[Finding]:
        try:
            return self.analyze_context(context)
        except LlmProviderError:
            logger.exception("LLM provider error analyzing context %s", context.context_id)
            return []
        except Exception:  # noqa: BLE001 - never let one bad context kill the whole run
            logger.exception("Unexpected error analyzing context %s", context.context_id)
            return []
