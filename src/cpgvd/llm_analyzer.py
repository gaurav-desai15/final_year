"""Context-aware vulnerability detection using Claude.

This is the "reasoning" half of the pipeline. Where the CPG-side code
(`context_extractor.py`) only has coarse, syntactic sink/source pattern
matching, this module hands the *actual* code, the *actual* call graph
neighborhood, and any *actual* CPG data-flow paths to Claude, and asks it
to judge whether that combination constitutes a real, exploitable
vulnerability -- the kind of judgment call that needs to see how a
function is really used, not just what it contains.
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import threading
import uuid
from dataclasses import dataclass

import anthropic

from .config import Config
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
- `context_reasoning` must explain what in the surrounding call graph or \
  data flow made this finding require *this* context to see -- i.e. why a \
  single-function, no-context scan would have missed or misjudged it. If \
  the vulnerability is obvious from the function alone, say so plainly \
  rather than inventing a cross-function justification.
- If you find nothing worth reporting, return an empty `findings` array. \
  Do not pad output with low-value findings to seem thorough.

Line numbers in findings must be absolute file line numbers (matching the \
line numbers shown next to the target function's code, not 1-indexed \
relative to the snippet)."""

_FINDING_ITEM_SCHEMA = {
    "type": "object",
    "properties": {
        "vulnerability_type": {"type": "string", "description": "Short human name, e.g. 'SQL Injection'"},
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


class LlmAnalyzer:
    def __init__(self, config: Config, client: anthropic.Anthropic | None = None):
        self.config = config
        self.client = client or anthropic.Anthropic()
        self.usage = AnalyzerUsage()
        self._usage_lock = threading.Lock()

    def analyze_context(self, context: FunctionContext) -> list[Finding]:
        user_text = context.to_prompt_text(max_related_chars=self.config.max_context_chars)

        response = self.client.messages.create(
            model=self.config.model,
            max_tokens=4096,
            system=[{"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}],
            thinking={"type": "adaptive"},
            output_config={"effort": self.config.effort, "format": {"type": "json_schema", "schema": RESPONSE_SCHEMA}},
            messages=[{"role": "user", "content": user_text}],
        )

        with self._usage_lock:
            self.usage.calls += 1
            self.usage.input_tokens += response.usage.input_tokens
            self.usage.output_tokens += response.usage.output_tokens

        if response.stop_reason == "refusal":
            logger.warning("Model refused to analyze context %s", context.context_id)
            return []

        text = next((b.text for b in response.content if b.type == "text"), None)
        if not text:
            logger.warning("No text content in response for context %s (stop_reason=%s)", context.context_id, response.stop_reason)
            return []

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            logger.exception("Failed to parse LLM JSON output for context %s", context.context_id)
            return []

        findings = []
        for item in parsed.get("findings", []):
            findings.append(
                Finding(
                    id=str(uuid.uuid4()),
                    context_id=context.context_id,
                    file=context.file,
                    start_line=item.get("start_line") or context.start_line,
                    end_line=item.get("end_line") or context.end_line,
                    function=context.full_name,
                    vulnerability_type=item["vulnerability_type"],
                    cwe=item.get("cwe", ""),
                    severity=Severity(item["severity"]),
                    confidence=Confidence(item["confidence"]),
                    title=item.get("title") or item["vulnerability_type"],
                    description=item["description"],
                    context_reasoning=item.get("context_reasoning", ""),
                    data_flow_summary=item.get("data_flow_summary", ""),
                    suggested_fix=item.get("suggested_fix", ""),
                    model=self.config.model,
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
        return findings

    def _safe_analyze(self, context: FunctionContext) -> list[Finding]:
        try:
            return self.analyze_context(context)
        except anthropic.APIStatusError:
            logger.exception("Anthropic API error analyzing context %s", context.context_id)
            return []
        except Exception:  # noqa: BLE001 - never let one bad context kill the whole run
            logger.exception("Unexpected error analyzing context %s", context.context_id)
            return []
