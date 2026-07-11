"""Typed data structures shared across the pipeline."""

from __future__ import annotations

import datetime as _dt
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class CodeRef(BaseModel):
    """A pointer to a location in the source tree."""

    file: str
    start_line: int
    end_line: int
    name: str = ""
    code: str = ""


class DataFlowStep(BaseModel):
    """One statement along a Joern `reachableByFlows` path."""

    file: str
    line_number: Optional[int] = None
    method: str = ""
    code: str = ""


class DataFlowPath(BaseModel):
    """A source -> sink taint path discovered in the CPG."""

    source_description: str
    sink_description: str
    steps: list[DataFlowStep] = Field(default_factory=list)

    def as_text(self) -> str:
        lines = [f"Source: {self.source_description}", f"Sink: {self.sink_description}"]
        for i, step in enumerate(self.steps):
            loc = f"{step.file}:{step.line_number}" if step.line_number else step.file
            lines.append(f"  {i + 1}. [{loc}] ({step.method}) {step.code}")
        return "\n".join(lines)


class FunctionContext(BaseModel):
    """Everything gathered from the CPG about one candidate function.

    This is the unit of work handed to the LLM: the target function's
    code plus enough surrounding call-graph / data-flow context that a
    model can reason about vulnerabilities that only manifest across
    function boundaries (e.g. unsanitized input crossing three calls
    before reaching a sink, or a missing auth check in a caller).
    """

    context_id: str
    language: str
    file: str
    method_name: str
    full_name: str
    start_line: int
    end_line: int
    code: str
    parameters: list[str] = Field(default_factory=list)
    return_type: str = ""

    callers: list[CodeRef] = Field(default_factory=list)
    callees: list[CodeRef] = Field(default_factory=list)
    imports: list[str] = Field(default_factory=list)

    matched_sink_patterns: list[str] = Field(default_factory=list)
    matched_source_patterns: list[str] = Field(default_factory=list)
    data_flow_paths: list[DataFlowPath] = Field(default_factory=list)

    def to_prompt_text(self, max_related_chars: int = 4000) -> str:
        """Render this context as plain text for the LLM prompt."""
        parts = [
            f"### Target function: {self.full_name}",
            f"File: {self.file}:{self.start_line}-{self.end_line}",
            f"Parameters: {', '.join(self.parameters) or '(none)'}",
            "",
            "```" + self.language,
            self.code,
            "```",
        ]

        if self.imports:
            parts.append("\nImports/dependencies visible in this file:")
            parts.append(", ".join(self.imports[:40]))

        if self.matched_sink_patterns:
            parts.append(
                "\nStatic sink patterns matched inside this function: "
                + ", ".join(self.matched_sink_patterns)
            )
        if self.matched_source_patterns:
            parts.append(
                "Static source/taint-origin patterns matched: "
                + ", ".join(self.matched_source_patterns)
            )

        if self.callers:
            parts.append("\n### Callers (who invokes this function)")
            budget = max_related_chars
            for c in self.callers:
                snippet = f"- {c.name} ({c.file}:{c.start_line})\n```{self.language}\n{c.code}\n```"
                budget -= len(snippet)
                if budget < 0:
                    parts.append("- ... additional callers truncated ...")
                    break
                parts.append(snippet)

        if self.callees:
            parts.append("\n### Callees (what this function calls)")
            budget = max_related_chars
            for c in self.callees:
                snippet = f"- {c.name} ({c.file}:{c.start_line})\n```{self.language}\n{c.code}\n```"
                budget -= len(snippet)
                if budget < 0:
                    parts.append("- ... additional callees truncated ...")
                    break
                parts.append(snippet)

        if self.data_flow_paths:
            parts.append("\n### Data-flow paths found by the CPG dataflow engine")
            for i, p in enumerate(self.data_flow_paths):
                parts.append(f"\nPath {i + 1}:")
                parts.append(p.as_text())

        return "\n".join(parts)


class Finding(BaseModel):
    """A single vulnerability finding emitted by the LLM analyzer."""

    id: str
    context_id: str
    file: str
    start_line: int
    end_line: int
    function: str

    vulnerability_type: str
    cwe: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MEDIUM

    title: str
    description: str
    context_reasoning: str = Field(
        default="",
        description="Why this required cross-function/call-graph context to detect.",
    )
    data_flow_summary: str = ""
    suggested_fix: str = ""

    model: str = ""


class RunStats(BaseModel):
    functions_discovered: int = 0
    candidate_contexts_analyzed: int = 0
    sink_matches: int = 0
    llm_calls: int = 0
    llm_input_tokens: int = 0
    llm_output_tokens: int = 0
    duration_seconds: float = 0.0


class AnalysisReport(BaseModel):
    repo: str
    commit_sha: str = ""
    languages: list[str] = Field(default_factory=list)
    model: str = ""
    generated_at: _dt.datetime = Field(default_factory=lambda: _dt.datetime.now(_dt.timezone.utc))
    findings: list[Finding] = Field(default_factory=list)
    stats: RunStats = Field(default_factory=RunStats)

    def findings_by_severity(self) -> dict[str, list[Finding]]:
        buckets: dict[str, list[Finding]] = {}
        for f in self.findings:
            buckets.setdefault(f.severity.value, []).append(f)
        return buckets
