"""Typed data structures shared across the pipeline."""

from __future__ import annotations

import datetime as _dt
import re as _re
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

# Route paths that are public by convention: the authentication flow itself,
# health/status probes, and static assets. A missing access control on one of
# these is almost always intentional. Used by the control-absence mode to
# avoid the most common false positive (flagging `/login` as unprotected).
_PUBLIC_ROUTE_RE = _re.compile(
    r"^/?(?:"
    r"|login|logout|log-in|log-out|signin|sign-in|signout|sign-out"
    r"|signup|sign-up|register|registration"
    r"|auth(?:[/-].*)?|oauth(?:[/-].*)?|sso(?:[/-].*)?|saml(?:[/-].*)?"
    r"|(?:.*[/-])?callback|(?:forgot|reset)[/-]?password|password[/-](?:forgot|reset)"
    r"|verify[/-]?email|confirm(?:[/-].*)?|activate(?:[/-].*)?"
    r"|health(?:z|check)?|healthcheck|status|ping|ready|readiness|live|liveness|metrics|version|info"
    r"|favicon\.ico|robots\.txt|sitemap\.xml|manifest\.json|\.well-known(?:/.*)?"
    r"|public(?:/.*)?|static(?:/.*)?|assets(?:/.*)?|css(?:/.*)?|js(?:/.*)?"
    r"|img(?:/.*)?|images(?:/.*)?|fonts(?:/.*)?|dist(?:/.*)?|build(?:/.*)?|vendor(?:/.*)?"
    r")/?$",
    _re.IGNORECASE,
)


def is_public_route(path: str) -> bool:
    """True if `path` is a conventionally-public endpoint (auth flow / probe / asset)."""
    return bool(path) and bool(_PUBLIC_ROUTE_RE.match(path.strip()))


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


class ControlTrigger(BaseModel):
    """An operation inside a candidate function that plausibly needs an access
    control before it runs (a route handler, a DB write, a file send, ...).

    Emitted by the control-absence mode. `node_id` is the CPG call node id, so
    a finding can be checked back against the graph.
    """

    operation: str  # route | db_read | db_write | file_send | credential | session
    category: str
    code: str
    file: str
    line: int
    node_id: int
    route_path: str = ""


class GuardEvidence(BaseModel):
    """Syntactic evidence that an access control IS present on/around a
    candidate function -- an auth-middleware call, a role check, an ownership
    comparison, a session guard, a validator.

    The control-absence mode collects every match onto the candidate. An empty
    list is itself the candidate finding: absence is a field, not an inference.
    `node_id` is the CPG call node id when the evidence came from a call, else
    -1 (a source-text regex match with no dedicated node).
    """

    control: str  # authentication | authorization | ownership | session | validation
    category: str
    code: str
    file: str
    line: int
    node_id: int = -1
    scope: str = "handler"  # where it was found: handler | caller


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

    # Control-absence mode only (empty in injection mode).
    control_triggers: list[ControlTrigger] = Field(default_factory=list)
    guard_evidence: list[GuardEvidence] = Field(default_factory=list)
    route_path: str = ""  # set for per-route absence contexts

    # "cpg" (CPG-derived slice) or "raw" (whole file -- the ungrounded H2 baseline).
    grounding: str = "cpg"

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

    def to_absence_prompt_text(self, max_related_chars: int = 4000) -> str:
        """Render this context for the control-absence question.

        Unlike `to_prompt_text` this leads with the operation(s) that need a
        control and the guard evidence found around them, and includes callers
        verbatim (the route-registration site and its middleware chain are
        where an access control usually lives).
        """
        parts = [
            f"### Candidate function: {self.full_name}",
            f"File: {self.file}:{self.start_line}-{self.end_line}",
            f"Parameters: {', '.join(self.parameters) or '(none)'}",
            "",
            "```" + self.language,
            self.code,
            "```",
        ]

        if self.route_path and is_public_route(self.route_path):
            parts.append(
                f"\n### NOTE: `{self.route_path}` matches a conventional PUBLIC endpoint "
                "(authentication flow, health/status probe, or static asset). A missing "
                "access control here is almost always intentional -- do NOT report it "
                "unless the handler demonstrably exposes another user's data or performs "
                "a privileged state change."
            )

        parts.append("\n### Operations found in this function that may require an access control")
        for t in self.control_triggers:
            path = f'  route="{t.route_path}"' if t.route_path else ""
            parts.append(
                f"- [{t.operation}] {t.category} (CPG node {t.node_id}, {t.file}:{t.line}){path}\n"
                f"    {t.code}"
            )

        if self.guard_evidence:
            parts.append("\n### Guard evidence found on this function and its callers")
            for g in self.guard_evidence:
                node = f"CPG node {g.node_id}" if g.node_id >= 0 else "source match"
                parts.append(
                    f"- [{g.control}] {g.category} ({g.scope}, {node}, {g.file}:{g.line})\n"
                    f"    {g.code}"
                )
        else:
            parts.append(
                "\n### Guard evidence found on this function and its callers\n"
                "(none) -- no authentication, authorization, ownership, session or "
                "validation check was detected on this function or any shown caller."
            )

        if self.imports:
            parts.append("\nImports/dependencies visible in this file:")
            parts.append(", ".join(self.imports[:40]))

        if self.callers:
            parts.append("\n### Callers (route registrations / middleware / wrappers)")
            budget = max_related_chars
            for c in self.callers:
                snippet = f"- {c.name} ({c.file}:{c.start_line})\n```{self.language}\n{c.code}\n```"
                budget -= len(snippet)
                if budget < 0:
                    parts.append("- ... additional callers truncated ...")
                    break
                parts.append(snippet)

        return "\n".join(parts)

    def to_raw_prompt_text(self, max_related_chars: int = 4000) -> str:
        """The ungrounded baseline (H2): the whole source file, no CPG-derived
        context. Same question, no call graph / guard extraction / node ids."""
        loc = f"{self.file}:{self.start_line}"
        header = [
            f"### Source file: {self.file}",
            f"The operation to judge is around line {self.start_line}"
            + (f' (route `{self.route_path}`).' if self.route_path else "."),
            "No call graph or guard list has been extracted for you -- read the "
            "file to determine what checks are or aren't applied before that "
            "operation, including middleware on the route registration.",
            "",
            "```" + self.language,
            self.code,
            "```",
        ]
        return "\n".join(header)


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

    # Per-stage wall-clock timings (seconds), filled in by the CLI so an
    # instrumented run shows where the time actually goes. `dataflow_seconds`
    # is a subset of the context-extraction phase, broken out because Joern's
    # `reachableByFlows` is the single most expensive operation in the pipeline.
    clone_seconds: float = 0.0
    cpg_build_seconds: float = 0.0
    cpg_load_seconds: float = 0.0
    context_extraction_seconds: float = 0.0
    dataflow_seconds: float = 0.0
    llm_seconds: float = 0.0

    def stage_breakdown(self) -> list[tuple[str, float]]:
        """Ordered (stage, seconds) pairs for display; omits unmeasured stages."""
        stages = [
            ("clone", self.clone_seconds),
            ("cpg-build", self.cpg_build_seconds),
            ("cpg-load", self.cpg_load_seconds),
            ("context", self.context_extraction_seconds),
            ("dataflow", self.dataflow_seconds),
            ("llm", self.llm_seconds),
        ]
        return [(name, secs) for name, secs in stages if secs > 0.0]


class MutationRecord(BaseModel):
    """One programmatic removal of an access control from an app that had it.

    Each record IS a labelled positive for the control-absence evaluation: the
    file/line/route/control-class are exact because we deleted them. The
    deletion is line-count preserving (removed lines become blank), so
    `start_line`/`end_line` are valid in both the original and the mutant.
    """

    id: str
    app: str
    repo: str = ""
    commit_sha: str = ""
    operator: str  # M1..M5
    control_class: str  # authentication | authorization | ownership | session | validation
    file: str  # repo-relative POSIX path
    start_line: int
    end_line: int
    route_path: str = ""
    original_text: str = ""
    mutated_text: str = ""
    note: str = ""


class MutationEvalResult(BaseModel):
    """Outcome of running the detector on one mutant."""

    record_id: str
    operator: str
    control_class: str
    file: str
    line: int
    route_path: str = ""
    detected: bool = False
    matched_title: str = ""
    matched_line: int = 0
    matched_control_ok: bool = False  # detected finding's class matches the removed one
    n_findings: int = 0


class EvalSummary(BaseModel):
    app: str
    commit_sha: str = ""
    n_mutations: int = 0
    baseline_fp: int = 0  # findings on the UNMUTATED original -- the critical negative control
    tp: int = 0
    fp: int = 0
    fn: int = 0
    recall: float = 0.0
    precision: float = 0.0
    f1: float = 0.0
    by_operator: dict[str, dict] = Field(default_factory=dict)
    by_control_class: dict[str, dict] = Field(default_factory=dict)


class EvalReport(BaseModel):
    generated_at: _dt.datetime = Field(default_factory=lambda: _dt.datetime.now(_dt.timezone.utc))
    model: str = ""
    mode: str = "absence"
    grounding: str = "cpg"
    match_window: int = 20
    summary: EvalSummary
    results: list[MutationEvalResult] = Field(default_factory=list)
    baseline_findings: list[Finding] = Field(default_factory=list)


class AnalysisReport(BaseModel):
    repo: str
    commit_sha: str = ""
    languages: list[str] = Field(default_factory=list)
    model: str = ""
    generated_at: _dt.datetime = Field(default_factory=lambda: _dt.datetime.now(_dt.timezone.utc))
    findings: list[Finding] = Field(default_factory=list)
    stats: RunStats = Field(default_factory=RunStats)

    # The contexts the LLM actually saw. Persisted so findings are checkable
    # against the CPG: an absence finding can be traced to the `guard_evidence`
    # (with node ids) that was, or wasn't, in front of the model.
    contexts: list[FunctionContext] = Field(default_factory=list)

    def findings_by_severity(self) -> dict[str, list[Finding]]:
        buckets: dict[str, list[Finding]] = {}
        for f in self.findings:
            buckets.setdefault(f.severity.value, []).append(f)
        return buckets
