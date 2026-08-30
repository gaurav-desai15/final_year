"""Turns a loaded CPG into `FunctionContext` bundles worth showing to the LLM.

Design notes
------------
We deliberately do the *sink/source pattern matching* in plain Python
against a flat list of calls fetched from the CPG in one query
(`list_calls`), rather than issuing one Scala query per regex rule. That
keeps the number of CPGQL round-trips small and constant (not
O(rules x languages)), and makes the matching logic itself unit-testable
without a live Joern server.

The one place we can't avoid talking to Joern per-candidate is data-flow:
computing an actual `reachableByFlows` taint path from a source to a sink
requires the CPG's dataflow engine, so `fetch_dataflow_paths` issues one
targeted query per candidate function.

Source code shown to the LLM is read directly off disk by line range
(rather than trusting a CPG `code` property, whose exact semantics differ
across language frontends) -- this is simpler and easier to reason about.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from .cpg_client import CpgClient
from .models import (
    CodeRef,
    ControlTrigger,
    DataFlowPath,
    DataFlowStep,
    FunctionContext,
    GuardEvidence,
)
from .rules import AbsenceRules, LanguageRules, Rule

logger = logging.getLogger(__name__)

# Files that are in the repo but are not the running application: dependencies,
# build output, test/fixture code, and vendored copies of route-wiring used as
# teaching material (OWASP Juice Shop ships these under data/static/codefixes/,
# and without this filter the absence detector builds its route contexts from
# the fixture copy instead of server.ts). Matched against the CPG `filename`
# (repo-relative POSIX path).
_NON_APP_PATH_RE = re.compile(
    r"(^|/)(?:node_modules|bower_components|vendor|third_party|dist|build|out|lib-cov"
    r"|coverage|\.next|\.nuxt|\.output|__tests__|__mocks__|tests?|spec|e2e|cypress"
    r"|fixtures?|__fixtures__|\.git)/"
    r"|(?:^|/)data/static/codefixes/"
    r"|\.(?:test|spec)\.[cm]?[jt]sx?$"
    r"|\.min\.js$",
    re.IGNORECASE,
)


def is_app_file(filename: str) -> bool:
    """True unless `filename` is dependency / build / test / fixture code."""
    if not filename or filename == "<empty>":
        return False
    return _NON_APP_PATH_RE.search(filename.replace("\\", "/")) is None


_IMPORT_PATTERNS: dict[str, re.Pattern] = {
    "python": re.compile(r"^\s*(?:import\s+[\w.]+|from\s+[\w.]+\s+import\s+.+)", re.MULTILINE),
    "javascript": re.compile(r"^\s*(?:import\s+.+from\s+['\"].+['\"]|(?:const|let|var)\s+.+require\(['\"].+['\"]\))", re.MULTILINE),
    "typescript": re.compile(r"^\s*import\s+.+from\s+['\"].+['\"]", re.MULTILINE),
    "java": re.compile(r"^\s*import\s+[\w.]+;", re.MULTILINE),
    "go": re.compile(r"^\s*\"[\w./-]+\"\s*$", re.MULTILINE),
    "php": re.compile(r"^\s*(?:use\s+[\w\\]+;|require(?:_once)?\s*\(.+\)|include(?:_once)?\s*\(.+\))", re.MULTILINE),
    "ruby": re.compile(r"^\s*require(?:_relative)?\s+['\"].+['\"]", re.MULTILINE),
    "csharp": re.compile(r"^\s*using\s+[\w.]+;", re.MULTILINE),
    "c": re.compile(r"^\s*#include\s+[<\"].+[>\"]", re.MULTILINE),
    "cpp": re.compile(r"^\s*#include\s+[<\"].+[>\"]", re.MULTILINE),
}


@dataclass
class RawMethod:
    id: int
    name: str
    full_name: str
    filename: str
    start_line: int
    end_line: int
    parameters: list[str] = field(default_factory=list)
    return_type: str = ""


@dataclass
class RawCall:
    id: int
    name: str
    code: str
    filename: str
    line_number: int
    callee_full_name: str
    containing_method_full_name: str


@dataclass
class SinkHit:
    call: RawCall
    category: str
    cwe: str
    pattern: str
    severity: str = ""  # set for `--mode hygiene` hits; blank for taint sinks


@dataclass
class TriggerHit:
    """A control-absence trigger match: an operation inside a method that may
    need an access control."""

    call: RawCall
    category: str
    operation: str
    pattern: str
    route_path: str = ""


_ROUTE_PATH_RE = re.compile(r"""['"]([^'"]{1,200})['"]""")
_ROUTE_VERB_RE = re.compile(r"\b(?:app|router)\s*\.\s*(get|post|put|patch|delete|all)\s*\(", re.IGNORECASE)


def _split_call_args(code: str) -> list[str]:
    """Top-level argument strings of the first call in `code`.

    `app.get('/x', mwA, mwB, handler)` -> ["'/x'", " mwA", " mwB", " handler"].
    Brace/bracket/paren/string aware so an inline `function (req, res) {...}`
    handler stays one argument.
    """
    open_paren = code.find("(")
    if open_paren == -1:
        return []
    depth = 0
    i = open_paren
    n = len(code)
    args: list[str] = []
    cur: list[str] = []
    while i < n:
        c = code[i]
        if c in "\"'`":
            j = i + 1
            while j < n and code[j] != c:
                j += 2 if code[j] == "\\" else 1
            cur.append(code[i : j + 1])
            i = j + 1
            continue
        if c in "([{":
            depth += 1
            if depth == 1 and c == "(":
                i += 1
                continue
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                args.append("".join(cur))
                return args
        if c == "," and depth == 1:
            args.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    if cur:
        args.append("".join(cur))
    return args


class _GuardAcc:
    """Accumulates GuardEvidence, de-duplicating on (control, file, line, code)."""

    def __init__(self) -> None:
        self._seen: set[tuple[str, str, int, str]] = set()
        self.items: list[GuardEvidence] = []

    def add(self, *, control: str, category: str, code: str, file: str, line: int, node_id: int, scope: str) -> None:
        code = code.strip()
        key = (control, file, line, code)
        if key in self._seen:
            return
        self._seen.add(key)
        self.items.append(
            GuardEvidence(
                control=control, category=category, code=code[:400],
                file=file, line=line, node_id=node_id, scope=scope,
            )
        )


_METHOD_LIST_QUERY = r"""
cpg.method.isExternal(false).filter(m => m.lineNumber.isDefined && m.filename != "<empty>").map(m =>
  "{" +
  "\"id\":" + m.id + "," +
  "\"name\":\"" + cpgvdEscape(m.name) + "\"," +
  "\"fullName\":\"" + cpgvdEscape(m.fullName) + "\"," +
  "\"filename\":\"" + cpgvdEscape(m.filename) + "\"," +
  "\"lineNumber\":" + m.lineNumber.getOrElse(-1) + "," +
  "\"lineNumberEnd\":" + m.lineNumberEnd.getOrElse(-1) + "," +
  "\"parameters\":[" + m.parameter.name.l.map(p => "\"" + cpgvdEscape(p) + "\"").mkString(",") + "]," +
  "\"returnType\":\"" + cpgvdEscape(m.methodReturn.typeFullName) + "\"" +
  "}"
).l.mkString("[", ",", "]")
"""

_CALL_LIST_QUERY = r"""
cpg.call.filter(c => c.lineNumber.isDefined).map(c =>
  "{" +
  "\"id\":" + c.id + "," +
  "\"name\":\"" + cpgvdEscape(c.name) + "\"," +
  "\"code\":\"" + cpgvdEscape(c.code) + "\"," +
  "\"filename\":\"" + cpgvdEscape(c.file.name.headOption.getOrElse("")) + "\"," +
  "\"lineNumber\":" + c.lineNumber.getOrElse(-1) + "," +
  "\"calleeFullName\":\"" + cpgvdEscape(c.methodFullName) + "\"," +
  "\"containingMethodFullName\":\"" + cpgvdEscape(c.method.fullName) + "\"" +
  "}"
).l.mkString("[", ",", "]")
"""

_DATAFLOW_PRELUDE = "import io.joern.dataflowengineoss.language._"


def _scala_id_list(ids: list[int]) -> str:
    return ", ".join(str(i) for i in ids)


def _dataflow_query(sink_call_id: int, method_full_name: str, source_call_ids: list[int], max_paths: int) -> str:
    method_lit = method_full_name.replace("\\", "\\\\").replace('"', '\\"')
    source_ids_lit = _scala_id_list(source_call_ids) if source_call_ids else ""
    return rf"""
{_DATAFLOW_PRELUDE}
val cpgvdSink = cpg.call.id({sink_call_id}).l
val cpgvdParamSources = cpg.method.fullNameExact("{method_lit}").parameter.l
val cpgvdCallSources = cpg.call.id({source_ids_lit}).l
val cpgvdSources = (cpgvdParamSources ++ cpgvdCallSources).l
cpgvdSink.reachableByFlows(cpgvdSources).take({max_paths}).l.map(path =>
  path.elements.map(e =>
    "{{" +
    "\"code\":\"" + cpgvdEscape(e.code) + "\"," +
    "\"lineNumber\":" + e.lineNumber.getOrElse(-1) + "," +
    "\"filename\":\"" + cpgvdEscape(e.file.name.headOption.getOrElse("")) + "\"," +
    "\"method\":\"" + cpgvdEscape(e.method.fullName) + "\"" +
    "}}"
  ).mkString("[", ",", "]")
).mkString("[", ",", "]")
"""


class ContextExtractor:
    def __init__(
        self,
        client: CpgClient,
        repo_root: Path,
        rules: dict[str, LanguageRules],
        absence_rules: dict[str, AbsenceRules] | None = None,
        hygiene_rules: dict[str, list[Rule]] | None = None,
    ):
        self.client = client
        self.repo_root = Path(repo_root)
        self.rules = rules
        self.absence_rules = absence_rules or {}
        self.hygiene_rules = hygiene_rules or {}
        self._methods_by_id: dict[int, RawMethod] = {}
        self._methods_by_full_name: dict[str, RawMethod] = {}
        self._calls: list[RawCall] = []
        # Accumulated wall-clock time spent in `reachableByFlows` dataflow
        # queries, so the CLI can report it as its own pipeline stage.
        self.dataflow_seconds: float = 0.0

    # -- CPG-backed fetch -------------------------------------------------

    def load(self) -> None:
        self._methods_by_id = {}
        self._methods_by_full_name = {}
        skipped_files: set[str] = set()
        for raw in self.client.run_json(_METHOD_LIST_QUERY):
            if not is_app_file(raw["filename"]):
                skipped_files.add(raw["filename"])
                continue
            m = RawMethod(
                id=raw["id"],
                name=raw["name"],
                full_name=raw["fullName"],
                filename=raw["filename"],
                start_line=raw["lineNumber"],
                end_line=raw["lineNumberEnd"] if raw["lineNumberEnd"] > 0 else raw["lineNumber"],
                parameters=raw.get("parameters", []),
                return_type=raw.get("returnType", ""),
            )
            self._methods_by_id[m.id] = m
            self._methods_by_full_name[m.full_name] = m

        self._calls = [
            RawCall(
                id=raw["id"],
                name=raw["name"],
                code=raw["code"],
                filename=raw["filename"],
                line_number=raw["lineNumber"],
                callee_full_name=raw["calleeFullName"],
                containing_method_full_name=raw["containingMethodFullName"],
            )
            for raw in self.client.run_json(_CALL_LIST_QUERY)
            if is_app_file(raw["filename"])
        ]
        logger.info(
            "Loaded %d methods, %d calls from CPG (skipped %d non-app file(s): dep/build/test/fixture)",
            len(self._methods_by_id), len(self._calls), len(skipped_files),
        )

    @property
    def methods(self) -> list[RawMethod]:
        return list(self._methods_by_id.values())

    @property
    def calls(self) -> list[RawCall]:
        return list(self._calls)

    def method_by_full_name(self, full_name: str) -> RawMethod | None:
        return self._methods_by_full_name.get(full_name)

    # -- Pure-python matching / graph building -----------------------------

    def find_sink_candidates(self, language: str) -> dict[str, list[SinkHit]]:
        """Return containing-method full_name -> list of sink hits inside it."""
        lang_rules = self.rules.get(language)
        if lang_rules is None:
            logger.warning("No sink/source rules configured for language %r", language)
            return {}

        by_method: dict[str, list[SinkHit]] = {}
        for call in self._calls:
            for rule in lang_rules.sinks:
                if rule.pattern.search(call.code) or rule.pattern.search(call.name):
                    by_method.setdefault(call.containing_method_full_name, []).append(
                        SinkHit(call=call, category=rule.category, cwe=rule.cwe, pattern=rule.raw_pattern)
                    )
                    break
        return by_method

    def find_hygiene_candidates(self, language: str) -> dict[str, list[SinkHit]]:
        """`--mode hygiene`: containing-method full_name -> flagged 'dangerous
        pattern present' hits (weak crypto, disabled TLS, hardcoded secret,
        debug flag). Same shape as sink candidates; no source/taint needed."""
        checks = self.hygiene_rules.get(language)
        if not checks:
            logger.warning("No hygiene rules configured for language %r", language)
            return {}
        by_method: dict[str, list[SinkHit]] = {}
        for call in self._calls:
            for rule in checks:
                if rule.pattern.search(call.code) or rule.pattern.search(call.name):
                    by_method.setdefault(call.containing_method_full_name, []).append(
                        SinkHit(
                            call=call, category=rule.category, cwe=rule.cwe,
                            pattern=rule.raw_pattern, severity=rule.severity,
                        )
                    )
                    break
        return by_method

    def find_source_calls(self, language: str) -> list[RawCall]:
        lang_rules = self.rules.get(language)
        if lang_rules is None:
            return []
        hits = []
        for call in self._calls:
            for rule in lang_rules.sources:
                if rule.pattern.search(call.code) or rule.pattern.search(call.name):
                    hits.append(call)
                    break
        return hits

    # -- Control-absence matching ----------------------------------------

    def find_control_triggers(self, language: str) -> dict[str, list[TriggerHit]]:
        """Return containing-method full_name -> control-absence trigger hits."""
        lang_rules = self.absence_rules.get(language)
        if lang_rules is None:
            logger.warning("No control-absence rules configured for language %r", language)
            return {}

        by_method: dict[str, list[TriggerHit]] = {}
        for call in self._calls:
            for rule in lang_rules.triggers:
                if rule.pattern.search(call.code) or rule.pattern.search(call.name):
                    route_path = ""
                    if rule.operation == "route":
                        m = _ROUTE_PATH_RE.search(call.code)
                        route_path = m.group(1) if m else ""
                    by_method.setdefault(call.containing_method_full_name, []).append(
                        TriggerHit(
                            call=call,
                            category=rule.category,
                            operation=rule.operation,
                            pattern=rule.raw_pattern,
                            route_path=route_path,
                        )
                    )
                    break
        return by_method

    def _calls_in(self, method_full_name: str) -> list[RawCall]:
        return [c for c in self._calls if c.containing_method_full_name == method_full_name]

    def _scan_guards_call(self, acc: _GuardAcc, call: RawCall, guards, scope: str) -> None:
        for rule in guards:
            if rule.pattern.search(call.code) or rule.pattern.search(call.name):
                acc.add(
                    control=rule.control, category=rule.category, code=call.code,
                    file=call.filename, line=call.line_number, node_id=call.id, scope=scope,
                )
                return

    def _scan_guards_text(self, acc: _GuardAcc, text: str, file: str, first_line: int, guards, scope: str, node_id: int = -1) -> None:
        for offset, line in enumerate(text.splitlines()):
            for rule in guards:
                if rule.pattern.search(line):
                    acc.add(
                        control=rule.control, category=rule.category, code=line,
                        file=file, line=first_line + offset, node_id=node_id, scope=scope,
                    )
                    break

    def _scan_guards_method_body(self, acc: _GuardAcc, method: RawMethod, guards, scope: str) -> None:
        for call in self._calls_in(method.full_name):
            self._scan_guards_call(acc, call, guards, scope)
        src = self.read_source(method.filename, method.start_line, method.end_line, max_lines=200)
        self._scan_guards_text(acc, src, method.filename, method.start_line, guards, scope)

    def _resolve_handler(self, handler_expr: str) -> RawMethod | None:
        """Map a route handler argument (`ctrl.displayFoo`, `displayFoo`) to its method."""
        name = re.split(r"[.\s(\[]", handler_expr.strip())[-1].strip()
        if not name.isidentifier() or name in ("function", "async"):
            return None
        cands = [m for m in self._methods_by_id.values() if m.name == name]
        if not cands:
            return None
        cands.sort(key=lambda m: (m.name == "<module>", "handler" not in m.filename and "route" not in m.filename, m.filename))
        return cands[0]

    def _control_triggers_in(self, method_full_name: str, language: str) -> list[ControlTrigger]:
        lang_rules = self.absence_rules.get(language)
        if lang_rules is None:
            return []
        out: list[ControlTrigger] = []
        for call in self._calls_in(method_full_name):
            for rule in lang_rules.triggers:
                if rule.operation == "route":
                    continue
                if rule.pattern.search(call.code) or rule.pattern.search(call.name):
                    out.append(
                        ControlTrigger(
                            operation=rule.operation, category=rule.category, code=call.code,
                            file=call.filename, line=call.line_number, node_id=call.id,
                        )
                    )
                    break
        return out

    def collect_guard_evidence(self, method: RawMethod, language: str) -> list[GuardEvidence]:
        """Every guard-pattern match on `method`, its route-registration sites,
        and its direct callers -- for a per-method (non-route) candidate.

        A route handler is *passed as an argument* to `app.get(path, mw, handler)`
        so it has no call-graph caller; we find calls whose code names this
        method and read the middleware list out of that call's code. Matches
        come from the flat call list (keeping the CPG node id) and a regex pass
        over source text (comparisons / decorators that aren't calls).
        """
        lang_rules = self.absence_rules.get(language)
        if lang_rules is None:
            return []
        acc = _GuardAcc()

        name_re = re.compile(rf"\b{re.escape(method.name)}\b") if method.name else None
        if name_re is not None:
            for call in self._calls:
                if call.containing_method_full_name == method.full_name:
                    continue
                if name_re.search(call.code):
                    self._scan_guards_call(acc, call, lang_rules.guards, "route-middleware")

        self._scan_guards_method_body(acc, method, lang_rules.guards, "handler")
        for c in self.callers_of(method.full_name)[:8]:
            self._scan_guards_method_body(acc, c, lang_rules.guards, "caller")
        return acc.items

    def callers_of(self, method_full_name: str) -> list[RawMethod]:
        caller_names = {
            c.containing_method_full_name for c in self._calls if c.callee_full_name == method_full_name
        }
        return [self._methods_by_full_name[n] for n in caller_names if n in self._methods_by_full_name]

    def callees_of(self, method_full_name: str) -> list[RawMethod]:
        callee_names = {
            c.callee_full_name for c in self._calls if c.containing_method_full_name == method_full_name
        }
        return [self._methods_by_full_name[n] for n in callee_names if n in self._methods_by_full_name]

    # -- Source text / imports ----------------------------------------------

    def read_source(self, filename: str, start_line: int, end_line: int, max_lines: int = 400) -> str:
        path = self._resolve_path(filename)
        if path is None or not path.exists():
            return ""
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return ""
        start = max(1, start_line)
        end = min(len(lines), end_line if end_line >= start else start)
        if end - start > max_lines:
            end = start + max_lines
        return "\n".join(lines[start - 1 : end])

    def extract_imports(self, filename: str, language: str) -> list[str]:
        path = self._resolve_path(filename)
        if path is None or not path.exists():
            return []
        pattern = _IMPORT_PATTERNS.get(language)
        if pattern is None:
            return []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        return [m.group(0).strip() for m in pattern.finditer(text)][:50]

    def _resolve_path(self, filename: str) -> Path | None:
        if not filename or filename == "<empty>":
            return None
        p = Path(filename)
        if p.is_absolute() and p.exists():
            return p
        candidate = self.repo_root / filename
        if candidate.exists():
            return candidate
        # Joern sometimes reports paths relative to the CPG input root already
        return candidate

    # -- Dataflow -------------------------------------------------------

    def fetch_dataflow_paths(
        self,
        sink_hits: list[SinkHit],
        method: RawMethod,
        source_calls: list[RawCall],
        max_paths_per_sink: int = 3,
        max_source_ids: int = 20,
    ) -> list[DataFlowPath]:
        started = time.monotonic()
        try:
            return self._fetch_dataflow_paths(
                sink_hits, method, source_calls, max_paths_per_sink, max_source_ids
            )
        finally:
            self.dataflow_seconds += time.monotonic() - started

    def _fetch_dataflow_paths(
        self,
        sink_hits: list[SinkHit],
        method: RawMethod,
        source_calls: list[RawCall],
        max_paths_per_sink: int,
        max_source_ids: int,
    ) -> list[DataFlowPath]:
        source_ids = [c.id for c in source_calls[:max_source_ids]]
        paths: list[DataFlowPath] = []
        for hit in sink_hits:
            query = _dataflow_query(hit.call.id, method.full_name, source_ids, max_paths_per_sink)
            try:
                raw_paths = self.client.run_json(query)
            except Exception:  # noqa: BLE001 - dataflow queries can legitimately fail/timeout on huge graphs
                logger.exception("Dataflow query failed for sink call %s", hit.call.id)
                continue
            for raw_path in raw_paths:
                if not raw_path:
                    continue
                steps = [
                    DataFlowStep(
                        file=e.get("filename", ""),
                        line_number=e.get("lineNumber") if e.get("lineNumber", -1) >= 0 else None,
                        method=e.get("method", ""),
                        code=e.get("code", ""),
                    )
                    for e in raw_path
                ]
                paths.append(
                    DataFlowPath(
                        source_description=steps[0].code if steps else "unknown source",
                        sink_description=f"{hit.category}: {hit.call.code}",
                        steps=steps,
                    )
                )
        return paths

    # -- Assembly ---------------------------------------------------------

    def build_function_context(
        self,
        method: RawMethod,
        language: str,
        sink_hits: list[SinkHit],
        source_calls: list[RawCall],
        *,
        include_dataflow: bool = True,
        max_related: int = 5,
    ) -> FunctionContext:
        code = self.read_source(method.filename, method.start_line, method.end_line)
        imports = self.extract_imports(method.filename, language)

        callers = [
            CodeRef(
                file=c.filename,
                start_line=c.start_line,
                end_line=c.end_line,
                name=c.full_name,
                code=self.read_source(c.filename, c.start_line, c.end_line, max_lines=120),
            )
            for c in self.callers_of(method.full_name)[:max_related]
        ]
        callees = [
            CodeRef(
                file=c.filename,
                start_line=c.start_line,
                end_line=c.end_line,
                name=c.full_name,
                code=self.read_source(c.filename, c.start_line, c.end_line, max_lines=120),
            )
            for c in self.callees_of(method.full_name)[:max_related]
        ]

        data_flow_paths = (
            self.fetch_dataflow_paths(sink_hits, method, source_calls) if include_dataflow else []
        )

        return FunctionContext(
            context_id=f"{method.filename}:{method.full_name}:{method.start_line}",
            language=language,
            file=method.filename,
            method_name=method.name,
            full_name=method.full_name,
            start_line=method.start_line,
            end_line=method.end_line,
            code=code,
            parameters=method.parameters,
            return_type=method.return_type,
            callers=callers,
            callees=callees,
            imports=imports,
            matched_sink_patterns=sorted({f"{h.category} ({h.cwe})" for h in sink_hits}),
            matched_source_patterns=sorted(
                {c.code for c in source_calls if c.containing_method_full_name == method.full_name}
            )[:10],
            data_flow_paths=data_flow_paths,
        )

    def build_absence_context(
        self,
        method: RawMethod,
        language: str,
        trigger_hits: list[TriggerHit],
        *,
        max_related: int = 6,
    ) -> FunctionContext:
        """Assemble a `FunctionContext` for the control-absence question.

        No dataflow: whether a control is *present* is a control-dependence
        question, not a taint one. Callers are included verbatim because the
        access control usually lives in the route-registration middleware.
        """
        code = self.read_source(method.filename, method.start_line, method.end_line)
        imports = self.extract_imports(method.filename, language)

        callers = [
            CodeRef(
                file=c.filename,
                start_line=c.start_line,
                end_line=c.end_line,
                name=c.full_name,
                code=self.read_source(c.filename, c.start_line, c.end_line, max_lines=120),
            )
            for c in self.callers_of(method.full_name)[:max_related]
        ]

        triggers = [
            ControlTrigger(
                operation=h.operation,
                category=h.category,
                code=h.call.code,
                file=h.call.filename,
                line=h.call.line_number,
                node_id=h.call.id,
                route_path=h.route_path,
            )
            for h in trigger_hits
        ]

        return FunctionContext(
            context_id=f"absence:{method.filename}:{method.full_name}:{method.start_line}",
            language=language,
            file=method.filename,
            method_name=method.name,
            full_name=method.full_name,
            start_line=method.start_line,
            end_line=method.end_line,
            code=code,
            parameters=method.parameters,
            return_type=method.return_type,
            callers=callers,
            imports=imports,
            control_triggers=triggers,
            guard_evidence=self.collect_guard_evidence(method, language),
        )

    def build_route_absence_context(self, route_hit: TriggerHit, language: str) -> FunctionContext:
        """One control-absence candidate per route *registration*.

        Centralised routers (`app.get(...)` x60 in one module) make a
        per-method context useless -- the model sees the whole router and
        can't localise a single missing `requireAuth`. This anchors on the
        one registration: its middleware list, the resolved handler body, and
        the guards found on either. `start_line` is the registration line, so
        it lines up with an M1 mutation label.
        """
        lang_rules = self.absence_rules.get(language)
        guards = lang_rules.guards if lang_rules else []
        call = route_hit.call
        args = _split_call_args(call.code)
        mw_exprs = args[1:-1] if len(args) >= 2 else []
        handler_expr = args[-1] if len(args) >= 2 else ""
        handler = self._resolve_handler(handler_expr)

        acc = _GuardAcc()
        for mw in mw_exprs:
            for rule in guards:
                if rule.pattern.search(mw):
                    acc.add(
                        control=rule.control, category=rule.category,
                        code=f"{mw.strip()}  (middleware on {call.code.strip()[:120]})",
                        file=call.filename, line=call.line_number, node_id=call.id,
                        scope="route-middleware",
                    )
                    break
        if handler is not None:
            self._scan_guards_method_body(acc, handler, guards, "handler")
            for c in self.callers_of(handler.full_name)[:4]:
                self._scan_guards_method_body(acc, c, guards, "caller")
        else:
            self._scan_guards_text(acc, call.code, call.filename, call.line_number, guards, "handler", node_id=call.id)

        triggers = [
            ControlTrigger(
                operation="route", category=route_hit.category, code=call.code,
                file=call.filename, line=call.line_number, node_id=call.id,
                route_path=route_hit.route_path,
            )
        ]
        verb_m = _ROUTE_VERB_RE.search(call.code)
        verb = verb_m.group(1).upper() if verb_m else "?"

        parts = [
            f"// {verb} {route_hit.route_path or '?'}  registered at {call.filename}:{call.line_number}",
            self.read_source(call.filename, call.line_number, call.line_number, max_lines=3) or call.code,
        ]
        if handler is not None:
            triggers += self._control_triggers_in(handler.full_name, language)
            parts += [
                "",
                f"// handler: {handler.full_name}  ({handler.filename}:{handler.start_line})",
                self.read_source(handler.filename, handler.start_line, handler.end_line, max_lines=200),
            ]
            end_line = handler.end_line if handler.filename == call.filename else call.line_number
            full_name, method_name, params = handler.full_name, handler.name, handler.parameters
            imports_file = handler.filename
        else:
            parts += ["", "// inline handler (following lines):",
                      self.read_source(call.filename, call.line_number, call.line_number + 40, max_lines=40)]
            end_line = call.line_number
            full_name = f"{call.containing_method_full_name}#{route_hit.route_path or call.line_number}"
            method_name = f"route {verb} {route_hit.route_path}"
            params = []
            imports_file = call.filename

        return FunctionContext(
            context_id=f"absence-route:{call.filename}:{route_hit.route_path or call.line_number}:{call.line_number}",
            language=language,
            file=call.filename,
            method_name=method_name,
            full_name=full_name,
            start_line=call.line_number,
            end_line=end_line,
            code="\n".join(parts),
            parameters=params,
            imports=self.extract_imports(imports_file, language),
            control_triggers=triggers,
            guard_evidence=acc.items,
            route_path=route_hit.route_path,
        )
