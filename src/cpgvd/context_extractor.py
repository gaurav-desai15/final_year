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
from .models import CodeRef, DataFlowPath, DataFlowStep, FunctionContext
from .rules import LanguageRules

logger = logging.getLogger(__name__)

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
    def __init__(self, client: CpgClient, repo_root: Path, rules: dict[str, LanguageRules]):
        self.client = client
        self.repo_root = Path(repo_root)
        self.rules = rules
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
        for raw in self.client.run_json(_METHOD_LIST_QUERY):
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
        ]
        logger.info("Loaded %d methods, %d calls from CPG", len(self._methods_by_id), len(self._calls))

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
