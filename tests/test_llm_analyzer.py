from cpgvd.config import Config
from cpgvd.llm_analyzer import (
    LlmAnalyzer,
    _asserts_no_attacker_path,
    _clean_vulnerability_type,
    _extract_json_object,
    dedupe_findings,
)
from cpgvd.llm_providers import LlmResult
from cpgvd.models import Confidence, Finding, FunctionContext, Severity


def make_context(context_id: str = "app.py:handle_request:9") -> FunctionContext:
    return FunctionContext(
        context_id=context_id,
        language="python",
        file="app.py",
        method_name="handle_request",
        full_name="app.py:<module>.handle_request",
        start_line=9,
        end_line=11,
        code="def handle_request(cmd):\n    import os\n    os.system(cmd)",
        parameters=["cmd"],
    )


class FakeProvider:
    """A provider stub that returns canned `LlmResult`s in order, and
    records every call it received."""

    def __init__(self, results):
        self._results = list(results)
        self.calls = []

    def complete_json(self, system, user, schema):
        self.calls.append((system, user, schema))
        return self._results.pop(0)


def result_with_findings(findings, **kwargs):
    import json

    return LlmResult(text=json.dumps({"findings": findings}), input_tokens=123, output_tokens=45, **kwargs)


FINDING_PAYLOAD = {
    "vulnerability_type": "OS Command Injection",
    "cwe": "CWE-78",
    "severity": "high",
    "confidence": "high",
    "title": "Unsanitized shell command from HTTP parameter",
    "description": "cmd flows from request.args into os.system with no validation.",
    "context_reasoning": "The caller `index` passes an unsanitized request parameter directly.",
    "data_flow_summary": "request.args.get('cmd') -> handle_request(cmd) -> os.system(cmd)",
    "suggested_fix": "Use subprocess with a fixed argument list and no shell=True.",
    "start_line": 9,
    "end_line": 11,
}


def test_analyze_context_parses_findings():
    provider = FakeProvider([result_with_findings([FINDING_PAYLOAD])])
    analyzer = LlmAnalyzer(Config(), provider=provider)

    findings = analyzer.analyze_context(make_context())

    assert len(findings) == 1
    f = findings[0]
    assert f.vulnerability_type == "OS Command Injection"
    assert f.cwe == "CWE-78"
    assert f.severity.value == "high"
    assert f.confidence.value == "high"
    assert f.context_reasoning.startswith("The caller")
    assert analyzer.usage.calls == 1
    assert analyzer.usage.input_tokens == 123
    assert analyzer.usage.output_tokens == 45


def test_analyze_context_handles_refusal():
    provider = FakeProvider([LlmResult(text="", refused=True)])
    analyzer = LlmAnalyzer(Config(), provider=provider)

    findings = analyzer.analyze_context(make_context())

    assert findings == []


def test_analyze_context_handles_empty_findings():
    provider = FakeProvider([result_with_findings([])])
    analyzer = LlmAnalyzer(Config(), provider=provider)

    findings = analyzer.analyze_context(make_context())

    assert findings == []


def test_analyze_context_handles_malformed_json():
    provider = FakeProvider([LlmResult(text="not valid json")])
    analyzer = LlmAnalyzer(Config(), provider=provider)

    findings = analyzer.analyze_context(make_context())

    assert findings == []


def test_analyze_context_handles_markdown_fenced_json():
    """Local models sometimes wrap JSON in a ```json fence despite the
    schema constraint -- this should still parse."""
    import json

    fenced = "```json\n" + json.dumps({"findings": [FINDING_PAYLOAD]}) + "\n```"
    provider = FakeProvider([LlmResult(text=fenced, input_tokens=10, output_tokens=20)])
    analyzer = LlmAnalyzer(Config(), provider=provider)

    findings = analyzer.analyze_context(make_context())

    assert len(findings) == 1
    assert findings[0].vulnerability_type == "OS Command Injection"


def test_analyze_many_aggregates_across_contexts():
    other_payload = dict(FINDING_PAYLOAD, start_line=30, end_line=32)
    provider = FakeProvider(
        [result_with_findings([FINDING_PAYLOAD]), result_with_findings([other_payload])]
    )
    config = Config()
    config.llm_concurrency = 2
    analyzer = LlmAnalyzer(config, provider=provider)

    findings = analyzer.analyze_many([make_context(), make_context("app.py:other:1")])

    assert len(findings) == 2
    assert analyzer.usage.calls == 2


def test_analyze_many_dedupes_identical_findings_across_contexts():
    """Two related candidate functions (a caller and its callee) often
    shortlist the same sink and yield near-identical findings -- only one
    should survive."""
    provider = FakeProvider(
        [result_with_findings([FINDING_PAYLOAD]), result_with_findings([FINDING_PAYLOAD])]
    )
    config = Config()
    config.llm_concurrency = 2
    analyzer = LlmAnalyzer(config, provider=provider)

    findings = analyzer.analyze_many([make_context(), make_context("app.py:other:1")])

    assert len(findings) == 1
    assert analyzer.usage.calls == 2


def test_analyze_context_strips_cwe_suffix_embedded_in_vulnerability_type():
    """Regression test: a real Ollama/qwen2.5-coder run put the CWE id
    inside vulnerability_type despite the separate `cwe` field, producing
    a doubled "OS Command Injection (CWE-78) (CWE-78)" in the report once
    report.py appended `cwe` on its own."""
    payload = dict(FINDING_PAYLOAD)
    payload["vulnerability_type"] = "OS Command Injection (CWE-78)"
    payload["cwe"] = "CWE-78"
    provider = FakeProvider([result_with_findings([payload])])
    analyzer = LlmAnalyzer(Config(), provider=provider)

    findings = analyzer.analyze_context(make_context())

    assert findings[0].vulnerability_type == "OS Command Injection"
    assert findings[0].cwe == "CWE-78"


def test_clean_vulnerability_type_strips_trailing_cwe():
    assert _clean_vulnerability_type("SQL Injection (CWE-89)") == "SQL Injection"
    assert _clean_vulnerability_type("SQL Injection (cwe-89)") == "SQL Injection"
    assert _clean_vulnerability_type("SQL Injection") == "SQL Injection"
    assert _clean_vulnerability_type("Path Traversal (CWE-22) and more") == "Path Traversal (CWE-22) and more"


def test_analyze_context_drops_self_contradictory_finding():
    """Regression test built from a real Ollama/qwen2.5-coder NodeGoat run:
    the model reported a hardcoded dev-config value as high-severity XSS
    while its own data_flow_summary said no taint path exists. A finding
    that argues against its own exploitability must be dropped."""
    payload = dict(FINDING_PAYLOAD)
    payload["vulnerability_type"] = "Cross-Site Scripting"
    payload["data_flow_summary"] = (
        "The environmentalScripts array is hardcoded in the function. There are "
        "no data flow paths leading from a potential taint source to this sink, "
        "indicating that the value is not dynamically generated or influenced by "
        "external inputs."
    )
    provider = FakeProvider([result_with_findings([payload])])
    analyzer = LlmAnalyzer(Config(), provider=provider)

    findings = analyzer.analyze_context(make_context())

    assert findings == []


def test_asserts_no_attacker_path_matches_assertions_of_absence_only():
    assert _asserts_no_attacker_path(
        {"data_flow_summary": "There are no data flow paths from a taint source to this sink."}
    )
    assert _asserts_no_attacker_path(
        {"context_reasoning": "This value cannot be controlled by an attacker."}
    )
    # "no evidence of sanitization" is how a *genuine* finding reads -- it
    # asserts absence of a defense, not absence of an attacker path.
    assert not _asserts_no_attacker_path(
        {"data_flow_summary": "User input reaches eval() with no evidence of sanitization."}
    )
    assert not _asserts_no_attacker_path(
        {"data_flow_summary": "request.args.get('cmd') -> handle_request(cmd) -> os.system(cmd)"}
    )


def make_finding(**overrides) -> Finding:
    base = dict(
        id="x",
        context_id="ctx",
        file="app.js",
        start_line=10,
        end_line=20,
        function="handler",
        vulnerability_type="Code Injection",
        cwe="CWE-94",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        title="t",
        description="d",
    )
    base.update(overrides)
    return Finding(**base)


def test_dedupe_findings_merges_overlapping_same_class():
    """The same eval() sink analyzed via both its caller's and its own
    context produces two near-identical findings -- keep the stronger one.
    CWE formatting differs between them ('CWE-94' vs 'CWE-94: Improper...'),
    as seen in real local-model output."""
    a = make_finding(id="a", severity=Severity.HIGH, cwe="CWE-94")
    b = make_finding(
        id="b",
        severity=Severity.MEDIUM,
        cwe="CWE-94: Improper Control of Generation of Code ('Code Injection')",
        start_line=12,
        end_line=18,
    )

    kept = dedupe_findings([b, a])

    assert [f.id for f in kept] == ["a"]


def test_dedupe_findings_keeps_distinct_findings():
    same_file_different_lines = make_finding(id="b", start_line=50, end_line=60)
    different_class = make_finding(id="c", cwe="CWE-79", vulnerability_type="XSS")
    different_file = make_finding(id="d", file="other.js")
    a = make_finding(id="a")

    kept = dedupe_findings([a, same_file_different_lines, different_class, different_file])

    assert {f.id for f in kept} == {"a", "b", "c", "d"}


def test_extract_json_object_strips_fence_and_prose():
    assert _extract_json_object('```json\n{"a": 1}\n```') == '{"a": 1}'
    assert _extract_json_object('Sure, here you go: {"a": 1} thanks!') == '{"a": 1}'
    assert _extract_json_object('{"a": 1}') == '{"a": 1}'


# -- control-absence mode ------------------------------------------------

ABSENCE_PAYLOAD = {
    "vulnerability_type": "Missing Authorization",
    "cwe": "CWE-862",
    "severity": "high",
    "confidence": "high",
    "title": "Admin user listing has no access control",
    "description": "GET /admin/users returns all users with no authentication or role check.",
    "operation_class": "admin route handler performing a bulk DB read",
    "required_control": "authorization (admin role)",
    "missing_control_reasoning": "guard_evidence is empty and no shown caller applies auth middleware.",
    "suggested_fix": "Add requireAuth + requireAdmin middleware to the route.",
    "start_line": 10,
    "end_line": 13,
}


def test_absence_mode_uses_absence_prompt_and_parses_finding():
    provider = FakeProvider([result_with_findings([ABSENCE_PAYLOAD])])
    analyzer = LlmAnalyzer(Config(), provider=provider, mode="absence")

    findings = analyzer.analyze_context(make_context("absence:routes.js:adminHandler:10"))

    assert "missing access control" in provider.calls[0][0].lower()
    assert len(findings) == 1
    f = findings[0]
    assert f.vulnerability_type == "Missing Authorization"
    assert f.cwe == "CWE-862"
    assert "required control:" in f.data_flow_summary
    assert "guard_evidence is empty" in f.context_reasoning


def test_absence_mode_drops_finding_that_concedes_control_is_present():
    conceding = dict(ABSENCE_PAYLOAD)
    conceding["missing_control_reasoning"] = (
        "The route legitimately delegates authorization to its callers, which apply requireAuth."
    )
    provider = FakeProvider([result_with_findings([conceding])])
    analyzer = LlmAnalyzer(Config(), provider=provider, mode="absence")

    assert analyzer.analyze_context(make_context("absence:x:y:1")) == []


def test_clean_vulnerability_type_normalises_snake_case():
    assert _clean_vulnerability_type("missing_access_control") == "Missing Access Control"
    assert _clean_vulnerability_type("broken-access-control") == "Broken Access Control"
    # a normal human name is left alone
    assert _clean_vulnerability_type("Missing Authorization") == "Missing Authorization"
    assert _clean_vulnerability_type("SQL Injection (CWE-89)") == "SQL Injection"


def test_unknown_mode_rejected():
    import pytest

    with pytest.raises(ValueError):
        LlmAnalyzer(Config(), provider=FakeProvider([]), mode="nonsense")
