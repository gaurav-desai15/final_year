from cpgvd.config import Config
from cpgvd.llm_analyzer import LlmAnalyzer, _extract_json_object
from cpgvd.llm_providers import LlmResult
from cpgvd.models import FunctionContext


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
    provider = FakeProvider(
        [result_with_findings([FINDING_PAYLOAD]), result_with_findings([FINDING_PAYLOAD])]
    )
    config = Config()
    config.llm_concurrency = 2
    analyzer = LlmAnalyzer(config, provider=provider)

    findings = analyzer.analyze_many([make_context(), make_context("app.py:other:1")])

    assert len(findings) == 2
    assert analyzer.usage.calls == 2


def test_extract_json_object_strips_fence_and_prose():
    assert _extract_json_object('```json\n{"a": 1}\n```') == '{"a": 1}'
    assert _extract_json_object('Sure, here you go: {"a": 1} thanks!') == '{"a": 1}'
    assert _extract_json_object('{"a": 1}') == '{"a": 1}'
