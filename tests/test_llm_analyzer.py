import json
from types import SimpleNamespace
from unittest.mock import MagicMock

from cpgvd.config import Config
from cpgvd.llm_analyzer import LlmAnalyzer
from cpgvd.models import FunctionContext


def make_context() -> FunctionContext:
    return FunctionContext(
        context_id="app.py:handle_request:9",
        language="python",
        file="app.py",
        method_name="handle_request",
        full_name="app.py:<module>.handle_request",
        start_line=9,
        end_line=11,
        code="def handle_request(cmd):\n    import os\n    os.system(cmd)",
        parameters=["cmd"],
    )


def make_response(stop_reason="end_turn", text=None, findings=None):
    if text is None:
        text = json.dumps({"findings": findings if findings is not None else []})
    return SimpleNamespace(
        stop_reason=stop_reason,
        content=[SimpleNamespace(type="text", text=text)],
        usage=SimpleNamespace(input_tokens=123, output_tokens=45),
    )


def test_analyze_context_parses_findings():
    finding_payload = {
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
    mock_client = MagicMock()
    mock_client.messages.create.return_value = make_response(findings=[finding_payload])

    analyzer = LlmAnalyzer(Config(), client=mock_client)
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
    mock_client = MagicMock()
    mock_client.messages.create.return_value = make_response(stop_reason="refusal", text="")

    analyzer = LlmAnalyzer(Config(), client=mock_client)
    findings = analyzer.analyze_context(make_context())

    assert findings == []


def test_analyze_context_handles_empty_findings():
    mock_client = MagicMock()
    mock_client.messages.create.return_value = make_response(findings=[])

    analyzer = LlmAnalyzer(Config(), client=mock_client)
    findings = analyzer.analyze_context(make_context())

    assert findings == []


def test_analyze_context_handles_malformed_json():
    mock_client = MagicMock()
    mock_client.messages.create.return_value = make_response(text="not valid json")

    analyzer = LlmAnalyzer(Config(), client=mock_client)
    findings = analyzer.analyze_context(make_context())

    assert findings == []


def test_analyze_many_aggregates_across_contexts():
    finding_payload = {
        "vulnerability_type": "OS Command Injection",
        "cwe": "CWE-78",
        "severity": "high",
        "confidence": "medium",
        "title": "t",
        "description": "d",
        "context_reasoning": "r",
        "data_flow_summary": "s",
        "suggested_fix": "f",
        "start_line": 9,
        "end_line": 11,
    }
    mock_client = MagicMock()
    mock_client.messages.create.return_value = make_response(findings=[finding_payload])

    config = Config()
    config.llm_concurrency = 2
    analyzer = LlmAnalyzer(config, client=mock_client)

    ctx1 = make_context()
    ctx2 = make_context()
    ctx2.context_id = "app.py:other:1"

    findings = analyzer.analyze_many([ctx1, ctx2])
    assert len(findings) == 2
    assert analyzer.usage.calls == 2
