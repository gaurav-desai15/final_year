import json

from cpgvd.models import AnalysisReport, Confidence, Finding, RunStats, Severity
from cpgvd.report import to_json, to_markdown, to_sarif, write_report


def make_report() -> AnalysisReport:
    findings = [
        Finding(
            id="1",
            context_id="ctx1",
            file="app.py",
            start_line=9,
            end_line=11,
            function="app.py:<module>.handle_request",
            vulnerability_type="OS Command Injection",
            cwe="CWE-78",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Unsanitized shell command",
            description="cmd flows from request.args into os.system.",
            context_reasoning="caller passes unsanitized input",
            data_flow_summary="request.args -> handle_request -> os.system",
            suggested_fix="use subprocess with arg list",
            model="claude-opus-4-8",
        ),
        Finding(
            id="2",
            context_id="ctx2",
            file="utils.py",
            start_line=20,
            end_line=22,
            function="utils.py:<module>.helper",
            vulnerability_type="Path Traversal",
            cwe="CWE-22",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            title="Unvalidated path join",
            description="path comes from user input",
            model="claude-opus-4-8",
        ),
    ]
    return AnalysisReport(
        repo="https://github.com/example/repo",
        commit_sha="abc123",
        languages=["python"],
        model="claude-opus-4-8",
        findings=findings,
        stats=RunStats(
            functions_discovered=42,
            candidate_contexts_analyzed=5,
            sink_matches=6,
            llm_calls=5,
            llm_input_tokens=1000,
            llm_output_tokens=500,
            duration_seconds=12.3,
        ),
    )


def test_to_json_roundtrips():
    report = make_report()
    data = json.loads(to_json(report))
    assert data["repo"] == "https://github.com/example/repo"
    assert len(data["findings"]) == 2


def test_to_markdown_orders_by_severity_and_includes_details():
    report = make_report()
    md = to_markdown(report)
    assert "HIGH" in md
    assert "MEDIUM" in md
    assert md.index("Unsanitized shell command") < md.index("Unvalidated path join")
    assert "CWE-78" in md
    assert "caller passes unsanitized input" in md


def test_to_markdown_no_findings():
    report = make_report()
    report.findings = []
    md = to_markdown(report)
    assert "No findings" in md


def test_to_sarif_structure():
    report = make_report()
    sarif = to_sarif(report)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "cpgvd"
    assert len(run["results"]) == 2
    assert run["results"][0]["level"] in ("error", "warning", "note")
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "CWE-78" in rule_ids
    assert "CWE-22" in rule_ids


def test_write_report_creates_all_files(tmp_path):
    report = make_report()
    paths = write_report(report, tmp_path / "out")
    assert paths["json"].exists()
    assert paths["markdown"].exists()
    assert paths["sarif"].exists()
    assert "OS Command Injection" in paths["markdown"].read_text()
