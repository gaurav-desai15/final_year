"""Renders an `AnalysisReport` as Markdown, JSON, and SARIF."""

from __future__ import annotations

import json
from pathlib import Path

from .models import AnalysisReport, Finding, Severity

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

_SEVERITY_EMOJI = {
    Severity.CRITICAL: "🟣",
    Severity.HIGH: "🔴",
    Severity.MEDIUM: "🟠",
    Severity.LOW: "🟡",
    Severity.INFO: "⚪",
}

# SARIF severity levels are coarser than ours; map down.
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def sorted_findings(report: AnalysisReport) -> list[Finding]:
    return sorted(report.findings, key=lambda f: (_SEVERITY_ORDER[f.severity], f.file, f.start_line))


def to_json(report: AnalysisReport) -> str:
    return report.model_dump_json(indent=2)


def to_markdown(report: AnalysisReport) -> str:
    findings = sorted_findings(report)
    lines: list[str] = []
    lines.append(f"# Vulnerability Report: {report.repo}")
    lines.append("")
    if report.commit_sha:
        lines.append(f"- **Commit:** `{report.commit_sha}`")
    lines.append(f"- **Languages:** {', '.join(report.languages) or 'unknown'}")
    lines.append(f"- **Model:** {report.model}")
    lines.append(f"- **Generated:** {report.generated_at.isoformat()}")
    lines.append(
        f"- **Contexts analyzed:** {report.stats.candidate_contexts_analyzed} "
        f"(of {report.stats.functions_discovered} functions discovered, "
        f"{report.stats.sink_matches} sink pattern matches)"
    )
    lines.append(
        f"- **LLM calls:** {report.stats.llm_calls} "
        f"({report.stats.llm_input_tokens} input / {report.stats.llm_output_tokens} output tokens)"
    )
    lines.append(f"- **Duration:** {report.stats.duration_seconds:.1f}s")
    lines.append("")

    if not findings:
        lines.append("No findings. 🎉")
        return "\n".join(lines)

    by_sev = report.findings_by_severity()
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in Severity:
        count = len(by_sev.get(sev.value, []))
        if count:
            lines.append(f"| {_SEVERITY_EMOJI[sev]} {sev.value.upper()} | {count} |")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    for f in findings:
        lines.append(f"### {_SEVERITY_EMOJI[f.severity]} [{f.severity.value.upper()}] {f.title}")
        lines.append("")
        lines.append(f"- **File:** `{f.file}:{f.start_line}-{f.end_line}`")
        lines.append(f"- **Function:** `{f.function}`")
        lines.append(f"- **Type:** {f.vulnerability_type}" + (f" ({f.cwe})" if f.cwe else ""))
        lines.append(f"- **Confidence:** {f.confidence.value}")
        lines.append("")
        lines.append(f"{f.description}")
        lines.append("")
        if f.context_reasoning:
            lines.append(f"**Why context mattered:** {f.context_reasoning}")
            lines.append("")
        if f.data_flow_summary:
            lines.append(f"**Data flow:** {f.data_flow_summary}")
            lines.append("")
        if f.suggested_fix:
            lines.append(f"**Suggested fix:** {f.suggested_fix}")
            lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def to_sarif(report: AnalysisReport) -> dict:
    rules_seen: dict[str, dict] = {}
    results = []
    for f in sorted_findings(report):
        rule_id = f.cwe or f.vulnerability_type.replace(" ", "-")
        if rule_id not in rules_seen:
            rules_seen[rule_id] = {
                "id": rule_id,
                "name": f.vulnerability_type,
                "shortDescription": {"text": f.vulnerability_type},
                "fullDescription": {"text": f.description[:500]},
            }
        results.append(
            {
                "ruleId": rule_id,
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f"{f.title}: {f.description}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file},
                            "region": {"startLine": max(1, f.start_line), "endLine": max(1, f.end_line)},
                        }
                    }
                ],
                "properties": {
                    "confidence": f.confidence.value,
                    "cwe": f.cwe,
                    "contextReasoning": f.context_reasoning,
                },
            }
        )

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "cpgvd",
                        "informationUri": "https://github.com/gaurav-desai15/final_year",
                        "version": "0.1.0",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def write_report(report: AnalysisReport, output_dir: Path) -> dict[str, Path]:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = output_dir / "report.json"
    md_path = output_dir / "report.md"
    sarif_path = output_dir / "report.sarif"

    json_path.write_text(to_json(report), encoding="utf-8")
    md_path.write_text(to_markdown(report), encoding="utf-8")
    sarif_path.write_text(json.dumps(to_sarif(report), indent=2), encoding="utf-8")

    return {"json": json_path, "markdown": md_path, "sarif": sarif_path}
