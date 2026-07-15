"""Streamlit dashboard for browsing a cpgvd `report.json`.

Run directly with:
    streamlit run src/cpgvd/dashboard.py -- --report cpgvd_output/report.json

Or via the CLI wrapper, which finds this file for you regardless of
where the package is installed:
    cpgvd dashboard --report cpgvd_output/report.json

This only reads the JSON report `cpgvd analyze` already writes -- it
doesn't call Joern or an LLM itself, so it's safe/cheap to poke around
in and re-run against any past report.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_EMOJI = {"critical": "🟣", "high": "🔴", "medium": "🟠", "low": "🟡", "info": "⚪"}


def _default_report_path() -> str:
    """Pull `--report <path>` out of argv if launched via `streamlit run
    dashboard.py -- --report <path>` (e.g. from the `cpgvd dashboard` CLI
    wrapper); otherwise fall back to the standard output location."""
    argv = sys.argv
    if "--report" in argv:
        idx = argv.index("--report")
        if idx + 1 < len(argv):
            return argv[idx + 1]
    return "cpgvd_output/report.json"


@st.cache_data(show_spinner=False)
def _load_report(path: str, mtime: float) -> dict:
    # `mtime` is part of the cache key purely so re-running a scan and
    # overwriting report.json invalidates the cache automatically.
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _findings_dataframe(findings: list[dict]) -> pd.DataFrame:
    if not findings:
        return pd.DataFrame(
            columns=["Severity", "Type", "CWE", "Confidence", "File", "Function", "Title"]
        )
    rows = [
        {
            "Severity": f["severity"],
            "Type": f["vulnerability_type"],
            "CWE": f.get("cwe", ""),
            "Confidence": f["confidence"],
            "File": f"{f['file']}:{f['start_line']}",
            "Function": f.get("function", ""),
            "Title": f.get("title", ""),
        }
        for f in findings
    ]
    df = pd.DataFrame(rows)
    df["_sev_order"] = df["Severity"].map(SEVERITY_ORDER)
    return df.sort_values("_sev_order").drop(columns="_sev_order").reset_index(drop=True)


def main() -> None:
    st.set_page_config(page_title="cpgvd report", page_icon="🛡️", layout="wide")
    st.title("🛡️ cpgvd — Vulnerability Report")

    default_path = _default_report_path()
    with st.sidebar:
        st.header("Report source")
        report_path = st.text_input("Path to report.json", value=default_path)
        uploaded = st.file_uploader("...or upload a report.json", type="json")

    if uploaded is not None:
        report = json.loads(uploaded.read().decode("utf-8"))
    else:
        path = Path(report_path)
        if not path.exists():
            st.warning(
                f"No report found at `{report_path}`. Run `cpgvd analyze <repo>` first, "
                "point the sidebar at the right file, or upload one directly."
            )
            st.stop()
        report = _load_report(str(path), path.stat().st_mtime)

    findings = report.get("findings", [])
    stats = report.get("stats", {})

    st.caption(
        f"**{report.get('repo', '?')}** &nbsp;·&nbsp; "
        f"commit `{report.get('commit_sha', '')[:12] or 'n/a'}` &nbsp;·&nbsp; "
        f"model `{report.get('model', '?')}` &nbsp;·&nbsp; "
        f"generated {report.get('generated_at', '?')}"
    )

    by_severity: dict[str, int] = {}
    for f in findings:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1

    cols = st.columns(6)
    cols[0].metric("Findings", len(findings))
    for i, sev in enumerate(("critical", "high", "medium", "low", "info"), start=1):
        cols[i].metric(f"{SEVERITY_EMOJI[sev]} {sev.title()}", by_severity.get(sev, 0))

    with st.expander("Run stats"):
        st.json(stats)

    if not findings:
        st.success("No findings. 🎉")
        return

    if by_severity:
        st.subheader("Findings by severity")
        chart_df = pd.DataFrame(
            {"count": [by_severity.get(s, 0) for s in SEVERITY_ORDER]},
            index=[s.title() for s in SEVERITY_ORDER],
        )
        st.bar_chart(chart_df, y="count")

    st.subheader("Findings")

    all_severities = sorted({f["severity"] for f in findings}, key=lambda s: SEVERITY_ORDER.get(s, 99))
    all_confidences = sorted({f["confidence"] for f in findings})

    filter_cols = st.columns(3)
    severity_filter = filter_cols[0].multiselect("Severity", all_severities, default=all_severities)
    confidence_filter = filter_cols[1].multiselect("Confidence", all_confidences, default=all_confidences)
    search = filter_cols[2].text_input("Search (file, function, or title)")

    filtered = [
        f
        for f in findings
        if f["severity"] in severity_filter
        and f["confidence"] in confidence_filter
        and (
            not search
            or search.lower() in f["file"].lower()
            or search.lower() in f.get("function", "").lower()
            or search.lower() in f.get("title", "").lower()
        )
    ]
    filtered.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))

    df = _findings_dataframe(filtered)
    st.dataframe(df, use_container_width=True, hide_index=True)
    st.download_button(
        "Download filtered findings as CSV",
        df.to_csv(index=False),
        file_name="cpgvd_findings.csv",
        mime="text/csv",
    )

    st.subheader("Details")
    for f in filtered:
        header = f"{SEVERITY_EMOJI.get(f['severity'], '')} [{f['severity'].upper()}] {f.get('title', f['vulnerability_type'])}"
        with st.expander(header):
            meta_cols = st.columns(4)
            meta_cols[0].markdown(f"**File**\n\n`{f['file']}:{f['start_line']}-{f['end_line']}`")
            meta_cols[1].markdown(f"**Function**\n\n`{f.get('function', '')}`")
            meta_cols[2].markdown(f"**Type**\n\n{f['vulnerability_type']} ({f.get('cwe', 'n/a')})")
            meta_cols[3].markdown(f"**Confidence**\n\n{f['confidence']}")

            st.markdown(f["description"])

            if f.get("context_reasoning"):
                st.info(f"**Why context mattered:** {f['context_reasoning']}")
            if f.get("data_flow_summary"):
                st.markdown(f"**Data flow:** `{f['data_flow_summary']}`")
            if f.get("suggested_fix"):
                st.markdown(f"**Suggested fix:** {f['suggested_fix']}")


if __name__ == "__main__":
    main()
