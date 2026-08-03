"""Streamlit dashboard for browsing a cpgvd `report.json`.

Run directly with:
    streamlit run src/cpgvd/dashboard.py -- --report cpgvd_output/report.json

Or via the CLI wrapper, which finds this file for you regardless of
where the package is installed:
    cpgvd dashboard --report cpgvd_output/report.json

This only reads the JSON report `cpgvd analyze` already writes -- it
doesn't call Joern or an LLM itself, so it's safe/cheap to poke around
in and re-run against any past report.

Shares its visual language with the benchmark dashboard via `ui_theme`;
see that module for why the severity scale is an ordinal one-hue ramp
rather than the conventional red/amber/green.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

try:
    from .ui_theme import (
        SEVERITY_EMOJI,
        SEVERITY_ORDER,
        banner,
        colors,
        inject_css,
        meta_row,
        page_header,
        pill,
        severity_color,
        stat_tiles,
        style_chart,
    )
except ImportError:
    # `streamlit run src/cpgvd/dashboard.py` executes this file as a top-level
    # script with no package context, so the relative import above can't
    # resolve. Put the package root on the path and import absolutely.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from cpgvd.ui_theme import (  # noqa: E402
        SEVERITY_EMOJI,
        SEVERITY_ORDER,
        banner,
        colors,
        inject_css,
        meta_row,
        page_header,
        pill,
        severity_color,
        stat_tiles,
        style_chart,
    )

SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


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
    df["_sev_order"] = df["Severity"].map(SEVERITY_RANK)
    return df.sort_values("_sev_order").drop(columns="_sev_order").reset_index(drop=True)


def _integer_ticks(maximum: int, target: int = 8) -> list[int]:
    """Whole-number tick positions up to `maximum`, at most ~`target` of them."""
    maximum = max(1, int(maximum))
    step = max(1, -(-maximum // target))
    return list(range(0, maximum + 1, step))


def severity_chart(counts: dict[str, int]) -> alt.Chart:
    """Findings per severity.

    Severity is an *ordered* scale, so this uses the validated ordinal ramp
    (one hue, darker = more severe) rather than a categorical palette. The
    emoji and the level name travel with every bar, so the ordering is never
    carried by hue alone.
    """
    present = [s for s in SEVERITY_ORDER if counts.get(s)]
    df = pd.DataFrame({
        "Severity": [s.title() for s in present],
        "Findings": [counts[s] for s in present],
        "_key": present,
    })
    return alt.Chart(df).mark_bar(cornerRadiusEnd=4).encode(
        y=alt.Y("Severity:N", title=None, sort=[s.title() for s in present]),
        # Counts are whole numbers. tickMinStep alone still lets Vega place
        # half-steps, which format="d" renders as duplicates (0, 1, 1, 2, 2) --
        # so name the tick positions explicitly.
        x=alt.X("Findings:Q", title="Findings",
                axis=alt.Axis(format="d", values=_integer_ticks(max(counts.values())))),
        color=alt.Color(
            "_key:N", legend=None,
            scale=alt.Scale(domain=present, range=[severity_color(s) for s in present]),
        ),
        tooltip=["Severity", "Findings"],
    ).properties(height=alt.Step(30))


def stage_chart(timings: dict[str, float]) -> alt.Chart:
    """Runtime per pipeline stage. One series, so one color -- a value ramp
    here would double-encode bar length as hue and add nothing."""
    c = colors()
    df = pd.DataFrame(
        [{"Stage": k.replace("_", " "), "Seconds": round(v, 2)} for k, v in timings.items()]
    ).sort_values("Seconds", ascending=False)
    return alt.Chart(df).mark_bar(cornerRadiusEnd=4, color=c["series"][0]).encode(
        y=alt.Y("Stage:N", title=None, sort="-x"),
        x=alt.X("Seconds:Q", title="Seconds"),
        tooltip=["Stage", "Seconds"],
    ).properties(height=alt.Step(26))


def _finding_card(f: dict) -> None:
    severity = f["severity"]
    color = severity_color(severity)
    header = (
        f"{SEVERITY_EMOJI.get(severity, '')} {severity.upper()} · "
        f"{f.get('title', f['vulnerability_type'])}"
    )
    with st.expander(header):
        st.markdown(
            pill(severity, color)
            + pill(f.get("cwe") or "no CWE")
            + pill(f"{f['confidence']} confidence"),
            unsafe_allow_html=True,
        )
        meta_row([
            ("File", f"{f['file']}:{f['start_line']}-{f['end_line']}"),
            ("Function", f.get("function", "")),
            ("Type", f["vulnerability_type"]),
        ])
        st.markdown(f["description"])

        if f.get("context_reasoning"):
            banner(f.get("context_reasoning"), kind="info", title="Why context mattered.")
        if f.get("data_flow_summary"):
            st.markdown(f"**Data flow** &nbsp; `{f['data_flow_summary']}`")
        if f.get("suggested_fix"):
            st.markdown(f"**Suggested fix** &nbsp; {f['suggested_fix']}")


def main() -> None:
    st.set_page_config(
        page_title="cpgvd · report", page_icon="🛡️", layout="wide",
        initial_sidebar_state="expanded",
    )
    inject_css()

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
            page_header("Vulnerability report", eyebrow="cpgvd")
            banner(
                f"No report found at <code>{report_path}</code>. Run "
                "<code>cpgvd analyze &lt;repo&gt;</code> first, point the sidebar at the "
                "right file, or upload one directly.",
                kind="warn", title="Nothing to show.",
            )
            st.stop()
        report = _load_report(str(path), path.stat().st_mtime)

    findings = report.get("findings", [])
    stats = report.get("stats", {})

    page_header(
        "Vulnerability report",
        subtitle=report.get("repo", "?"),
        eyebrow="cpgvd scan",
    )
    meta_row([
        ("Commit", report.get("commit_sha", "")[:12] or "n/a"),
        ("Model", report.get("model", "?")),
        ("Languages", ", ".join(report.get("languages", [])) or "?"),
        ("Generated", str(report.get("generated_at", "?"))[:16].replace("T", " ")),
    ])

    by_severity: dict[str, int] = {}
    for f in findings:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1

    stat_tiles(
        [{"label": "Findings", "value": len(findings), "accent": True,
          "note": f"across {stats.get('candidate_contexts_analyzed', 0)} analysed contexts"}]
        + [
            {"label": f"{SEVERITY_EMOJI[s]} {s.title()}", "value": by_severity.get(s, 0)}
            for s in SEVERITY_ORDER
        ],
        hero_first=True,
    )

    duration = stats.get("duration_seconds", 0)
    stat_tiles([
        {"label": "Functions", "value": stats.get("functions_discovered", 0)},
        {"label": "Sink matches", "value": stats.get("sink_matches", 0)},
        {"label": "LLM calls", "value": stats.get("llm_calls", 0),
         "note": f"{stats.get('llm_input_tokens', 0):,} in / "
                 f"{stats.get('llm_output_tokens', 0):,} out"},
        {"label": "Duration", "value": f"{duration:.0f}s"},
        {"label": "Peak memory",
         "value": f"{stats.get('peak_memory_mb', 0):.0f} MB"
                  if stats.get("peak_memory_mb") else "—"},
    ])

    if not findings:
        banner(
            "No findings in this report. Either the code is clean of the sink "
            "classes cpgvd looks for, or no candidate function cleared the rules — "
            "check the sink-match count above to tell those apart.",
            kind="info", title="🎉 Nothing reported.",
        )
        return

    timings = stats.get("stage_timings") or {}
    left, right = st.columns([1, 1], gap="medium")
    with left:
        with st.container(border=True):
            st.markdown("### Findings by severity")
            st.altair_chart(style_chart(severity_chart(by_severity)), width="stretch")
    with right:
        with st.container(border=True):
            st.markdown("### Where the time went")
            if timings:
                st.altair_chart(style_chart(stage_chart(timings)), width="stretch")
            else:
                st.caption(
                    "No stage timings in this report — it predates the pipeline "
                    "instrumentation. Re-run the scan to populate them."
                )

    st.markdown("## Findings")

    all_severities = sorted(
        {f["severity"] for f in findings}, key=lambda s: SEVERITY_RANK.get(s, 99)
    )
    all_confidences = sorted({f["confidence"] for f in findings})

    # One filter row above everything it scopes, never per-card.
    filter_cols = st.columns([1, 1, 2])
    severity_filter = filter_cols[0].multiselect(
        "Severity", all_severities, default=all_severities
    )
    confidence_filter = filter_cols[1].multiselect(
        "Confidence", all_confidences, default=all_confidences
    )
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
    filtered.sort(key=lambda f: SEVERITY_RANK.get(f["severity"], 99))

    if not filtered:
        banner("No findings match the current filters.", kind="info")
        return

    st.caption(f"Showing {len(filtered)} of {len(findings)} findings.")

    df = _findings_dataframe(filtered)
    with st.container(border=True):
        st.dataframe(df, width="stretch", hide_index=True)
        st.download_button(
            "Download filtered findings as CSV",
            df.to_csv(index=False),
            file_name="cpgvd_findings.csv",
            mime="text/csv",
        )

    st.markdown("### Details")
    for f in filtered:
        _finding_card(f)


if __name__ == "__main__":
    main()
