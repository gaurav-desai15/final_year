"""Shared visual language for the two Streamlit dashboards.

`cpgvd dashboard` (scan reports) and `benchmark/dashboard.py` (evaluation
results) are different apps, but they're the same product and should look
like it. Everything visual lives here so a change lands in both: the color
tokens, the CSS that dresses Streamlit's default chrome, and the small set
of HTML components (hero figure, stat tiles, badges, banners) that Streamlit
doesn't provide in a form worth using.

Color notes -- these are decisions, not preferences:

* **Categorical slots and the severity ramp are validated, not eyeballed.**
  The categorical trio clears the colorblind-separation gate (worst adjacent
  ΔE 9.2 light / 9.4 dark against a ≥8 target). The obvious green/red
  encoding for good/bad outcomes does *not*: those two measure ΔE 4.1 under
  deuteranopia simulation, so a red-green colorblind reader could not
  separate them. They are deliberately unused for series color.
* **Severity is an ordinal ramp** -- one hue, light→dark, since severity has
  a natural order. The conventional red-for-critical signal is carried by the
  emoji + text label that always accompany it, so color never encodes alone.
* **Both themes are selected, not flipped.** The dark values are the same
  hues re-stepped for the dark surface and validated against it.
"""

from __future__ import annotations

from typing import Any, Iterable, Literal

TONE = Literal["neutral", "good", "bad", "warn"]

PALETTE: dict[str, dict[str, Any]] = {
    "light": {
        # Categorical slots 1-3. Fixed order, never cycled.
        "series": ["#2a78d6", "#eb6834", "#1baf7a"],
        # Ordinal severity ramp, light -> dark = info -> critical.
        "ordinal": ["#86b6ef", "#5598e7", "#2a78d6", "#1c5cab", "#104281"],
        "page": "#f9f9f7",
        "surface": "#fcfcfb",
        "card": "#ffffff",
        "text": "#0b0b0b",
        "secondary": "#52514e",
        "muted": "#898781",
        "grid": "#e1e0d9",
        "axis": "#c3c2b7",
        "border": "rgba(11,11,11,0.10)",
        "shadow": "0 1px 2px rgba(11,11,11,0.04)",
        # Diverging pair for deltas: warm/cool poles, gray for "no change".
        "positive": "#2a78d6",
        "negative": "#d03b3b",
        "good_text": "#006300",
        "bad_text": "#b02a2a",
        "warn_bg": "#fdf6e3",
        "warn_border": "#fab219",
        "bad_bg": "#fdf0f0",
    },
    "dark": {
        "series": ["#3987e5", "#d95926", "#199e70"],
        "ordinal": ["#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95"],
        "page": "#0d0d0d",
        "surface": "#1a1a19",
        "card": "#1f1f1e",
        "text": "#ffffff",
        "secondary": "#c3c2b7",
        "muted": "#898781",
        "grid": "#2c2c2a",
        "axis": "#383835",
        "border": "rgba(255,255,255,0.10)",
        "shadow": "none",
        "positive": "#3987e5",
        "negative": "#e66767",
        "good_text": "#0ca30c",
        "bad_text": "#e66767",
        "warn_bg": "#2a2415",
        "warn_border": "#fab219",
        "bad_bg": "#2a1717",
    },
}

FONT_STACK = 'system-ui, -apple-system, "Segoe UI", Roboto, sans-serif'
MONO_STACK = 'ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace'

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
# Emoji carry the conventional severity signal alongside the ordinal ramp, so
# meaning never rests on hue alone.
SEVERITY_EMOJI = {
    "critical": "🟣", "high": "🔴", "medium": "🟠", "low": "🟡", "info": "⚪",
}


def theme_mode() -> str:
    """'light' or 'dark', matching what Streamlit is actually rendering.

    Order matters here. `theme.base` is the *configured* theme and is what
    Streamlit renders its own chrome with, so an explicit setting has to win.
    `st.context.theme.type` reports the **browser's** preference, which
    disagrees whenever config and OS setting differ -- checking it first meant
    a `base = "dark"` config produced dark Streamlit chrome wrapped around a
    light-palette page. It is the right answer only when nothing is
    configured (`theme.base` is None), which is the default and the case this
    project ships, so both paths are live.
    """
    import streamlit as st

    try:
        base = st.get_option("theme.base")
        if base in ("light", "dark"):
            return base
    except Exception:  # noqa: BLE001 - no script context
        pass
    try:
        theme_type = st.context.theme.type  # Streamlit >= 1.46
        if theme_type in ("light", "dark"):
            return theme_type
    except Exception:  # noqa: BLE001 - older Streamlit, or no script context
        pass
    return "light"


def colors(mode: str | None = None) -> dict[str, Any]:
    return PALETTE[mode or theme_mode()]


def severity_color(severity: str, mode: str | None = None) -> str:
    ramp = colors(mode)["ordinal"]
    try:
        # SEVERITY_ORDER runs critical->info; the ramp runs light->dark.
        return ramp[len(ramp) - 1 - SEVERITY_ORDER.index(severity)]
    except ValueError:
        return colors(mode)["muted"]


def inject_css(mode: str | None = None) -> None:
    """Dress Streamlit's default chrome. Call once, right after set_page_config."""
    import streamlit as st

    c = colors(mode)
    st.markdown(
        f"""
<style>
:root {{
  --cp-page: {c["page"]};
  --cp-surface: {c["surface"]};
  --cp-card: {c["card"]};
  --cp-text: {c["text"]};
  --cp-secondary: {c["secondary"]};
  --cp-muted: {c["muted"]};
  --cp-border: {c["border"]};
  --cp-shadow: {c["shadow"]};
  --cp-accent: {c["series"][0]};
  --cp-good: {c["good_text"]};
  --cp-bad: {c["bad_text"]};
  --cp-font: {FONT_STACK};
  --cp-mono: {MONO_STACK};
}}

/* Streamlit's toolbar and footer are dev affordances, not part of the app. */
#MainMenu, footer, header [data-testid="stToolbar"], [data-testid="stDecoration"] {{
  display: none !important;
}}

html, body, [class*="st-"], button, input, select, textarea {{
  font-family: var(--cp-font);
}}
code, kbd, pre, [data-testid="stCode"] {{ font-family: var(--cp-mono); }}

/* Streamlit draws its icons as ligature text in an icon font. The broad
   font-family rule above would otherwise re-render them as their literal
   names -- the sidebar collapse control shows up as "keyboard_double_arrow".
   Hand those elements their font back. */
[data-testid="stIconMaterial"],
.material-icons, .material-icons-outlined,
[class*="material-symbols"], [class*="material-icons"] {{
  font-family: "Material Symbols Rounded", "Material Symbols Outlined",
               "Material Icons" !important;
}}

.stApp {{ background: var(--cp-page); }}
[data-testid="stMain"] .block-container {{
  padding-top: 3.25rem;
  padding-bottom: 4rem;
  max-width: 1500px;
}}

/* --- Sidebar ------------------------------------------------------- */
[data-testid="stSidebar"] {{
  background: var(--cp-surface);
  border-right: 1px solid var(--cp-border);
}}
[data-testid="stSidebar"] .block-container {{ padding-top: 2rem; }}
[data-testid="stSidebar"] h2 {{
  font-size: 0.72rem !important;
  font-weight: 600 !important;
  letter-spacing: 0.09em;
  text-transform: uppercase;
  color: var(--cp-muted) !important;
  margin-bottom: 0.85rem !important;
}}

/* --- Typography ---------------------------------------------------- */
h1 {{
  font-size: 1.85rem !important;
  font-weight: 640 !important;
  letter-spacing: -0.022em;
  color: var(--cp-text) !important;
  padding: 0 !important;
  margin-bottom: 0.2rem !important;
}}
h2 {{
  font-size: 1.07rem !important;
  font-weight: 620 !important;
  letter-spacing: -0.01em;
  color: var(--cp-text) !important;
  margin: 2.1rem 0 0.5rem !important;
  padding: 0 !important;
}}
h3 {{
  font-size: 0.93rem !important;
  font-weight: 600 !important;
  color: var(--cp-secondary) !important;
  margin: 1.5rem 0 0.4rem !important;
}}

/* --- Tabs ---------------------------------------------------------- */
[data-testid="stTabs"] [data-baseweb="tab-list"] {{
  gap: 0.35rem;
  border-bottom: 1px solid var(--cp-border);
  margin-bottom: 1.5rem;
}}
[data-testid="stTabs"] [data-baseweb="tab"] {{
  height: 2.5rem;
  padding: 0 0.95rem;
  font-size: 0.855rem;
  font-weight: 520;
  color: var(--cp-muted);
  border-radius: 7px 7px 0 0;
}}
[data-testid="stTabs"] [data-baseweb="tab"]:hover {{ color: var(--cp-text); }}
[data-testid="stTabs"] [aria-selected="true"] {{ color: var(--cp-text) !important; }}
[data-testid="stTabs"] [data-baseweb="tab-highlight"] {{
  background: var(--cp-accent) !important;
  height: 2px;
}}
[data-testid="stTabs"] [data-baseweb="tab-border"] {{ display: none; }}

/* --- Cards & containers -------------------------------------------- */
[data-testid="stVerticalBlockBorderWrapper"] {{
  background: var(--cp-card);
  border: 1px solid var(--cp-border) !important;
  border-radius: 12px;
  box-shadow: var(--cp-shadow);
}}
[data-testid="stExpander"] details {{
  background: var(--cp-card);
  border: 1px solid var(--cp-border) !important;
  border-radius: 10px;
}}
[data-testid="stExpander"] summary {{
  font-size: 0.82rem;
  font-weight: 520;
  color: var(--cp-secondary);
}}
[data-testid="stExpander"] summary:hover {{ color: var(--cp-accent); }}

/* --- Data tables ---------------------------------------------------- */
[data-testid="stDataFrame"] {{
  border: 1px solid var(--cp-border);
  border-radius: 10px;
  overflow: hidden;
}}
[data-testid="stDataFrame"] [role="columnheader"] {{
  font-size: 0.72rem !important;
  letter-spacing: 0.045em;
  text-transform: uppercase;
  color: var(--cp-muted) !important;
  font-weight: 600 !important;
}}

/* Vertically-aligned digits belong in table columns, not on hero figures. */
[data-testid="stDataFrame"] [role="gridcell"] {{ font-variant-numeric: tabular-nums; }}

/* --- Inputs --------------------------------------------------------- */
[data-baseweb="select"] > div, [data-testid="stTextInput"] input {{
  border-radius: 9px !important;
  border-color: var(--cp-border) !important;
  font-size: 0.87rem;
}}
[data-testid="stTextInput"] input:focus, [data-baseweb="select"] > div:focus-within {{
  border-color: var(--cp-accent) !important;
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--cp-accent) 16%, transparent) !important;
}}
[data-testid="stDownloadButton"] button, [data-testid="stButton"] button {{
  border-radius: 9px;
  border: 1px solid var(--cp-border);
  font-size: 0.83rem;
  font-weight: 520;
  padding: 0.4rem 0.9rem;
}}
[data-testid="stDownloadButton"] button:hover, [data-testid="stButton"] button:hover {{
  border-color: var(--cp-accent);
  color: var(--cp-accent);
}}

/* Charts sit directly on the card; Vega draws its own surface. */
[data-testid="stVegaLiteChart"] {{ overflow: visible; }}

hr {{ border-color: var(--cp-border); margin: 2rem 0; }}

/* --- Components defined below --------------------------------------- */
.cp-eyebrow {{
  font-size: 0.7rem;
  font-weight: 600;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--cp-muted);
}}
.cp-subtitle {{
  font-size: 0.86rem;
  color: var(--cp-secondary);
  margin-top: 0.15rem;
}}

.cp-tiles {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 0.7rem;
  margin: 0.35rem 0 0.5rem;
}}
.cp-tile {{
  background: var(--cp-card);
  border: 1px solid var(--cp-border);
  border-radius: 12px;
  padding: 0.85rem 0.95rem 0.9rem;
  box-shadow: var(--cp-shadow);
  min-width: 0;
}}
.cp-tile-label {{
  font-size: 0.7rem;
  font-weight: 600;
  letter-spacing: 0.075em;
  text-transform: uppercase;
  color: var(--cp-muted);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}}
.cp-tile-value {{
  font-size: 1.75rem;
  font-weight: 600;
  line-height: 1.15;
  letter-spacing: -0.025em;
  color: var(--cp-text);
  margin-top: 0.3rem;
  /* Proportional figures: tabular-nums makes standalone numbers look loose. */
}}
.cp-tile-value.cp-hero {{ font-size: 3rem; letter-spacing: -0.035em; }}
.cp-tile-accent {{ border-left: 3px solid var(--cp-accent); }}
.cp-tile-delta {{ font-size: 0.76rem; margin-top: 0.2rem; font-weight: 520; }}
.cp-tile-delta.good {{ color: var(--cp-good); }}
.cp-tile-delta.bad {{ color: var(--cp-bad); }}
.cp-tile-delta.neutral {{ color: var(--cp-muted); }}
.cp-tile-note {{ font-size: 0.74rem; color: var(--cp-muted); margin-top: 0.2rem; }}

.cp-banner {{
  border-radius: 12px;
  padding: 0.85rem 1.05rem;
  margin: 0.4rem 0 1.1rem;
  font-size: 0.86rem;
  line-height: 1.55;
  border: 1px solid var(--cp-border);
  color: var(--cp-secondary);
}}
.cp-banner strong {{ color: var(--cp-text); }}
.cp-banner.warn {{ background: {c["warn_bg"]}; border-color: {c["warn_border"]}; }}
.cp-banner.bad {{ background: {c["bad_bg"]}; border-color: {c["negative"]}; }}
.cp-banner.info {{ background: var(--cp-surface); }}

.cp-pill {{
  display: inline-flex;
  align-items: center;
  gap: 0.3rem;
  padding: 0.13rem 0.5rem;
  border-radius: 999px;
  font-size: 0.71rem;
  font-weight: 600;
  letter-spacing: 0.035em;
  text-transform: uppercase;
  border: 1px solid var(--cp-border);
  color: var(--cp-secondary);
  white-space: nowrap;
}}

.cp-meta {{
  display: flex;
  flex-wrap: wrap;
  gap: 0.35rem 1.15rem;
  font-size: 0.79rem;
  color: var(--cp-muted);
  margin-bottom: 1.1rem;
}}
.cp-meta code {{
  font-size: 0.76rem;
  background: var(--cp-surface);
  border: 1px solid var(--cp-border);
  border-radius: 5px;
  padding: 0.04rem 0.32rem;
  color: var(--cp-secondary);
}}

.cp-kv {{ font-size: 0.82rem; line-height: 1.85; }}
.cp-kv .k {{ color: var(--cp-muted); }}
.cp-kv .v {{ color: var(--cp-text); font-weight: 520; }}

.cp-rule {{
  height: 1px;
  background: var(--cp-border);
  border: 0;
  margin: 1.4rem 0 1rem;
}}
</style>
""",
        unsafe_allow_html=True,
    )


def _esc(value: Any) -> str:
    from html import escape

    return escape(str(value), quote=True)


def page_header(title: str, subtitle: str = "", eyebrow: str = "") -> None:
    import streamlit as st

    parts = []
    if eyebrow:
        parts.append(f'<div class="cp-eyebrow">{_esc(eyebrow)}</div>')
    parts.append(f"<h1>{_esc(title)}</h1>")
    if subtitle:
        parts.append(f'<div class="cp-subtitle">{_esc(subtitle)}</div>')
    st.markdown("".join(parts), unsafe_allow_html=True)


def meta_row(items: Iterable[tuple[str, str]]) -> None:
    """A compact run/scan provenance strip: label + monospace value pairs."""
    import streamlit as st

    chunks = [
        f"<span>{_esc(label)} <code>{_esc(value)}</code></span>"
        for label, value in items
        if value
    ]
    if chunks:
        st.markdown(f'<div class="cp-meta">{"".join(chunks)}</div>', unsafe_allow_html=True)


def stat_tiles(tiles: list[dict[str, Any]], hero_first: bool = False) -> None:
    """A KPI row of stat tiles.

    Each tile: {label, value, delta?, tone?, note?, accent?}. A row of tiles is
    the right form for a handful of headline numbers -- a grouped bar chart of
    four unrelated scalars communicates less and takes more space.
    """
    import streamlit as st

    cells = []
    for i, tile in enumerate(tiles):
        classes = ["cp-tile"]
        if tile.get("accent"):
            classes.append("cp-tile-accent")
        value_classes = ["cp-tile-value"]
        if hero_first and i == 0:
            value_classes.append("cp-hero")

        body = [
            f'<div class="cp-tile-label">{_esc(tile["label"])}</div>',
            f'<div class="{" ".join(value_classes)}">{_esc(tile["value"])}</div>',
        ]
        if tile.get("delta"):
            tone = tile.get("tone", "neutral")
            body.append(f'<div class="cp-tile-delta {tone}">{_esc(tile["delta"])}</div>')
        if tile.get("note"):
            body.append(f'<div class="cp-tile-note">{_esc(tile["note"])}</div>')
        cells.append(f'<div class="{" ".join(classes)}">{"".join(body)}</div>')

    st.markdown(f'<div class="cp-tiles">{"".join(cells)}</div>', unsafe_allow_html=True)


def banner(body: str, kind: str = "info", title: str = "") -> None:
    """A callout. `body` may contain inline HTML from the caller (trusted)."""
    import streamlit as st

    lead = f"<strong>{_esc(title)}</strong> " if title else ""
    st.markdown(
        f'<div class="cp-banner {kind}">{lead}{body}</div>', unsafe_allow_html=True
    )


def pill(text: str, color: str | None = None) -> str:
    """An inline badge. Returns HTML for embedding, doesn't render itself."""
    style = ""
    if color:
        style = (
            f' style="border-color:{color};color:{color};'
            f'background:color-mix(in srgb,{color} 10%,transparent)"'
        )
    return f'<span class="cp-pill"{style}>{_esc(text)}</span>'


def rule() -> None:
    import streamlit as st

    st.markdown('<hr class="cp-rule">', unsafe_allow_html=True)


def style_chart(chart: Any, mode: str | None = None) -> Any:
    """Recessive chrome for an Altair chart: hairline solid grid, muted axes.

    Solid, never dashed -- dashing reads as "projection" or "threshold" when
    it is just a grid.
    """
    c = colors(mode)
    return (
        chart.configure_view(strokeWidth=0, fill=None)
        .configure_axis(
            gridColor=c["grid"], gridWidth=1, domainColor=c["axis"],
            tickColor=c["axis"], labelColor=c["muted"], titleColor=c["muted"],
            labelFontSize=11, titleFontSize=11, titleFontWeight="normal",
            labelFont=FONT_STACK, titleFont=FONT_STACK,
        )
        .configure_legend(
            labelColor=c["secondary"], titleColor=c["muted"],
            labelFontSize=11, titleFontSize=11, titleFontWeight="normal",
            labelFont=FONT_STACK, titleFont=FONT_STACK, symbolType="square",
            symbolSize=90,
        )
        .configure_text(font=FONT_STACK)
    )
