const { pres, writeTo } = require("./build.js");
const path = require("path");

const BG = "0A0F16", PANEL = "121A24", PANEL2 = "16202C", PANEL3 = "1B2733",
  BORDER = "24303D", TEXT = "EAF2FB", TEXT2 = "9FB2C6", MUTED = "6B8199",
  ACCENT = "35C5E3", SERIES1 = "3987E5", SERIES2 = "D95926", SERIES3 = "199E70", WHITE = "FFFFFF";
const PW = 13.333, PH = 7.5;
const ICON = (name) => path.join(__dirname, "icons", `${name}.png`);
const ASSETS = path.join(__dirname, "..", "pitch_assets");

function slide() { return pres.addSlide({ masterName: "DARK" }); }
function eyebrow(s, text, x, y, opts = {}) {
  s.addText(text.toUpperCase(), { x, y, w: opts.w || 6, h: 0.35, fontFace: "Calibri", fontSize: 11, bold: true, color: ACCENT, charSpacing: 2, margin: 0 });
}
function title(s, text, x, y, opts = {}) {
  s.addText(text, { x, y, w: opts.w || 9, h: opts.h || 0.9, fontFace: "Cambria", fontSize: opts.size || 32, bold: true, color: WHITE, margin: 0, valign: "top" });
}
function body(s, text, x, y, w, h, opts = {}) {
  s.addText(text, { x, y, w, h, fontFace: "Calibri", fontSize: opts.size || 14, color: opts.color || TEXT2, margin: 0, align: "left", valign: "top", lineSpacingMultiple: opts.lineSpacing || 1.25 });
}
function bullets(s, items, x, y, w, h, opts = {}) {
  s.addText(items.map((t, i) => ({ text: t, options: { bullet: { code: "2022", indent: 18 }, breakLine: i < items.length - 1, paraSpaceAfter: opts.spacing || 10 } })), {
    x, y, w, h, fontFace: "Calibri", fontSize: opts.size || 13.5, color: opts.color || TEXT2, margin: 0, valign: "top", lineSpacingMultiple: 1.2,
  });
}
function iconCircle(s, x, y, d, bgColor, iconFile) {
  s.addShape("ellipse", { x, y, w: d, h: d, fill: { color: bgColor }, line: { type: "none" } });
  const pad = d * 0.26;
  s.addImage({ path: ICON(iconFile), x: x + pad, y: y + pad, w: d - 2 * pad, h: d - 2 * pad });
}
function card(s, x, y, w, h, opts = {}) {
  s.addShape("roundRect", { x, y, w, h, rectRadius: 0.1, fill: { color: opts.fill || PANEL2 }, line: { color: opts.line || BORDER, width: 1 },
    shadow: opts.shadow === false ? undefined : { type: "outer", color: "000000", opacity: 0.35, blur: 10, offset: 3, angle: 90 } });
}
function pageNum(s, n) {
  s.addText(String(n).padStart(2, "0"), { x: PW - 0.9, y: PH - 0.5, w: 0.6, h: 0.3, fontFace: "Calibri", fontSize: 10, color: MUTED, align: "right", margin: 0 });
  s.addText("cpgvd", { x: 0.5, y: PH - 0.5, w: 2, h: 0.3, fontFace: "Calibri", fontSize: 10, color: MUTED, margin: 0 });
}
function statTile(s, x, y, w, h, value, label, color, size = 34) {
  card(s, x, y, w, h, { fill: PANEL2 });
  s.addText(value, { x: x + 0.25, y: y + 0.18, w: w - 0.5, h: h - 0.75, fontFace: "Cambria", fontSize: size, bold: true, color: color || ACCENT, margin: 0, valign: "top" });
  s.addText(label.toUpperCase(), { x: x + 0.25, y: y + h - 0.55, w: w - 0.5, h: 0.45, fontFace: "Calibri", fontSize: 10.5, bold: true, color: MUTED, charSpacing: 1, margin: 0, valign: "top", lineSpacingMultiple: 1.15 });
}
function browserFrame(s, imgPath, x, y, w, h) {
  card(s, x, y, w, h, { fill: PANEL3, line: BORDER });
  // fake title bar
  s.addShape("roundRect", { x, y, w, h: 0.32, rectRadius: 0.04, fill: { color: PANEL }, line: { type: "none" } });
  ["E66767", "FAB219", "199E70"].forEach((c, i) => {
    s.addShape("ellipse", { x: x + 0.14 + i * 0.2, y: y + 0.1, w: 0.12, h: 0.12, fill: { color: c }, line: { type: "none" } });
  });
  s.addImage({ path: imgPath, x: x + 0.06, y: y + 0.38, w: w - 0.12, h: h - 0.44, sizing: { type: "contain", w: w - 0.12, h: h - 0.44 } });
}

// ===========================================================================
// SLIDE 5 — Product: Scan Report
// ===========================================================================
{
  const s = slide();
  eyebrow(s, "Product", 0.7, 0.55);
  title(s, "Findings you can actually audit.", 0.7, 0.95, { w: 8, h: 0.8 });
  body(s, "Every finding carries the call-graph reasoning behind it — not just a line number, but why the context made it exploitable.", 0.7, 1.7, 5.2, 1.0, { size: 13 });

  bullets(s, [
    "Severity, CWE, and confidence at a glance",
    "Call-graph reasoning attached to every finding",
    "Data-flow summary from source to sink",
    "Filterable by severity, confidence, free-text search",
    "Markdown / JSON / SARIF export for CI pipelines",
  ], 0.7, 2.85, 5.0, 3.4, { size: 12.5, spacing: 12 });

  browserFrame(s, path.join(ASSETS, "web-scan.png"), 6.0, 1.55, 6.65, 5.35);
  pageNum(s, 5);
}

// ===========================================================================
// SLIDE 6 — Product: Evaluation framework (differentiator)
// ===========================================================================
{
  const s = slide();
  eyebrow(s, "Product — What Sets Us Apart", 0.7, 0.55);
  title(s, "We measure ourselves. Most tools don't.", 0.7, 0.95, { w: 9.5, h: 0.8 });
  body(s, "A built-in benchmark harness scores findings against hand-verified ground truth: precision, recall, and F1 — per CWE, per case, tracked across every change.", 0.7, 1.7, 5.2, 1.1, { size: 13 });

  bullets(s, [
    "Weighted, line-tolerant matching engine",
    "TP / FP / FN / TN accounting, not vibes",
    "OWASP Benchmark & NIST Juliet importers built in",
    "Every run archived immutably — regression-proof",
    "Two-run comparison shows exactly which vulnerabilities changed status",
  ], 0.7, 2.9, 5.0, 3.3, { size: 12.5, spacing: 11 });

  browserFrame(s, path.join(ASSETS, "web-bench.png"), 6.0, 1.55, 6.65, 5.35);
  pageNum(s, 6);
}

// ===========================================================================
// SLIDE 7 — Why Now
// ===========================================================================
{
  const s = slide();
  eyebrow(s, "Why Now", 0.7, 0.55);
  title(s, "Three curves crossed at once.", 0.7, 0.95, { w: 9, h: 0.8 });

  const cols = [
    ["cpu", "LLMs finally reason about code", "Frontier and open code-tuned models can now trace multi-hop call graphs well enough to judge exploitability, not just pattern-match — a capability that didn't exist three years ago."],
    ["trend", "AI-written code is outpacing review", "Copilot-style tools multiply how much code ships per developer; the security-review bottleneck hasn't moved, and legacy SAST wasn't built for this volume."],
    ["alert", "Alert fatigue has a real cost", "Teams that stop trusting their scanner stop reading its output — the noisiest tool in the pipeline becomes the one nobody looks at."],
  ];
  const y = 2.35, w = 3.85, h = 4.0, gap = 0.28;
  cols.forEach(([icon, h1, d], i) => {
    const x = 0.7 + i * (w + gap);
    card(s, x, y, w, h);
    iconCircle(s, x + 0.35, y + 0.4, 0.75, PANEL3, icon);
    s.addText(h1, { x: x + 0.35, y: y + 1.45, w: w - 0.7, h: 0.85, fontFace: "Calibri", fontSize: 15.5, bold: true, color: WHITE, margin: 0, lineSpacingMultiple: 1.2 });
    s.addText(d, { x: x + 0.35, y: y + 2.35, w: w - 0.7, h: h - 2.55, fontFace: "Calibri", fontSize: 11.5, color: TEXT2, margin: 0, lineSpacingMultiple: 1.35 });
  });

  pageNum(s, 7);
}

// ===========================================================================
// SLIDE 8 — Market size
// ===========================================================================
{
  const s = slide();
  eyebrow(s, "Market", 0.7, 0.55);
  title(s, "A large, fast-growing, and fragmented market.", 0.7, 0.95, { w: 10.5, h: 0.8 });

  statTile(s, 0.7, 2.15, 3.85, 2.15, "$12.6–14.8B", "Application Security market, 2026", ACCENT, 30);
  statTile(s, 4.75, 2.15, 3.85, 2.15, "18.8%", "CAGR to 2033 (MarketsandMarkets)", SERIES1, 34);
  statTile(s, 8.8, 2.15, 3.85, 2.15, "$0.7–3.8B", "SAST-specific segment, 2025–26 (analyst estimates vary)", SERIES2, 26);

  card(s, 0.7, 4.55, 12.0, 2.2, { fill: PANEL3 });
  s.addText("Reading the range honestly", { x: 1.0, y: 4.8, w: 4, h: 0.35, fontFace: "Calibri", fontSize: 13, bold: true, color: ACCENT, margin: 0 });
  body(s, "Analyst firms disagree sharply on how narrowly to define \"SAST\" versus the broader AppSec category — estimates for the SAST segment alone range from $0.7B to $3.8B for 2025/26 depending on scope. We cite the range rather than picking the most flattering number. The strategic point stands regardless: this is a large, actively consolidating market where AI-native entrants (this project, IRIS, LLMxCPG) are still a small fraction of spend — legacy rule-based tools (Checkmarx, Veracode, SonarQube) still dominate deployed seats.", 1.0, 5.2, 11.4, 1.4, { size: 11.5, lineSpacing: 1.3 });

  s.addText("Sources: MarketsandMarkets, Grand View Research, Business Research Insights, Coherent Market Insights (2026 forecasts)", {
    x: 0.7, y: 6.85, w: 12, h: 0.3, fontFace: "Calibri", fontSize: 9, italic: true, color: MUTED, margin: 0,
  });

  pageNum(s, 8);
}

module.exports = { pres, writeTo };
