const pptxgen = require("pptxgenjs");
const path = require("path");

// ---------------------------------------------------------------------------
// Palette — lifted directly from cpgvd's own web console (styles.css), so the
// deck visually matches the real product shown on the demo slides.
// ---------------------------------------------------------------------------
const BG = "0A0F16";
const PANEL = "121A24";
const PANEL2 = "16202C";
const PANEL3 = "1B2733";
const BORDER = "24303D";
const TEXT = "EAF2FB";
const TEXT2 = "9FB2C6";
const MUTED = "6B8199";
const ACCENT = "35C5E3";
const SERIES1 = "3987E5"; // blue
const SERIES2 = "D95926"; // orange
const SERIES3 = "199E70"; // teal
const WHITE = "FFFFFF";

const ICON = (name) => path.join(__dirname, "icons", `${name}.png`);

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE"; // 13.333 x 7.5 in
const PW = 13.333, PH = 7.5;

pres.defineSlideMaster({
  title: "DARK",
  background: { color: BG },
});

function slide() {
  return pres.addSlide({ masterName: "DARK" });
}

function eyebrow(s, text, x, y, opts = {}) {
  s.addText(text.toUpperCase(), {
    x, y, w: opts.w || 6, h: 0.35,
    fontFace: "Calibri", fontSize: 11, bold: true, color: ACCENT,
    charSpacing: 2, margin: 0,
  });
}

function title(s, text, x, y, opts = {}) {
  s.addText(text, {
    x, y, w: opts.w || 9, h: opts.h || 0.9,
    fontFace: "Cambria", fontSize: opts.size || 32, bold: true, color: WHITE,
    margin: 0, valign: "top",
  });
}

function body(s, text, x, y, w, h, opts = {}) {
  s.addText(text, {
    x, y, w, h, fontFace: "Calibri", fontSize: opts.size || 14,
    color: opts.color || TEXT2, margin: 0, align: "left", valign: "top",
    lineSpacingMultiple: opts.lineSpacing || 1.25,
  });
}

function bullets(s, items, x, y, w, h, opts = {}) {
  s.addText(
    items.map((t, i) => ({
      text: t,
      options: {
        bullet: { code: "2022", indent: 18 },
        breakLine: i < items.length - 1,
        paraSpaceAfter: opts.spacing || 10,
      },
    })),
    {
      x, y, w, h, fontFace: "Calibri", fontSize: opts.size || 13.5,
      color: opts.color || TEXT2, margin: 0, valign: "top",
      lineSpacingMultiple: 1.2,
    }
  );
}

function iconCircle(s, name, x, y, d, bgColor, iconFile) {
  s.addShape("ellipse", { x, y, w: d, h: d, fill: { color: bgColor }, line: { type: "none" } });
  const pad = d * 0.26;
  s.addImage({ path: ICON(iconFile), x: x + pad, y: y + pad, w: d - 2 * pad, h: d - 2 * pad });
}

function card(s, x, y, w, h, opts = {}) {
  s.addShape("roundRect", {
    x, y, w, h, rectRadius: 0.1,
    fill: { color: opts.fill || PANEL2 },
    line: { color: opts.line || BORDER, width: 1 },
    shadow: opts.shadow === false ? undefined : {
      type: "outer", color: "000000", opacity: 0.35, blur: 10, offset: 3, angle: 90,
    },
  });
}

function pageNum(s, n) {
  s.addText(String(n).padStart(2, "0"), {
    x: PW - 0.9, y: PH - 0.5, w: 0.6, h: 0.3,
    fontFace: "Calibri", fontSize: 10, color: MUTED, align: "right", margin: 0,
  });
  s.addText("cpgvd", {
    x: 0.5, y: PH - 0.5, w: 2, h: 0.3,
    fontFace: "Calibri", fontSize: 10, color: MUTED, margin: 0,
  });
}

function statTile(s, x, y, w, h, value, label, color) {
  card(s, x, y, w, h, { fill: PANEL2 });
  s.addText(value, {
    x: x + 0.25, y: y + 0.18, w: w - 0.5, h: h - 0.75,
    fontFace: "Cambria", fontSize: 34, bold: true, color: color || ACCENT, margin: 0, valign: "top",
  });
  s.addText(label.toUpperCase(), {
    x: x + 0.25, y: y + h - 0.55, w: w - 0.5, h: 0.45,
    fontFace: "Calibri", fontSize: 10.5, bold: true, color: MUTED, charSpacing: 1,
    margin: 0, valign: "top", lineSpacingMultiple: 1.15,
  });
}

// ===========================================================================
// SLIDE 1 — Title
// ===========================================================================
{
  const s = slide();
  // Ambient corner glow via a soft ellipse
  s.addShape("ellipse", {
    x: 8.5, y: -2, w: 8, h: 8, fill: { color: PANEL2, transparency: 55 }, line: { type: "none" },
  });
  s.addShape("ellipse", {
    x: -3, y: 4, w: 7, h: 7, fill: { color: SERIES1, transparency: 88 }, line: { type: "none" },
  });

  iconCircle(s, "shield", 0.9, 1.05, 0.72, PANEL2, "shield_accent");
  s.addText([
    { text: "cpgvd", options: { color: WHITE, bold: true } },
  ], {
    x: 0.85, y: 2.7, w: 10, h: 1.3,
    fontFace: "Cambria", fontSize: 60, margin: 0, charSpacing: 0.5,
  });
  s.addText("Context-aware vulnerability detection, powered by Code Property Graphs and LLM reasoning.", {
    x: 0.9, y: 3.95, w: 9.4, h: 0.8,
    fontFace: "Calibri", fontSize: 18, color: TEXT2, margin: 0, italic: true,
  });

  s.addText("A sink pattern isn't a finding. A vulnerability is a sink reached by attacker-controlled input, with no check in between — and that's a claim only the call graph can prove.", {
    x: 0.9, y: 4.85, w: 8.6, h: 0.7,
    fontFace: "Calibri", fontSize: 12.5, color: MUTED, margin: 0, lineSpacingMultiple: 1.3,
  });

  s.addText("Thakur College of Engineering and Technology, Mumbai  •  Dept. of Computer Engineering", {
    x: 0.9, y: 6.5, w: 9, h: 0.35,
    fontFace: "Calibri", fontSize: 11.5, color: MUTED, margin: 0,
  });
  s.addText("Rashi Bedse  ·  Gaurav Desai  ·  Kruti Dagade      Advisor: Dr. Harshali Patil", {
    x: 0.9, y: 6.85, w: 9, h: 0.35,
    fontFace: "Calibri", fontSize: 12.5, color: TEXT, bold: true, margin: 0,
  });
}

// ===========================================================================
// SLIDE 2 — The Problem
// ===========================================================================
{
  const s = slide();
  eyebrow(s, "The Problem", 0.7, 0.55);
  title(s, "Security teams don't have a detection\nproblem. They have a trust problem.", 0.7, 0.95, { w: 10.5, h: 1.3, size: 30 });

  const rows = [
    ["alert", "Traditional SAST is noisy", "Rule-based scanners flag every dangerous-looking call, regardless of whether attacker input can ever reach it — teams learn to ignore the tool."],
    ["cpu", "Pure-LLM scanners don't scale", "A model reasoning without a bounded, verified context window hallucinates on large codebases and can't be trusted at repository scale."],
    ["search", "Nobody proves the call graph", "\"Is this input attacker-controlled given who calls this function?\" is exactly the question static rules and free-form LLMs both fail to answer."],
  ];
  const rowY = 2.55, rowH = 1.35, gap = 0.28;
  rows.forEach(([icon, h, d], i) => {
    const y = rowY + i * (rowH + gap);
    card(s, 0.7, y, 7.7, rowH);
    iconCircle(s, icon, 1.0, y + (rowH - 0.62) / 2, 0.62, PANEL3, icon);
    s.addText(h, { x: 1.85, y: y + 0.16, w: 6.3, h: 0.4, fontFace: "Calibri", fontSize: 15.5, bold: true, color: WHITE, margin: 0 });
    s.addText(d, { x: 1.85, y: y + 0.56, w: 6.3, h: rowH - 0.65, fontFace: "Calibri", fontSize: 11.5, color: TEXT2, margin: 0, lineSpacingMultiple: 1.25 });
  });

  // Right column: stat callouts
  statTile(s, 8.7, 2.55, 3.9, 1.62, "60–80%", "Findings from legacy SAST tools that security teams report as noise, per industry surveys cited in SAST tooling literature [Dalaq et al., 2025]", SERIES2);
  statTile(s, 8.7, 4.45, 3.9, 1.62, "1", "sink pattern ≠ 1 finding — exploitability depends entirely on who calls it and with what", ACCENT);

  pageNum(s, 2);
}

// ===========================================================================
// SLIDE 3 — The Insight / Solution
// ===========================================================================
{
  const s = slide();
  eyebrow(s, "The Insight", 0.7, 0.55);
  title(s, "Context is the product.", 0.7, 0.95, { w: 8, h: 0.8 });
  body(s, "cpgvd builds a Code Property Graph of the repository, then hands the LLM exactly the evidence it needs to judge exploitability — not the whole codebase, not a bare sink match.", 0.7, 1.75, 7.6, 0.9, { size: 13.5 });

  // Before/after comparison cards
  const y0 = 2.85, h0 = 3.9;
  card(s, 0.7, y0, 3.75, h0, { fill: PANEL2, line: SERIES2 });
  s.addText("SAFE", { x: 1.0, y: y0 + 0.25, w: 3, h: 0.3, fontFace: "Calibri", fontSize: 11, bold: true, color: SERIES3, charSpacing: 1.5, margin: 0 });
  s.addText("/status/<name>", { x: 1.0, y: y0 + 0.6, w: 3.2, h: 0.35, fontFace: "Courier New", fontSize: 13, color: WHITE, margin: 0 });
  s.addText("name checked against\nALLOWED_DIAGNOSTICS\nbefore reaching os.popen", { x: 1.0, y: y0 + 1.05, w: 3.2, h: 0.9, fontFace: "Calibri", fontSize: 11.5, color: TEXT2, margin: 0, lineSpacingMultiple: 1.3 });
  s.addShape("line", { x: 1.0, y: y0 + 2.1, w: 3.15, h: 0, line: { color: BORDER, width: 1 } });
  s.addText("A pattern-only scanner flags this too.", { x: 1.0, y: y0 + 2.25, w: 3.2, h: 0.6, fontFace: "Calibri", fontSize: 11, italic: true, color: MUTED, margin: 0, lineSpacingMultiple: 1.3 });
  iconCircle(s, "check", 1.0, y0 + 2.95, 0.55, PANEL3, "check_accent");
  s.addText("cpgvd: not reported", { x: 1.7, y: y0 + 3.02, w: 2.6, h: 0.4, fontFace: "Calibri", fontSize: 11.5, bold: true, color: SERIES3, margin: 0 });

  card(s, 4.65, y0, 3.75, h0, { fill: PANEL2, line: SERIES2 });
  s.addText("VULNERABLE", { x: 4.95, y: y0 + 0.25, w: 3, h: 0.3, fontFace: "Calibri", fontSize: 11, bold: true, color: SERIES2, charSpacing: 1.5, margin: 0 });
  s.addText("/admin/run", { x: 4.95, y: y0 + 0.6, w: 3.2, h: 0.35, fontFace: "Courier New", fontSize: 13, color: WHITE, margin: 0 });
  s.addText("cmd query param flows\nunvalidated into the same\nos.popen call", { x: 4.95, y: y0 + 1.05, w: 3.2, h: 0.9, fontFace: "Calibri", fontSize: 11.5, color: TEXT2, margin: 0, lineSpacingMultiple: 1.3 });
  s.addShape("line", { x: 4.95, y: y0 + 2.1, w: 3.15, h: 0, line: { color: BORDER, width: 1 } });
  s.addText("Same function. Opposite verdict.", { x: 4.95, y: y0 + 2.25, w: 3.2, h: 0.6, fontFace: "Calibri", fontSize: 11, italic: true, color: MUTED, margin: 0, lineSpacingMultiple: 1.3 });
  iconCircle(s, "alert", 4.95, y0 + 2.95, 0.55, PANEL3, "alert");
  s.addText("cpgvd: CWE-78, critical", { x: 5.65, y: y0 + 3.02, w: 2.7, h: 0.4, fontFace: "Calibri", fontSize: 11.5, bold: true, color: SERIES2, margin: 0 });

  // Right: the thesis statement
  card(s, 8.75, y0, 3.85, h0, { fill: PANEL3 });
  iconCircle(s, "target", 9.05, y0 + 0.35, 0.6, PANEL2, "target_accent");
  s.addText("The thesis", { x: 9.05, y: y0 + 1.1, w: 3.3, h: 0.35, fontFace: "Calibri", fontSize: 13, bold: true, color: ACCENT, margin: 0 });
  s.addText("A context-blind scanner scores ~50% precision on this pair, by construction. Ours has to actually reason about the caller to tell them apart.", {
    x: 9.05, y: y0 + 1.55, w: 3.3, h: 2.1,
    fontFace: "Calibri", fontSize: 13, color: TEXT, margin: 0, lineSpacingMultiple: 1.4,
  });

  pageNum(s, 3);
}

// ===========================================================================
// SLIDE 4 — How it works (pipeline)
// ===========================================================================
{
  const s = slide();
  eyebrow(s, "Product", 0.7, 0.55);
  title(s, "One pipeline, five stages.", 0.7, 0.95, { w: 9, h: 0.8 });

  const steps = [
    ["branch", "Build the CPG", "Joern parses the repo into one Code Property Graph — AST, control flow, and data dependence in a single structure."],
    ["search", "Shortlist candidates", "Sink/source regex rules flag call sites worth investigating — command injection, SQLi, path traversal, SSRF, and more."],
    ["layers", "Assemble context", "1-hop callers/callees, file imports, and Joern's reachableByFlows taint paths — bounded evidence, not the whole repo."],
    ["cpu", "LLM judgment", "One structured call per candidate: is this exploitable given the evidence shown? Severity, CWE, and reasoning — not a guess."],
    ["check", "Report & verify", "Markdown / JSON / SARIF output, plus a benchmark harness that scores findings against hand-verified ground truth."],
  ];

  const startX = 0.7, colW = 2.32, colGap = 0.13, y = 2.35, h = 3.9;
  steps.forEach(([icon, h1, d], i) => {
    const x = startX + i * (colW + colGap);
    card(s, x, y, colW, h, { fill: i === steps.length - 1 ? PANEL3 : PANEL2 });
    s.addText(String(i + 1), {
      x: x + 0.18, y: y + 0.15, w: 0.6, h: 0.5,
      fontFace: "Cambria", fontSize: 20, bold: true, color: MUTED, margin: 0,
    });
    iconCircle(s, icon, x + colW / 2 - 0.33, y + 0.75, 0.66, PANEL3, icon);
    s.addText(h1, { x: x + 0.18, y: y + 1.65, w: colW - 0.36, h: 0.65, fontFace: "Calibri", fontSize: 13.5, bold: true, color: WHITE, margin: 0, lineSpacingMultiple: 1.15 });
    s.addText(d, { x: x + 0.18, y: y + 2.3, w: colW - 0.36, h: h - 2.45, fontFace: "Calibri", fontSize: 10.5, color: TEXT2, margin: 0, lineSpacingMultiple: 1.3 });
    if (i < steps.length - 1) {
      s.addText("›", { x: x + colW + 0.005, y: y + h / 2 - 0.25, w: colGap + 0.02, h: 0.5, fontFace: "Calibri", fontSize: 20, color: MUTED, align: "center", margin: 0 });
    }
  });

  pageNum(s, 4);
}

module.exports = { pres, writeTo: async (file) => { await pres.writeFile({ fileName: file }); } };
