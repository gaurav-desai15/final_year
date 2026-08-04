const { pres, writeTo } = require("./build2.js");
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

// ===========================================================================
// SLIDE 9 — Competitive landscape (2x2)
// ===========================================================================
{
  const s = slide();
  eyebrow(s, "Competitive Landscape", 0.7, 0.55);
  title(s, "Positioned where rules end and research begins.", 0.7, 0.95, { w: 10.5, h: 0.8 });

  const gx = 2.3, gy = 2.15, gw = 8.6, gh = 4.85;
  card(s, gx, gy, gw, gh, { fill: PANEL2 });
  // axis lines
  s.addShape("line", { x: gx, y: gy + gh / 2, w: gw, h: 0, line: { color: BORDER, width: 1 } });
  s.addShape("line", { x: gx + gw / 2, y: gy, w: 0, h: gh, line: { color: BORDER, width: 1 } });
  // axis labels
  s.addText("HIGH CONTEXT AWARENESS", { x: gx, y: gy - 0.32, w: gw, h: 0.3, align: "center", fontFace: "Calibri", fontSize: 10, bold: true, color: MUTED, charSpacing: 1, margin: 0 });
  s.addText("LOW CONTEXT AWARENESS", { x: gx, y: gy + gh + 0.05, w: gw, h: 0.3, align: "center", fontFace: "Calibri", fontSize: 10, bold: true, color: MUTED, charSpacing: 1, margin: 0 });
  s.addText("RULE-BASED", { x: gx - 2.15, y: gy + gh / 2 - 0.15, w: 2.0, h: 0.3, align: "right", fontFace: "Calibri", fontSize: 10, bold: true, color: MUTED, charSpacing: 1, margin: 0 });
  s.addText("LEARNED / LLM-DRIVEN", { x: gx + gw + 0.15, y: gy + gh / 2 - 0.15, w: 2.3, h: 0.3, fontFace: "Calibri", fontSize: 10, bold: true, color: MUTED, charSpacing: 1, margin: 0 });

  function chip(label, sub, cx, cy, color, big) {
    const w = big ? 2.3 : 1.9, h = big ? 0.85 : 0.75;
    s.addShape("roundRect", { x: cx - w / 2, y: cy - h / 2, w, h, rectRadius: 0.08, fill: { color: color }, line: { type: "none" },
      shadow: { type: "outer", color: "000000", opacity: 0.4, blur: 8, offset: 2, angle: 90 } });
    s.addText(label, { x: cx - w / 2 + 0.08, y: cy - h / 2 + 0.08, w: w - 0.16, h: 0.35, fontFace: "Calibri", fontSize: big ? 13 : 11.5, bold: true, color: WHITE, align: "center", margin: 0 });
    if (sub) s.addText(sub, { x: cx - w / 2 + 0.08, y: cy - h / 2 + 0.4, w: w - 0.16, h: 0.35, fontFace: "Calibri", fontSize: 8.5, color: "E8F7FA", align: "center", margin: 0 });
  }

  // quadrant placements (x: rule-based -> learned, y: high context top -> low context bottom)
  chip("Checkmarx / SonarQube", "legacy SAST", gx + gw * 0.22, gy + gh * 0.78, PANEL3);
  chip("Semgrep / CodeQL", "rule-based + query DSL", gx + gw * 0.30, gy + gh * 0.55, PANEL3);
  chip("Free-form LLM review", "prompt the whole repo", gx + gw * 0.78, gy + gh * 0.85, SERIES2);
  chip("LLMxCPG", "USENIX Sec '25 — CPG-guided, fine-tuned", gx + gw * 0.76, gy + gh * 0.20, SERIES1);
  chip("cpgvd", "CPG context + LLM judgment, zero fine-tuning", gx + gw * 0.50, gy + gh * 0.20, ACCENT, true);

  pageNum(s, 9);
}

// ===========================================================================
// SLIDE 10 — Business Model
// ===========================================================================
{
  const s = slide();
  eyebrow(s, "Business Model", 0.7, 0.55);
  title(s, "Open core: free where trust is earned,\npaid where scale is needed.", 0.7, 0.95, { w: 10.5, h: 1.3, size: 28 });

  const tiers = [
    {
      name: "Community", price: "Free", color: BORDER, iconName: "code",
      items: ["Self-hosted, runs on your machine", "Local Ollama backend — no API cost", "Full CLI: analyze, dashboard, web console", "Community sink/source rule set", "Open evaluation framework"],
      cta: "Individual developers, OSS maintainers",
    },
    {
      name: "Team", price: "Usage-based", color: ACCENT, iconName: "users", featured: true,
      items: ["Hosted scanning + CI/CD integration", "PR comments with call-graph reasoning", "Claude-backed analysis for higher precision", "Team dashboards & finding triage", "Benchmark tracking across every change"],
      cta: "Engineering teams shipping fast",
    },
    {
      name: "Enterprise", price: "Custom", color: SERIES1, iconName: "server",
      items: ["On-prem / VPC deployment", "Custom sink rules & compliance mapping", "SSO, audit logs, SLA support", "Fine-tuned judgment model on your codebase", "Dedicated CVE-grade evaluation dataset"],
      cta: "Regulated industries, large orgs",
    },
  ];

  const y = 2.15, w = 3.85, h = 4.65, gap = 0.28;
  tiers.forEach((t, i) => {
    const x = 0.7 + i * (w + gap);
    card(s, x, y, w, h, { fill: t.featured ? PANEL3 : PANEL2, line: t.featured ? ACCENT : BORDER });
    iconCircle(s, x + 0.3, y + 0.3, 0.6, PANEL, t.iconName);
    s.addText(t.name, { x: x + 1.05, y: y + 0.32, w: w - 1.3, h: 0.35, fontFace: "Calibri", fontSize: 15, bold: true, color: WHITE, margin: 0 });
    s.addText(t.price, { x: x + 1.05, y: y + 0.63, w: w - 1.3, h: 0.3, fontFace: "Cambria", fontSize: 13, bold: true, color: t.color, margin: 0 });
    bullets(s, t.items, x + 0.3, y + 1.15, w - 0.6, 2.95, { size: 10.8, spacing: 9, color: TEXT2 });
    s.addShape("line", { x: x + 0.3, y: y + h - 0.75, w: w - 0.6, h: 0, line: { color: BORDER, width: 1 } });
    s.addText(t.cta, { x: x + 0.3, y: y + h - 0.62, w: w - 0.6, h: 0.55, fontFace: "Calibri", fontSize: 10, italic: true, color: MUTED, margin: 0, lineSpacingMultiple: 1.25 });
  });

  pageNum(s, 10);
}

// ===========================================================================
// SLIDE 11 — Go-to-market
// ===========================================================================
{
  const s = slide();
  eyebrow(s, "Go-To-Market", 0.7, 0.55);
  title(s, "Bottom-up, the way developer tools win.", 0.7, 0.95, { w: 10, h: 0.8 });

  const stages = [
    ["package", "Free local tool", "Individual developers install and run cpgvd on their own repos — zero cost, zero approval needed."],
    ["trend", "Organic spread", "A tool that catches real bugs with call-graph proof gets shared inside a team without a sales call."],
    ["users", "Team adoption", "One engineer champions it; the team wants CI integration, PR comments, and shared dashboards — the paid tier."],
    ["award", "Enterprise pull", "Security/compliance teams demand on-prem deployment, audit trails, and custom rules once it's load-bearing."],
  ];
  const y = 2.3, w = 2.85, h = 3.6, gap = 0.25;
  stages.forEach(([icon, h1, d], i) => {
    const x = 0.7 + i * (w + gap);
    card(s, x, y, w, h);
    s.addText(String(i + 1), { x: x + 0.2, y: y + 0.15, w: 0.5, h: 0.4, fontFace: "Cambria", fontSize: 16, bold: true, color: MUTED, margin: 0 });
    iconCircle(s, x + w / 2 - 0.32, y + 0.65, 0.64, PANEL3, icon);
    s.addText(h1, { x: x + 0.2, y: y + 1.5, w: w - 0.4, h: 0.6, fontFace: "Calibri", fontSize: 13, bold: true, color: WHITE, margin: 0, lineSpacingMultiple: 1.15, align: "center" });
    s.addText(d, { x: x + 0.2, y: y + 2.15, w: w - 0.4, h: h - 2.3, fontFace: "Calibri", fontSize: 10, color: TEXT2, margin: 0, lineSpacingMultiple: 1.3, align: "center" });
    if (i < stages.length - 1) {
      s.addText("›", { x: x + w + 0.005, y: y + h / 2 - 0.25, w: gap - 0.01, h: 0.5, fontFace: "Calibri", fontSize: 18, color: MUTED, align: "center", margin: 0 });
    }
  });

  card(s, 0.7, 6.15, 12.0, 0.85, { fill: PANEL3, shadow: false });
  s.addText("This mirrors how Semgrep, Trivy, and Sentry grew — an open-source tool developers trust first, a paid platform teams adopt second.", {
    x: 1.0, y: 6.3, w: 11.4, h: 0.55, fontFace: "Calibri", fontSize: 12, italic: true, color: TEXT2, margin: 0, valign: "middle",
  });

  pageNum(s, 11);
}

// ===========================================================================
// SLIDE 12 — Roadmap
// ===========================================================================
{
  const s = slide();
  eyebrow(s, "Roadmap", 0.7, 0.55);
  title(s, "Now, next, later.", 0.7, 0.95, { w: 8, h: 0.8 });

  const phases = [
    { label: "NOW", color: SERIES3, items: [
      "Run a live benchmark on the pilot dataset",
      "Import OWASP Benchmark & Juliet for scale",
      "Publish precision/recall/F1 with citations",
    ]},
    { label: "NEXT", color: SERIES1, items: [
      "Multi-hop dataflow (beyond 1-hop context)",
      "Second-pass FP verifier — \"does a caller validate this?\"",
      "CI/CD integrations (GitHub Actions, GitLab)",
    ]},
    { label: "LATER", color: ACCENT, items: [
      "Fine-tuned judgment model on our own corpus",
      "Hosted Team tier with PR-comment workflow",
      "Enterprise on-prem + compliance mapping",
    ]},
  ];

  const y = 2.35, w = 3.85, h = 4.4, gap = 0.28;
  phases.forEach((p, i) => {
    const x = 0.7 + i * (w + gap);
    card(s, x, y, w, h);
    s.addShape("roundRect", { x: x + 0.3, y: y + 0.3, w: 1.5, h: 0.4, rectRadius: 0.06, fill: { color: p.color }, line: { type: "none" } });
    s.addText(p.label, { x: x + 0.3, y: y + 0.3, w: 1.5, h: 0.4, fontFace: "Calibri", fontSize: 12, bold: true, color: WHITE, align: "center", valign: "middle", margin: 0, charSpacing: 1 });
    bullets(s, p.items, x + 0.3, y + 1.05, w - 0.6, h - 1.3, { size: 12, spacing: 16, color: TEXT2 });
  });

  pageNum(s, 12);
}

// ===========================================================================
// SLIDE 13 — Team & Ask
// ===========================================================================
{
  const s = slide();
  s.addShape("ellipse", { x: -2, y: -2, w: 7, h: 7, fill: { color: PANEL2, transparency: 60 }, line: { type: "none" } });

  eyebrow(s, "Team & Ask", 0.7, 0.55);
  title(s, "Built by four people who\nread the CPGs themselves.", 0.7, 0.95, { w: 8.5, h: 1.3, size: 28 });

  const team = [
    ["Rashi Bedse", "Co-author"],
    ["Gaurav Desai", "Co-author"],
    ["Kruti Dagade", "Co-author"],
    ["Dr. Harshali Patil", "Faculty Advisor"],
  ];
  const ty = 2.55, tw = 2.85, th = 1.3, tgap = 0.2;
  team.forEach(([n, r], i) => {
    const x = 0.7 + i * (tw + tgap);
    card(s, x, ty, tw, th, { fill: PANEL2 });
    iconCircle(s, x + 0.25, ty + 0.25, 0.55, PANEL3, "users");
    s.addText(n, { x: x + 0.95, y: ty + 0.22, w: tw - 1.1, h: 0.4, fontFace: "Calibri", fontSize: 12.5, bold: true, color: WHITE, margin: 0 });
    s.addText(r, { x: x + 0.95, y: ty + 0.58, w: tw - 1.1, h: 0.35, fontFace: "Calibri", fontSize: 10.5, color: MUTED, margin: 0 });
  });
  s.addText("Department of Computer Engineering, Thakur College of Engineering and Technology, Mumbai", {
    x: 0.7, y: 4.05, w: 12, h: 0.35, fontFace: "Calibri", fontSize: 11, italic: true, color: MUTED, margin: 0,
  });

  card(s, 0.7, 4.65, 12.0, 2.35, { fill: PANEL3 });
  s.addText("What we're asking for", { x: 1.0, y: 4.9, w: 6, h: 0.4, fontFace: "Cambria", fontSize: 18, bold: true, color: ACCENT, margin: 0 });
  bullets(s, [
    "GPU access or cloud credits to run the full benchmark suite at scale (OWASP Benchmark + Juliet)",
    "Pilot codebases from a real engineering team to validate precision/recall beyond our two example apps",
    "Mentorship on productionizing the Team/Enterprise tiers — CI integration and hosted deployment",
  ], 1.0, 5.4, 11.0, 1.5, { size: 13, spacing: 10, color: TEXT2 });

  pageNum(s, 13);
}

writeTo(path.join(__dirname, "..", "cpgvd_pitch_deck.pptx")).then(() => {
  console.log("Deck written.");
});
