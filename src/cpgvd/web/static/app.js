/* cpgvd console — single-page client.
 *
 * No framework and no CDN: the whole app is this file plus styles.css, so it
 * works offline and there is no build step between editing and seeing the
 * result. Charts are hand-built SVG for the same reason.
 *
 * Structure:
 *   utils / dom      tiny helpers (el, fmt, escape)
 *   charts           SVG chart builders, one per form
 *   views            scan, benchmark, compare — each renders rail/main/detail
 *   router           hash-based, so a view is linkable and survives reload
 *
 * Charting rules this file follows, and why:
 *   - Colours come from CSS custom properties, never literals, so the light
 *     and dark palettes stay in one place (styles.css) and both stay valid.
 *   - Counts get integer tick positions. Letting a linear scale pick ticks
 *     for a max of 2 yields "0, 0.5, 1, 1.5, 2" — or, rounded, "0, 1, 1, 2, 2".
 *   - Every chart has a table twin. No value is reachable only by hovering.
 *   - A legend appears whenever there is more than one series; single-series
 *     charts are titled instead.
 */

'use strict';

/* ------------------------------------------------------------------ *
 * Utilities
 * ------------------------------------------------------------------ */

const SVG_NS = 'http://www.w3.org/2000/svg';

/** Read a CSS custom property, so JS never hardcodes a validated colour. */
function token(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else if (k === 'html') node.innerHTML = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2).toLowerCase(), v);
    else node.setAttribute(k, v);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}

function svg(tag, attrs = {}) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined) continue;
    node.setAttribute(k, v);
  }
  return node;
}

const pct = (v) => `${(100 * (v || 0)).toFixed(1)}%`;
const num = (v, d = 0) => (v ?? 0).toFixed(d);
const escapeHtml = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/** Whole-number tick positions, at most ~target of them. */
function integerTicks(maximum, target = 6) {
  const max = Math.max(1, Math.ceil(maximum || 0));
  const step = Math.max(1, Math.ceil(max / target));
  const out = [];
  for (let v = 0; v <= max; v += step) out.push(v);
  return out;
}

function shortDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? String(iso).slice(0, 16) : d.toISOString().slice(0, 16).replace('T', ' ');
}

/* ------------------------------------------------------------------ *
 * Metrics — mirrors benchmark/metrics.py so the client can aggregate
 * without a round trip per chart.
 * ------------------------------------------------------------------ */

function metricsOf(tp, fp, fn, tn = 0) {
  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
  return { tp, fp, fn, tn, precision, recall, f1 };
}

function okCases(run) {
  return (run.cases || []).filter((c) => c.status === 'ok');
}

function overallMetrics(run) {
  let tp = 0, fp = 0, fn = 0, tn = 0;
  for (const c of okCases(run)) {
    tp += c.metrics.true_positives;
    fp += c.metrics.false_positives;
    fn += c.metrics.false_negatives;
    tn += c.metrics.true_negatives;
  }
  return metricsOf(tp, fp, fn, tn);
}

function normalizeCwe(value) {
  const m = /cwe[-_\s]?(\d+)/i.exec(value || '');
  return m ? `CWE-${m[1]}` : '';
}

/** TP/FN attributed to the ground-truth CWE, FP to the CWE it claimed. */
function metricsByCwe(run) {
  const buckets = new Map();
  const bucket = (cwe) => {
    const key = normalizeCwe(cwe) || 'unspecified';
    if (!buckets.has(key)) buckets.set(key, { tp: 0, fp: 0, fn: 0 });
    return buckets.get(key);
  };
  for (const c of okCases(run)) {
    for (const m of c.matches || []) bucket(m.ground_truth_cwe).tp += 1;
    for (const f of c.false_negatives || []) bucket(f.cwe).fn += 1;
    for (const f of c.false_positives || []) bucket(f.cwe).fp += 1;
  }
  return [...buckets.entries()]
    .map(([name, v]) => ({ name, ...metricsOf(v.tp, v.fp, v.fn) }))
    .sort((a, b) => b.tp + b.fp + b.fn - (a.tp + a.fp + a.fn));
}

function stageTotals(run) {
  const totals = new Map();
  for (const c of run.cases || []) {
    for (const [stage, secs] of Object.entries(c.stage_timings || {})) {
      totals.set(stage, (totals.get(stage) || 0) + secs);
    }
  }
  return [...totals.entries()]
    .map(([name, seconds]) => ({ name: name.replace(/_/g, ' '), seconds }))
    .sort((a, b) => b.seconds - a.seconds);
}

function runtimeStats(run) {
  const durations = (run.cases || []).map((c) => c.duration_seconds).filter((d) => d > 0);
  if (!durations.length) return { total: 0, mean: 0, median: 0, max: 0 };
  const sorted = [...durations].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return {
    total: durations.reduce((a, b) => a + b, 0),
    mean: durations.reduce((a, b) => a + b, 0) / durations.length,
    median: sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2,
    max: sorted[sorted.length - 1],
  };
}

/* ------------------------------------------------------------------ *
 * Tooltip (shared by every chart)
 * ------------------------------------------------------------------ */

const tooltip = {
  node: null,
  init() { this.node = document.getElementById('tooltip'); },
  show(evt, html) {
    if (!this.node) return;
    this.node.innerHTML = html;
    this.node.classList.add('show');
    this.node.setAttribute('aria-hidden', 'false');
    this.move(evt);
  },
  move(evt) {
    if (!this.node) return;
    const pad = 14;
    const rect = this.node.getBoundingClientRect();
    let x = evt.clientX + pad;
    let y = evt.clientY + pad;
    if (x + rect.width > window.innerWidth - 8) x = evt.clientX - rect.width - pad;
    if (y + rect.height > window.innerHeight - 8) y = evt.clientY - rect.height - pad;
    this.node.style.left = `${Math.max(8, x)}px`;
    this.node.style.top = `${Math.max(8, y)}px`;
  },
  hide() {
    if (!this.node) return;
    this.node.classList.remove('show');
    this.node.setAttribute('aria-hidden', 'true');
  },
};

/** Attach hover/focus tooltips. Focusable so keyboard reaches the same info. */
function attachTip(node, html) {
  node.addEventListener('mouseenter', (e) => tooltip.show(e, html));
  node.addEventListener('mousemove', (e) => tooltip.move(e));
  node.addEventListener('mouseleave', () => tooltip.hide());
  node.setAttribute('tabindex', '0');
  node.addEventListener('focus', (e) => {
    const r = node.getBoundingClientRect();
    tooltip.show({ clientX: r.left + r.width / 2, clientY: r.top }, html);
  });
  node.addEventListener('blur', () => tooltip.hide());
}

/* ------------------------------------------------------------------ *
 * Charts
 * ------------------------------------------------------------------ */

function legend(items) {
  return el('div', { class: 'legend' },
    items.map(([label, color]) =>
      el('span', { class: 'legend-item' },
        el('span', { class: 'legend-swatch', style: `background:${color}` }),
        label)));
}

/**
 * Horizontal stacked bar. Used for TP/FP/FN per class: the three outcomes
 * together are the total evidence for that class, so bar width carries how
 * much a rate actually rests on.
 */
function stackedBarChart(rows, series, opts = {}) {
  const labelW = opts.labelWidth ?? 96;
  const rowH = 30, gap = 9, padR = 16, padB = 30, padT = 4;
  const width = opts.width ?? 640;
  const height = padT + rows.length * (rowH + gap) + padB;
  const plotW = Math.max(60, width - labelW - padR);
  const maxTotal = Math.max(1, ...rows.map((r) => series.reduce((s, k) => s + (r[k.key] || 0), 0)));
  const ticks = integerTicks(maxTotal);
  const scale = (v) => (v / (ticks[ticks.length - 1] || 1)) * plotW;

  const root = svg('svg', {
    class: 'chart', viewBox: `0 0 ${width} ${height}`,
    preserveAspectRatio: 'xMinYMin meet', role: 'img',
    'aria-label': opts.ariaLabel || 'Stacked bar chart',
  });

  for (const t of ticks) {
    const x = labelW + scale(t);
    root.appendChild(svg('line', {
      class: 'grid-line', x1: x, x2: x, y1: padT, y2: height - padB,
    }));
    const label = svg('text', {
      class: 'tick-label', x, y: height - padB + 16, 'text-anchor': 'middle',
    });
    label.textContent = t;
    root.appendChild(label);
  }

  rows.forEach((row, i) => {
    const y = padT + i * (rowH + gap);
    const name = svg('text', { x: labelW - 10, y: y + rowH / 2 + 4, 'text-anchor': 'end' });
    name.textContent = row.name;
    root.appendChild(name);

    let cursor = 0;
    for (const s of series) {
      const value = row[s.key] || 0;
      if (!value) continue;
      const x = labelW + scale(cursor);
      const w = scale(value);
      // 2px surface gap between segments instead of a stroke around them.
      const rect = svg('rect', {
        class: 'bar', x, y, width: Math.max(1, w - 2), height: rowH,
        rx: 4, fill: s.color,
      });
      attachTip(rect,
        `<strong>${escapeHtml(row.name)}</strong><br>` +
        `<span class="tt-key">${escapeHtml(s.label)}</span> ${value}`);
      root.appendChild(rect);
      cursor += value;
    }
  });

  return root;
}

/**
 * Horizontal bar, one series. A value ramp here would double-encode bar
 * length as hue, so every bar shares one colour.
 */
function barChart(rows, opts = {}) {
  const labelW = opts.labelWidth ?? 130;
  const rowH = opts.rowHeight ?? 22, gap = 8, padR = 46, padB = 26, padT = 4;
  const width = opts.width ?? 640;
  const height = padT + rows.length * (rowH + gap) + padB;
  const plotW = Math.max(60, width - labelW - padR);
  const max = Math.max(...rows.map((r) => r.value), opts.min ?? 0.0001);
  const color = opts.color || token('--series-1');
  const fmt = opts.format || ((v) => num(v, 1));

  const root = svg('svg', {
    class: 'chart', viewBox: `0 0 ${width} ${height}`,
    preserveAspectRatio: 'xMinYMin meet', role: 'img',
    'aria-label': opts.ariaLabel || 'Bar chart',
  });

  root.appendChild(svg('line', {
    class: 'axis-line', x1: labelW, x2: labelW, y1: padT, y2: height - padB,
  }));

  rows.forEach((row, i) => {
    const y = padT + i * (rowH + gap);
    const name = svg('text', { x: labelW - 10, y: y + rowH / 2 + 4, 'text-anchor': 'end' });
    name.textContent = row.name;
    root.appendChild(name);

    const w = Math.max(2, (row.value / max) * plotW);
    const rect = svg('rect', {
      class: 'bar', x: labelW + 1, y, width: w, height: rowH, rx: 4,
      fill: row.color || color,
    });
    attachTip(rect, `<strong>${escapeHtml(row.name)}</strong><br>${escapeHtml(row.tip || fmt(row.value))}`);
    root.appendChild(rect);

    // Direct-label the value at the bar end: selective, not one per point.
    const value = svg('text', {
      class: 'value-label', x: labelW + w + 8, y: y + rowH / 2 + 4,
    });
    value.textContent = fmt(row.value);
    root.appendChild(value);
  });

  return root;
}

/** Grouped bar for precision/recall/F1 per class. */
function groupedBarChart(rows, series, opts = {}) {
  const labelW = opts.labelWidth ?? 96;
  const barH = 11, barGap = 3, groupGap = 14, padR = 42, padB = 28, padT = 4;
  const width = opts.width ?? 640;
  const groupH = series.length * barH + (series.length - 1) * barGap;
  const height = padT + rows.length * (groupH + groupGap) + padB;
  const plotW = Math.max(60, width - labelW - padR);

  const root = svg('svg', {
    class: 'chart', viewBox: `0 0 ${width} ${height}`,
    preserveAspectRatio: 'xMinYMin meet', role: 'img',
    'aria-label': opts.ariaLabel || 'Grouped bar chart',
  });

  for (let t = 0; t <= 1.0001; t += 0.25) {
    const x = labelW + t * plotW;
    root.appendChild(svg('line', { class: 'grid-line', x1: x, x2: x, y1: padT, y2: height - padB }));
    const label = svg('text', { class: 'tick-label', x, y: height - padB + 16, 'text-anchor': 'middle' });
    label.textContent = `${Math.round(t * 100)}%`;
    root.appendChild(label);
  }

  rows.forEach((row, i) => {
    const groupY = padT + i * (groupH + groupGap);
    const name = svg('text', { x: labelW - 10, y: groupY + groupH / 2 + 4, 'text-anchor': 'end' });
    name.textContent = row.name;
    root.appendChild(name);

    series.forEach((s, j) => {
      const y = groupY + j * (barH + barGap);
      const value = row[s.key] || 0;
      const w = Math.max(1, value * plotW);
      const rect = svg('rect', {
        class: 'bar', x: labelW + 1, y, width: w, height: barH, rx: 3, fill: s.color,
      });
      attachTip(rect,
        `<strong>${escapeHtml(row.name)}</strong><br>` +
        `<span class="tt-key">${escapeHtml(s.label)}</span> ${pct(value)}<br>` +
        `<span class="tt-key">support</span> ${row.tp + row.fn} (TP ${row.tp} · FP ${row.fp} · FN ${row.fn})`);
      root.appendChild(rect);
    });
  });

  return root;
}

/** Multi-series line chart for the metric trend across runs. */
function lineChart(points, series, opts = {}) {
  const padL = 44, padR = 54, padT = 12, padB = 40;
  const width = opts.width ?? 640;
  const height = opts.height ?? 240;
  const plotW = Math.max(40, width - padL - padR);
  const plotH = height - padT - padB;
  const n = points.length;
  const x = (i) => (n === 1 ? padL + plotW / 2 : padL + (i / (n - 1)) * plotW);
  const y = (v) => padT + (1 - v) * plotH;

  const root = svg('svg', {
    class: 'chart', viewBox: `0 0 ${width} ${height}`,
    preserveAspectRatio: 'xMinYMin meet', role: 'img',
    'aria-label': opts.ariaLabel || 'Line chart',
  });

  for (let t = 0; t <= 1.0001; t += 0.25) {
    root.appendChild(svg('line', { class: 'grid-line', x1: padL, x2: padL + plotW, y1: y(t), y2: y(t) }));
    const label = svg('text', { class: 'tick-label', x: padL - 8, y: y(t) + 4, 'text-anchor': 'end' });
    label.textContent = `${Math.round(t * 100)}%`;
    root.appendChild(label);
  }

  points.forEach((p, i) => {
    const label = svg('text', {
      x: x(i), y: height - padB + 18, 'text-anchor': 'middle',
    });
    const name = String(p.name);
    label.textContent = name.length > 14 ? `${name.slice(0, 13)}…` : name;
    root.appendChild(label);
  });

  for (const s of series) {
    const path = points.map((p, i) => `${i ? 'L' : 'M'}${x(i)},${y(p[s.key] || 0)}`).join(' ');
    root.appendChild(svg('path', {
      d: path, fill: 'none', stroke: s.color, 'stroke-width': 2,
      'stroke-linejoin': 'round', 'stroke-linecap': 'round',
    }));

    points.forEach((p, i) => {
      const dot = svg('circle', {
        cx: x(i), cy: y(p[s.key] || 0), r: 4.5, fill: s.color,
        stroke: token('--panel-2'), 'stroke-width': 2,  // 2px surface ring
      });
      attachTip(dot,
        `<strong>${escapeHtml(p.name)}</strong><br>` +
        `<span class="tt-key">${escapeHtml(s.label)}</span> ${pct(p[s.key])}` +
        (p.synthetic ? '<br><span class="tt-key">synthetic run</span>' : ''));
      root.appendChild(dot);
    });

    // Direct-label the final point only.
    const last = points[points.length - 1];
    const text = svg('text', {
      class: 'value-label', x: x(n - 1) + 10, y: y(last[s.key] || 0) + 4, fill: s.color,
    });
    text.textContent = pct(last[s.key]);
    root.appendChild(text);
  }

  return root;
}

/**
 * Diverging bar centred on zero, for metric deltas.
 * Only rates are plotted — counts and runtime live on other scales, and
 * putting them on one axis would be the dual-axis mistake in disguise.
 */
function divergingBarChart(rows, opts = {}) {
  const labelW = opts.labelWidth ?? 92;
  const rowH = 26, gap = 12, padR = 56, padB = 28, padT = 6;
  const width = opts.width ?? 640;
  const height = padT + rows.length * (rowH + gap) + padB;
  const plotW = Math.max(60, width - labelW - padR);
  const mid = labelW + plotW / 2;
  const bound = Math.max(0.05, ...rows.map((r) => Math.abs(r.delta)));
  const scale = (v) => (v / bound) * (plotW / 2);

  const root = svg('svg', {
    class: 'chart', viewBox: `0 0 ${width} ${height}`,
    preserveAspectRatio: 'xMinYMin meet', role: 'img',
    'aria-label': opts.ariaLabel || 'Change versus baseline',
  });

  root.appendChild(svg('line', {
    class: 'axis-line', x1: mid, x2: mid, y1: padT, y2: height - padB,
  }));

  rows.forEach((row, i) => {
    const y = padT + i * (rowH + gap);
    const name = svg('text', { x: labelW - 10, y: y + rowH / 2 + 4, 'text-anchor': 'end' });
    name.textContent = row.name;
    root.appendChild(name);

    const w = Math.abs(scale(row.delta));
    // A rise in a good metric and a fall in a bad one are both improvements,
    // so colour follows `improvement`, never the raw sign of the delta.
    const color = row.delta === 0 ? token('--neutral')
      : row.improvement ? token('--pos') : token('--neg');
    const rect = svg('rect', {
      class: 'bar', x: row.delta >= 0 ? mid : mid - w, y,
      width: Math.max(2, w), height: rowH, rx: 4, fill: color,
    });
    attachTip(rect,
      `<strong>${escapeHtml(row.name)}</strong><br>` +
      `<span class="tt-key">baseline</span> ${escapeHtml(row.baselineText)}<br>` +
      `<span class="tt-key">candidate</span> ${escapeHtml(row.candidateText)}`);
    root.appendChild(rect);

    const value = svg('text', {
      class: 'value-label',
      x: row.delta >= 0 ? mid + w + 8 : mid - w - 8,
      y: y + rowH / 2 + 4,
      'text-anchor': row.delta >= 0 ? 'start' : 'end',
    });
    value.textContent = `${row.delta >= 0 ? '+' : ''}${(row.delta * 100).toFixed(1)}pp`;
    root.appendChild(value);
  });

  return root;
}

/* ------------------------------------------------------------------ *
 * Shared building blocks
 * ------------------------------------------------------------------ */

function tiles(items) {
  return el('div', { class: 'tiles' },
    items.map((t) =>
      el('div', { class: `tile${t.accent ? ' accent' : ''}` },
        el('div', { class: 'tile-label', text: t.label }),
        el('div', { class: 'tile-value', text: String(t.value) }),
        t.note ? el('div', { class: 'tile-note', text: t.note }) : null)));
}

function card(title, note, ...body) {
  return el('div', { class: 'card' },
    el('div', { class: 'card-head' }, el('span', { class: 'card-title', text: title })),
    note ? el('div', { class: 'card-note', text: note }) : null,
    ...body);
}

function table(columns, rows) {
  return el('div', { class: 'table-wrap' },
    el('table', {},
      el('thead', {}, el('tr', {}, columns.map((c) => el('th', { text: c.label })))),
      el('tbody', {},
        rows.length
          ? rows.map((r) => el('tr', {}, columns.map((c) =>
              el('td', { class: c.numeric ? 'num' : (c.mono ? 'mono' : ''), text: String(c.get(r) ?? '') }))))
          : [el('tr', {}, el('td', { colspan: columns.length, text: '—' }))])));
}

/** The table twin every chart ships with. */
function tableView(columns, rows, label = 'Table view') {
  return el('details', { class: 'table-view' },
    el('summary', { text: label }),
    table(columns, rows));
}

function banner(kind, title, html) {
  return el('div', { class: `banner ${kind}` },
    el('strong', { text: title }), ' ', el('span', { html }));
}

function metaRow(pairs) {
  return el('div', { class: 'meta' },
    pairs.filter(([, v]) => v).map(([k, v]) =>
      el('span', {}, `${k} `, el('code', { text: String(v) }))));
}

function empty(message) {
  return el('div', { class: 'empty', text: message });
}

function loading(message = 'Loading…') {
  return el('div', { class: 'empty' }, el('span', { class: 'spinner' }), ` ${message}`);
}

/* ------------------------------------------------------------------ *
 * API
 * ------------------------------------------------------------------ */

const api = {
  async get(path) {
    const res = await fetch(path, { headers: { Accept: 'application/json' } });
    if (!res.ok) {
      let detail = `${res.status} ${res.statusText}`;
      try {
        const body = await res.json();
        if (body.detail) detail = body.detail;
      } catch { /* non-JSON error body; the status line is enough */ }
      throw new Error(detail);
    }
    return res.json();
  },
  scans: () => api.get('/api/scans'),
  scan: (path) => api.get(`/api/scan?path=${encodeURIComponent(path)}`),
  runs: () => api.get('/api/runs'),
  run: (id) => api.get(`/api/run/${encodeURIComponent(id)}`),
  health: () => api.get('/api/health'),
};

/* ------------------------------------------------------------------ *
 * State
 * ------------------------------------------------------------------ */

const state = {
  view: 'scan',
  scans: [], scan: null, scanPath: null,
  severityFilter: new Set(), search: '',
  runs: [], run: null, runId: null,
  baselineId: null, candidateId: null,
  baseline: null, candidate: null,
};

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const severityColor = (s) => token(`--sev-${s}`) || token('--muted');

function mount(railNode, mainNode, detailNode) {
  const workspace = document.getElementById('workspace');
  workspace.classList.toggle('no-detail', !detailNode);
  document.getElementById('rail').replaceChildren(railNode || el('div'));
  document.getElementById('main').replaceChildren(mainNode || el('div'));
  const detail = document.querySelector('.detail');
  detail.style.display = detailNode ? '' : 'none';
  document.getElementById('detail').replaceChildren(detailNode || el('div'));
}

/* ------------------------------------------------------------------ *
 * View: scan report
 * ------------------------------------------------------------------ */

async function renderScanView() {
  mount(loading('Loading scans…'), loading(), null);

  if (!state.scans.length) {
    try {
      state.scans = await api.scans();
    } catch (err) {
      mount(el('div'), banner('danger', 'Could not list scans.', escapeHtml(err.message)), null);
      return;
    }
  }

  if (!state.scans.length) {
    mount(
      el('div', {}, el('h2', { class: 'panel-title', text: 'Scan Report' }),
        el('p', { class: 'panel-note', text: 'No reports found yet.' })),
      banner('info', 'No scans found.',
        'Run <code>cpgvd analyze &lt;repo&gt;</code> to produce a <code>report.json</code>, ' +
        'then reload this page.'),
      null);
    return;
  }

  if (!state.scanPath || !state.scans.some((s) => s.path === state.scanPath)) {
    state.scanPath = state.scans[0].path;
    state.scan = null;
  }
  if (!state.scan) {
    try {
      state.scan = await api.scan(state.scanPath);
      state.severityFilter = new Set(SEVERITIES);
    } catch (err) {
      mount(el('div'), banner('danger', 'Could not load scan.', escapeHtml(err.message)), null);
      return;
    }
  }

  const report = state.scan;
  const findings = report.findings || [];
  const stats = report.stats || {};

  const bySeverity = {};
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;

  /* --- rail --- */
  const select = el('select', {
    onchange: (e) => { state.scanPath = e.target.value; state.scan = null; renderScanView(); },
  }, state.scans.map((s) => el('option', {
    value: s.path, selected: s.path === state.scanPath,
    text: `${s.name} · ${s.findings} finding${s.findings === 1 ? '' : 's'}`,
  })));

  const severityButtons = el('div', { style: 'display:flex;flex-wrap:wrap;gap:0.3rem' },
    SEVERITIES.map((s) => el('button', {
      class: `btn${state.severityFilter.has(s) ? ' active' : ''}`,
      style: 'padding:0.3rem 0.55rem;font-size:0.76rem',
      onclick: () => {
        if (state.severityFilter.has(s)) state.severityFilter.delete(s);
        else state.severityFilter.add(s);
        renderScanView();
      },
    },
      el('span', {
        class: 'legend-swatch',
        style: `background:${severityColor(s)};display:inline-block;margin-right:0.35rem`,
      }),
      `${s} (${bySeverity[s] || 0})`)));

  const rail = el('div', {},
    el('h2', { class: 'panel-title', text: 'Scan Report' }),
    el('p', { class: 'panel-note', text: 'Findings from one cpgvd analysis run, with the call-graph context that justified each.' }),
    el('div', { class: 'field' }, el('label', { text: 'Report' }), select),
    el('div', { class: 'field' }, el('label', { text: 'Severity' }), severityButtons),
    el('div', { class: 'field' },
      el('label', { text: 'Search' }),
      el('input', {
        type: 'search', placeholder: 'file, function, or title', value: state.search,
        oninput: (e) => { state.search = e.target.value; renderFindingsOnly(); },
      })),
    el('hr', { class: 'rule' }),
    el('div', { class: 'tile-label', text: 'Pipeline' }),
    el('div', { style: 'margin-top:0.6rem' },
      stageRows(stats.stage_timings || {})));

  /* --- main --- */
  const main = el('div', {},
    el('h2', { class: 'panel-title', text: report.repo || 'Scan' }),
    metaRow([
      ['commit', (report.commit_sha || '').slice(0, 12)],
      ['model', report.model],
      ['languages', (report.languages || []).join(', ')],
      ['generated', shortDate(report.generated_at)],
    ]),
    tiles([
      { label: 'Findings', value: findings.length, accent: true,
        note: `${stats.candidate_contexts_analyzed || 0} contexts analysed` },
      { label: 'Functions', value: stats.functions_discovered || 0 },
      { label: 'Sink matches', value: stats.sink_matches || 0 },
      { label: 'LLM calls', value: stats.llm_calls || 0 },
      { label: 'Duration', value: `${num(stats.duration_seconds, 0)}s` },
      { label: 'Peak memory', value: stats.peak_memory_mb ? `${num(stats.peak_memory_mb, 0)} MB` : '—' },
    ]),
    findings.length ? severityCard(bySeverity) : null,
    el('div', { id: 'findings-block' }));

  /* --- detail --- */
  const detail = el('div', {},
    el('h2', { class: 'panel-title', text: 'Runtime' }),
    el('p', { class: 'panel-note', text: 'Where this scan spent its wall-clock time.' }),
    stageCard(stats.stage_timings || {}));

  mount(rail, main, detail);
  renderFindingsOnly();
}

function stageRows(timings) {
  const entries = Object.entries(timings);
  if (!entries.length) return el('div', { class: 'tile-note', text: 'No stage timings in this report.' });
  const total = entries.reduce((s, [, v]) => s + v, 0) || 1;
  return el('div', {}, entries
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4)
    .map(([name, secs]) => el('div', {
      style: 'display:flex;justify-content:space-between;font-size:0.78rem;padding:0.2rem 0;color:var(--text-2)',
    },
      el('span', { text: name.replace(/_/g, ' ') }),
      el('span', { class: 'mono', text: `${((100 * secs) / total).toFixed(0)}%` }))));
}

function stageCard(timings) {
  const entries = Object.entries(timings);
  if (!entries.length) {
    return banner('info', 'No stage timings.',
      'This report predates the pipeline instrumentation — re-run the scan to populate it.');
  }
  const rows = entries
    .map(([name, seconds]) => ({ name: name.replace(/_/g, ' '), value: seconds }))
    .sort((a, b) => b.value - a.value);
  const total = rows.reduce((s, r) => s + r.value, 0) || 1;
  return card('Stage breakdown',
    `${rows[0].name} dominates at ${((100 * rows[0].value) / total).toFixed(0)}% of total.`,
    barChart(rows, { width: 300, labelWidth: 120, rowHeight: 18, format: (v) => `${num(v, 1)}s`,
      ariaLabel: 'Runtime per pipeline stage' }),
    tableView(
      [{ label: 'Stage', get: (r) => r.name },
       { label: 'Seconds', numeric: true, get: (r) => num(r.value, 2) },
       { label: 'Share', numeric: true, get: (r) => `${((100 * r.value) / total).toFixed(1)}%` }],
      rows));
}

function severityCard(bySeverity) {
  const present = SEVERITIES.filter((s) => bySeverity[s]);
  const rows = present.map((s) => ({
    name: s, value: bySeverity[s], color: severityColor(s),
    tip: `${bySeverity[s]} finding${bySeverity[s] === 1 ? '' : 's'}`,
  }));
  return card('Findings by severity',
    'Severity is an ordered scale, so this is a single-hue ramp — darker is more severe. The level name sits beside every bar, so colour never carries the ordering alone.',
    barChart(rows, { width: 620, labelWidth: 76, rowHeight: 22, format: (v) => String(v),
      ariaLabel: 'Findings by severity' }),
    tableView(
      [{ label: 'Severity', get: (r) => r.name },
       { label: 'Findings', numeric: true, get: (r) => r.value }],
      rows));
}

/** Re-render only the findings list, so typing in search doesn't rebuild charts. */
function renderFindingsOnly() {
  const block = document.getElementById('findings-block');
  if (!block || !state.scan) return;

  const q = state.search.trim().toLowerCase();
  const findings = (state.scan.findings || [])
    .filter((f) => state.severityFilter.has(f.severity))
    .filter((f) => !q
      || (f.file || '').toLowerCase().includes(q)
      || (f.function || '').toLowerCase().includes(q)
      || (f.title || '').toLowerCase().includes(q))
    .sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));

  const total = (state.scan.findings || []).length;
  block.replaceChildren(
    el('div', { class: 'card-head', style: 'margin:1.2rem 0 0.5rem' },
      el('span', { class: 'card-title', text: `Findings (${findings.length} of ${total})` })),
    findings.length
      ? el('div', {}, findings.map(findingNode))
      : empty('No findings match the current filters.'));
}

function findingNode(f) {
  const color = severityColor(f.severity);
  return el('details', { class: 'finding', style: `border-left-color:${color}` },
    el('summary', {},
      el('span', { class: 'pill' },
        el('span', { class: 'swatch', style: `background:${color}` }), f.severity),
      el('span', { class: 'finding-title', text: f.title || f.vulnerability_type }),
      el('span', { class: 'finding-loc', text: `${f.file}:${f.start_line}` })),
    el('div', { class: 'finding-body' },
      metaRow([
        ['function', f.function],
        ['type', f.vulnerability_type],
        ['cwe', f.cwe || 'n/a'],
        ['confidence', f.confidence],
      ]),
      el('p', { text: f.description || '' }),
      f.context_reasoning
        ? el('div', {}, el('h4', { text: 'Why context mattered' }), el('p', { text: f.context_reasoning }))
        : null,
      f.data_flow_summary
        ? el('div', {}, el('h4', { text: 'Data flow' }),
            el('p', { class: 'mono', text: f.data_flow_summary }))
        : null,
      f.suggested_fix
        ? el('div', {}, el('h4', { text: 'Suggested fix' }), el('p', { text: f.suggested_fix }))
        : null));
}

/* ------------------------------------------------------------------ *
 * View: benchmark analysis
 * ------------------------------------------------------------------ */

async function renderBenchmarkView() {
  mount(loading('Loading runs…'), loading(), null);

  if (!state.runs.length) {
    try {
      state.runs = await api.runs();
    } catch (err) {
      mount(el('div'), banner('danger', 'Could not list runs.', escapeHtml(err.message)), null);
      return;
    }
  }

  if (!state.runs.length) {
    mount(
      el('div', {}, el('h2', { class: 'panel-title', text: 'Benchmark Analysis' })),
      banner('info', 'No benchmark runs archived.',
        'Record one with <code>python -m benchmark.run --label baseline</code>, then reload.'),
      null);
    return;
  }

  if (!state.runId || !state.runs.some((r) => r.run_id === state.runId)) {
    state.runId = state.runs[0].run_id;
    state.run = null;
  }
  if (!state.run) {
    try {
      state.run = await api.run(state.runId);
    } catch (err) {
      mount(el('div'), banner('danger', 'Could not load run.', escapeHtml(err.message)), null);
      return;
    }
  }

  const run = state.run;
  const meta = run.metadata || {};
  const overall = overallMetrics(run);
  const cases = run.cases || [];
  const totalGt = okCases(run).reduce((s, c) => s + (c.ground_truth_total || 0), 0);
  const byCwe = metricsByCwe(run);
  const rt = runtimeStats(run);

  const s1 = token('--series-1'), s2 = token('--series-2'), s3 = token('--series-3');
  const outcomeSeries = [
    { key: 'tp', label: 'True positives', color: s1 },
    { key: 'fp', label: 'False positives', color: s2 },
    { key: 'fn', label: 'False negatives', color: s3 },
  ];

  /* --- rail --- */
  const rail = el('div', {},
    el('h2', { class: 'panel-title', text: 'Benchmark Analysis' }),
    el('p', { class: 'panel-note', text: 'Detection quality scored against known ground truth.' }),
    el('div', { class: 'field' },
      el('label', { text: 'Run' }),
      el('select', {
        onchange: (e) => { state.runId = e.target.value; state.run = null; renderBenchmarkView(); },
      }, state.runs.map((r) => el('option', {
        value: r.run_id, selected: r.run_id === state.runId,
        text: `${r.label || r.run_id}${r.synthetic ? ' (synthetic)' : ''}`,
      })))),
    el('hr', { class: 'rule' }),
    el('div', { class: 'hero' },
      el('div', { class: 'hero-label', text: 'F1 Score' }),
      el('div', { class: 'hero-value', text: overall.f1.toFixed(3) }),
      el('div', { class: 'hero-note', text: `${pct(overall.precision)} precision · ${pct(overall.recall)} recall` })),
    el('hr', { class: 'rule' }),
    tiles([
      { label: 'True pos', value: overall.tp },
      { label: 'False pos', value: overall.fp },
      { label: 'False neg', value: overall.fn },
      { label: 'True neg', value: overall.tn },
    ]),
    el('div', { class: 'tile-label', text: 'Provenance', style: 'margin-top:0.6rem' }),
    el('div', { style: 'font-size:0.79rem;line-height:1.9;color:var(--text-2);margin-top:0.4rem' },
      kv('Label', meta.label || '—'),
      kv('Model', meta.model || 'n/a'),
      kv('Runner', meta.runner || '—'),
      kv('Commit', (meta.git_commit || '').slice(0, 12) || 'unknown'),
      kv('Cases', `${okCases(run).length}/${cases.length}`)));

  /* --- main --- */
  const main = el('div', {},
    el('h2', { class: 'panel-title', text: 'Results' }),
    metaRow([
      ['run', meta.run_id],
      ['datasets', (meta.datasets || []).join(', ')],
      ['generated', shortDate(meta.created_at)],
    ]),
    meta.synthetic
      ? banner('danger', '⚠ Synthetic run — not a measurement.',
          'These results were replayed from fixtures or archived reports rather than produced ' +
          'by a live scan. They demonstrate that the framework works and must not be cited as ' +
          "cpgvd's detection quality.")
      : null,
    totalGt < 20
      ? banner('warn', 'Small sample.',
          `${totalGt} ground-truth entries. Precision and recall move in large jumps at this ` +
          'size — read this as a smoke test, not a performance measurement.')
      : null,
    byCwe.length ? card('Outcomes by CWE',
      'Bar width is the total evidence for that class — a rate resting on two entries and one resting on fifty look very different here.',
      legend(outcomeSeries.map((s) => [s.label, s.color])),
      stackedBarChart(byCwe, outcomeSeries, { width: 620, ariaLabel: 'Outcomes by CWE' }),
      tableView(
        [{ label: 'CWE', get: (r) => r.name },
         { label: 'TP', numeric: true, get: (r) => r.tp },
         { label: 'FP', numeric: true, get: (r) => r.fp },
         { label: 'FN', numeric: true, get: (r) => r.fn }],
        byCwe, 'Table view — outcome counts')) : null,
    byCwe.length ? card('Precision / recall by CWE',
      'Support (TP + FN) is in the tooltip and table: a perfect score on two entries is not the same result as a perfect score on fifty.',
      legend([['Precision', s1], ['Recall', s2], ['F1', s3]]),
      groupedBarChart(byCwe, [
        { key: 'precision', label: 'Precision', color: s1 },
        { key: 'recall', label: 'Recall', color: s2 },
        { key: 'f1', label: 'F1', color: s3 },
      ], { width: 620, ariaLabel: 'Precision and recall by CWE' }),
      tableView(
        [{ label: 'CWE', get: (r) => r.name },
         { label: 'Precision', numeric: true, get: (r) => pct(r.precision) },
         { label: 'Recall', numeric: true, get: (r) => pct(r.recall) },
         { label: 'F1', numeric: true, get: (r) => r.f1.toFixed(3) },
         { label: 'Support', numeric: true, get: (r) => r.tp + r.fn }],
        byCwe, 'Table view — rates and support')) : null,
    card('Per case', '',
      table([
        { label: 'Case', get: (c) => c.case_id },
        { label: 'Status', get: (c) => c.status },
        { label: 'TP', numeric: true, get: (c) => c.metrics.true_positives },
        { label: 'FP', numeric: true, get: (c) => c.metrics.false_positives },
        { label: 'FN', numeric: true, get: (c) => c.metrics.false_negatives },
        { label: 'Precision', numeric: true, get: (c) => pct(metricsOf(c.metrics.true_positives, c.metrics.false_positives, c.metrics.false_negatives).precision) },
        { label: 'Recall', numeric: true, get: (c) => pct(metricsOf(c.metrics.true_positives, c.metrics.false_positives, c.metrics.false_negatives).recall) },
        { label: 'Runtime', numeric: true, get: (c) => `${num(c.duration_seconds, 1)}s` },
      ], cases)));

  /* --- detail --- */
  const stages = stageTotals(run);
  const fps = okCases(run).flatMap((c) => (c.false_positives || []).map((f) => ({ ...f, case_id: c.case_id })));
  const fns = okCases(run).flatMap((c) => (c.false_negatives || []).map((f) => ({ ...f, case_id: c.case_id })));
  const nearMiss = fns.filter((f) => f.best_score >= 0.3);

  const detail = el('div', {},
    el('h2', { class: 'panel-title', text: 'Diagnostics' }),
    el('p', { class: 'panel-note', text: 'Runtime profile and the errors worth acting on.' }),
    tiles([
      { label: 'Total', value: `${num(rt.total, 0)}s` },
      { label: 'Median/case', value: `${num(rt.median, 1)}s` },
    ]),
    stages.length ? card('Stage breakdown',
      `${stages[0].name} dominates.`,
      barChart(stages.map((s) => ({ name: s.name, value: s.seconds })),
        { width: 320, labelWidth: 128, rowHeight: 17, format: (v) => `${num(v, 1)}s`,
          ariaLabel: 'Runtime per stage' })) : null,
    card(`False positives (${fps.length})`,
      fps.length ? 'A high best-score is a near-miss worth checking against the matcher; 0.0 is an unambiguous false positive.' : '',
      fps.length ? table([
        { label: 'CWE', get: (f) => f.cwe || '—' },
        { label: 'Type', get: (f) => f.vulnerability_type || '—' },
        { label: 'Location', mono: true, get: (f) => `${f.file}:${f.start_line}` },
        { label: 'Best', numeric: true, get: (f) => (f.best_score ?? 0).toFixed(2) },
      ], fps) : empty('None.')),
    card(`False negatives (${fns.length})`,
      nearMiss.length
        ? `${nearMiss.length} scored close to the match threshold — usually a matching problem (CWE label or line drift), not a detection failure.`
        : '',
      fns.length ? table([
        { label: 'Ground truth', get: (f) => f.ground_truth_id },
        { label: 'CWE', get: (f) => f.cwe || '—' },
        { label: 'Location', mono: true, get: (f) => `${f.file}:${f.start_line ?? '?'}` },
        { label: 'Best', numeric: true, get: (f) => (f.best_score ?? 0).toFixed(2) },
      ], fns) : empty('None.')));

  mount(rail, main, detail);
}

function kv(k, v) {
  return el('div', {},
    el('span', { style: 'color:var(--muted)', text: `${k} ` }),
    el('span', { text: String(v) }));
}

/* ------------------------------------------------------------------ *
 * View: compare runs
 * ------------------------------------------------------------------ */

async function renderCompareView() {
  mount(loading('Loading runs…'), loading(), null);

  if (!state.runs.length) {
    try {
      state.runs = await api.runs();
    } catch (err) {
      mount(el('div'), banner('danger', 'Could not list runs.', escapeHtml(err.message)), null);
      return;
    }
  }

  if (state.runs.length < 2) {
    mount(
      el('div', {}, el('h2', { class: 'panel-title', text: 'Compare Runs' })),
      banner('info', 'Need at least two runs.',
        'Record another with a different <code>--label</code>, then reload.'),
      null);
    return;
  }

  // Default to oldest as baseline, newest as candidate — the usual question
  // is "did the thing I just changed help?".
  if (!state.baselineId) state.baselineId = state.runs[state.runs.length - 1].run_id;
  if (!state.candidateId) state.candidateId = state.runs[0].run_id;

  try {
    [state.baseline, state.candidate] = await Promise.all([
      api.run(state.baselineId), api.run(state.candidateId),
    ]);
  } catch (err) {
    mount(el('div'), banner('danger', 'Could not load runs.', escapeHtml(err.message)), null);
    return;
  }

  const b = overallMetrics(state.baseline);
  const c = overallMetrics(state.candidate);
  const bRt = runtimeStats(state.baseline), cRt = runtimeStats(state.candidate);

  const rateRows = [
    { name: 'Precision', delta: c.precision - b.precision, improvement: c.precision > b.precision,
      baselineText: pct(b.precision), candidateText: pct(c.precision) },
    { name: 'Recall', delta: c.recall - b.recall, improvement: c.recall > b.recall,
      baselineText: pct(b.recall), candidateText: pct(c.recall) },
    { name: 'F1', delta: c.f1 - b.f1, improvement: c.f1 > b.f1,
      baselineText: b.f1.toFixed(3), candidateText: c.f1.toFixed(3) },
  ];

  const countRows = [
    { name: 'True positives', before: b.tp, after: c.tp, higherBetter: true },
    { name: 'False positives', before: b.fp, after: c.fp, higherBetter: false },
    { name: 'False negatives', before: b.fn, after: c.fn, higherBetter: false },
    { name: 'Total runtime (s)', before: Math.round(bRt.total), after: Math.round(cRt.total), higherBetter: false },
  ].map((r) => ({ ...r, delta: r.after - r.before,
    improvement: r.after === r.before ? null : (r.after > r.before) === r.higherBetter }));

  const detected = new Set(okCases(state.candidate).flatMap((x) => (x.matches || []).map((m) => m.ground_truth_id)));
  const before = new Set(okCases(state.baseline).flatMap((x) => (x.matches || []).map((m) => m.ground_truth_id)));
  const newlyDetected = [...detected].filter((id) => !before.has(id)).sort();
  const newlyMissed = [...before].filter((id) => !detected.has(id)).sort();

  const runSelect = (which, selected) => el('select', {
    onchange: (e) => {
      if (which === 'baseline') state.baselineId = e.target.value;
      else state.candidateId = e.target.value;
      renderCompareView();
    },
  }, state.runs.map((r) => el('option', {
    value: r.run_id, selected: r.run_id === selected,
    text: `${r.label || r.run_id}${r.synthetic ? ' (synthetic)' : ''}`,
  })));

  const df1 = c.f1 - b.f1;
  const verdict = Math.abs(df1) < 0.005
    ? ['info', 'No material change.', 'F1 moved less than 0.005. Treat as neutral.']
    : df1 > 0
      ? ['info', 'Improvement.', `F1 ${b.f1.toFixed(3)} → ${c.f1.toFixed(3)} (+${df1.toFixed(3)}).`]
      : ['danger', 'Regression.', `F1 ${b.f1.toFixed(3)} → ${c.f1.toFixed(3)} (${df1.toFixed(3)}).`];

  const rail = el('div', {},
    el('h2', { class: 'panel-title', text: 'Compare Runs' }),
    el('p', { class: 'panel-note', text: 'Did the change help? Metric deltas plus the specific vulnerabilities that changed status.' }),
    el('div', { class: 'field' }, el('label', { text: 'Baseline' }), runSelect('baseline', state.baselineId)),
    el('div', { class: 'field' }, el('label', { text: 'Candidate' }), runSelect('candidate', state.candidateId)),
    el('hr', { class: 'rule' }),
    el('div', { class: 'hero' },
      el('div', { class: 'hero-label', text: 'F1 Delta' }),
      el('div', {
        class: 'hero-value',
        style: `color:${df1 >= 0 ? token('--pos') : token('--neg')};text-shadow:none`,
        text: `${df1 >= 0 ? '+' : ''}${df1.toFixed(3)}`,
      })),
    banner(...verdict));

  const main = el('div', {},
    el('h2', { class: 'panel-title', text: 'Change vs baseline' }),
    (state.baseline.metadata?.synthetic || state.candidate.metadata?.synthetic)
      ? banner('danger', '⚠ Synthetic run involved.',
          'One or both runs were replayed rather than measured. This comparison demonstrates the tooling only.')
      : null,
    card('Rate deltas',
      'Rates only — counts and runtime live on different scales, and plotting them on one axis would be the dual-axis mistake in disguise. They are in the table below.',
      divergingBarChart(rateRows, { width: 620, ariaLabel: 'Change in precision, recall and F1' }),
      tableView(
        [{ label: 'Metric', get: (r) => r.name },
         { label: 'Baseline', numeric: true, get: (r) => r.baselineText },
         { label: 'Candidate', numeric: true, get: (r) => r.candidateText },
         { label: 'Delta', numeric: true, get: (r) => `${r.delta >= 0 ? '+' : ''}${(r.delta * 100).toFixed(1)}pp` }],
        rateRows, 'Table view — rate deltas')),
    card('Counts and runtime', '',
      table([
        { label: 'Metric', get: (r) => r.name },
        { label: 'Baseline', numeric: true, get: (r) => r.before },
        { label: 'Candidate', numeric: true, get: (r) => r.after },
        { label: 'Delta', numeric: true, get: (r) => `${r.delta >= 0 ? '+' : ''}${r.delta}` },
        { label: 'Direction', get: (r) => r.improvement === null ? '—' : (r.improvement ? 'better' : 'worse') },
      ], countRows)));

  const detail = el('div', {},
    el('h2', { class: 'panel-title', text: 'Detection diff' }),
    el('p', { class: 'panel-note', text: 'What an aggregate F1 hides: a change can leave F1 flat while swapping which vulnerabilities it catches.' }),
    card(`Newly detected (${newlyDetected.length})`, '',
      newlyDetected.length
        ? table([{ label: 'Ground truth', get: (id) => id }], newlyDetected)
        : empty('None.')),
    card(`Newly missed (${newlyMissed.length})`,
      newlyMissed.length ? 'These are regressions — the baseline found them and the candidate does not.' : '',
      newlyMissed.length
        ? table([{ label: 'Ground truth', get: (id) => id }], newlyMissed)
        : empty('None.')),
    state.runs.length >= 2 ? historyCard() : null);

  mount(rail, main, detail);
}

/** Metric trend across every archived run, loaded lazily into its card. */
function historyCard() {
  const container = card('Trend across runs',
    'Only the latest point is labelled; hover any point for its value.',
    loading('Loading history…'));

  (async () => {
    try {
      const runs = await Promise.all(state.runs.map((r) => api.run(r.run_id)));
      const points = runs
        .map((run) => {
          const m = overallMetrics(run);
          return {
            name: run.metadata?.label || run.metadata?.run_id || '?',
            created: run.metadata?.created_at || '',
            synthetic: !!run.metadata?.synthetic,
            precision: m.precision, recall: m.recall, f1: m.f1,
          };
        })
        .sort((a, b) => String(a.created).localeCompare(String(b.created)));

      const s1 = token('--series-1'), s2 = token('--series-2'), s3 = token('--series-3');
      const series = [
        { key: 'precision', label: 'Precision', color: s1 },
        { key: 'recall', label: 'Recall', color: s2 },
        { key: 'f1', label: 'F1', color: s3 },
      ];
      container.replaceChildren(
        el('div', { class: 'card-head' }, el('span', { class: 'card-title', text: 'Trend across runs' })),
        el('div', { class: 'card-note', text: 'Only the latest point is labelled; hover any point for its value.' }),
        legend(series.map((s) => [s.label, s.color])),
        lineChart(points, series, { width: 330, height: 220, ariaLabel: 'Metric trend across runs' }),
        tableView(
          [{ label: 'Run', get: (p) => p.name },
           { label: 'Precision', numeric: true, get: (p) => pct(p.precision) },
           { label: 'Recall', numeric: true, get: (p) => pct(p.recall) },
           { label: 'F1', numeric: true, get: (p) => p.f1.toFixed(3) }],
          points, 'Table view — history'));
    } catch (err) {
      container.replaceChildren(banner('danger', 'Could not load history.', escapeHtml(err.message)));
    }
  })();

  return container;
}

/* ------------------------------------------------------------------ *
 * Router
 * ------------------------------------------------------------------ */

const VIEWS = {
  scan: renderScanView,
  benchmark: renderBenchmarkView,
  compare: renderCompareView,
};

function navigate(view, { push = true } = {}) {
  if (!VIEWS[view]) view = 'scan';
  state.view = view;
  for (const btn of document.querySelectorAll('#nav button')) {
    if (btn.dataset.view === view) btn.setAttribute('aria-current', 'page');
    else btn.removeAttribute('aria-current');
  }
  if (push && window.location.hash !== `#${view}`) window.location.hash = view;
  VIEWS[view]().catch((err) => {
    mount(el('div'), banner('danger', 'Unexpected error.', escapeHtml(err.message)), null);
    console.error(err);
  });
}

async function checkHealth() {
  const dot = document.querySelector('#conn .status-dot');
  const text = document.getElementById('conn-text');
  try {
    await api.health();
    dot.classList.remove('offline');
    text.textContent = 'connected';
  } catch {
    dot.classList.add('offline');
    text.textContent = 'server unreachable';
  }
}

function init() {
  tooltip.init();
  document.getElementById('nav').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-view]');
    if (btn) navigate(btn.dataset.view);
  });
  window.addEventListener('hashchange', () => navigate(window.location.hash.slice(1), { push: false }));
  checkHealth();
  navigate(window.location.hash.slice(1) || 'scan', { push: false });
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
else init();
