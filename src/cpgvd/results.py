"""Roll every eval JSON in a directory into one comparison table.

Reads corpus/eval/<app>[-raw|-semgrep].json and emits a single Markdown
document: the three detectors (cpgvd grounded / cpgvd ungrounded / semgrep)
side by side, overall and per operator, plus the compression and
grounded-findings ratios and the corpus composition. This is the raw
material for the paper's results section.
"""

from __future__ import annotations

import json
from pathlib import Path

from .models import EvalReport

_VARIANTS = {
    "": "cpgvd (grounded)",
    "-raw": "cpgvd (ungrounded)",
    "-semgrep": "semgrep (rules only)",
}


def _load(eval_dir: Path) -> dict[str, list[EvalReport]]:
    out: dict[str, list[EvalReport]] = {k: [] for k in _VARIANTS}
    for p in sorted(Path(eval_dir).glob("*.json")):
        if p.name.startswith("_"):
            continue
        for suffix in ("-raw", "-semgrep", ""):
            if p.stem.endswith(suffix):
                try:
                    out[suffix].append(EvalReport.model_validate_json(p.read_text()))
                except Exception:  # noqa: BLE001
                    pass
                break
    return out


def _pool(reports: list[EvalReport]) -> dict:
    tp = sum(r.summary.tp for r in reports)
    fp = sum(r.summary.fp for r in reports)
    fn = sum(r.summary.fn for r in reports)
    n = sum(r.summary.n_mutations for r in reports)
    base = sum(r.summary.baseline_fp for r in reports)
    raw_tp = round(sum(r.summary.recall_raw * r.summary.n_mutations for r in reports))
    by_op: dict[str, dict] = {}
    for r in reports:
        for op, b in r.summary.by_operator.items():
            d = by_op.setdefault(op, {"tp": 0, "fn": 0})
            d["tp"] += b["tp"]
            d["fn"] += b["fn"]
    for b in by_op.values():
        t = b["tp"] + b["fn"]
        b["recall"] = round(b["tp"] / t, 2) if t else 0.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    comp = [r.summary.compression.get("slice_over_file_mean") for r in reports]
    comp = [c for c in comp if c is not None]
    gnd = [r.summary.grounded_findings.get("ratio") for r in reports]
    gnd = [g for g in gnd if g is not None]
    return {
        "apps": len(reports),
        "mutations": n,
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(prec, 3),
        "recall": round(rec, 3),
        "recall_raw": round(raw_tp / n, 3) if n else 0.0,
        "f1": round(f1, 3),
        "baseline_fp": base,
        "by_operator": by_op,
        "slice_over_file": round(sum(comp) / len(comp), 4) if comp else None,
        "grounded_ratio": round(sum(gnd) / len(gnd), 3) if gnd else None,
    }


def build_markdown(eval_dir: Path) -> str:
    loaded = _load(eval_dir)
    pooled = {k: _pool(v) for k, v in loaded.items() if v}
    L: list[str] = ["# Control-absence evaluation -- results", ""]

    if not pooled:
        return "# No eval JSON found in " + str(eval_dir) + "\n"

    L += ["## Overall (pooled across apps)", ""]
    L.append("| detector | apps | mutations | precision | recall | recall_raw | F1 | FP on originals |")
    L.append("|---|--:|--:|--:|--:|--:|--:|--:|")
    for suffix, name in _VARIANTS.items():
        if suffix not in pooled:
            continue
        p = pooled[suffix]
        L.append(
            f"| {name} | {p['apps']} | {p['mutations']} | {p['precision']:.2f} | "
            f"{p['recall']:.2f} | {p['recall_raw']:.2f} | {p['f1']:.2f} | {p['baseline_fp']} |"
        )
    L.append("")

    ops = sorted({op for p in pooled.values() for op in p["by_operator"]})
    if ops:
        L += ["## Recall by operator", "", "| operator | " + " | ".join(_VARIANTS[s] for s in _VARIANTS if s in pooled) + " |"]
        L.append("|---|" + "|".join("--:" for s in _VARIANTS if s in pooled) + "|")
        for op in ops:
            row = [op]
            for s in _VARIANTS:
                if s not in pooled:
                    continue
                b = pooled[s]["by_operator"].get(op)
                row.append(f"{b['recall']:.2f} ({b['tp']}/{b['tp'] + b['fn']})" if b else "-")
            L.append("| " + " | ".join(row) + " |")
        L.append("")

    g = pooled.get("")
    if g and (g["slice_over_file"] is not None or g["grounded_ratio"] is not None):
        L += ["## H3 / H5 (grounded runs)", ""]
        if g["slice_over_file"] is not None:
            L.append(f"- **Compression (H3):** the CPG slice is on average **{g['slice_over_file'] * 100:.1f}%** of the file it came from.")
        if g["grounded_ratio"] is not None:
            L.append(f"- **Grounded findings (H5):** **{g['grounded_ratio'] * 100:.0f}%** of findings cite line numbers that were in the context shown.")
        L.append("")

    L += ["## Per app (grounded)", "", "| app | mutations | precision | recall | recall_raw | F1 | FP orig |", "|---|--:|--:|--:|--:|--:|--:|"]
    for r in sorted(loaded.get("", []), key=lambda x: -x.summary.n_mutations):
        s = r.summary
        L.append(
            f"| {s.app} | {s.n_mutations} | {s.precision:.2f} | {s.recall:.2f} | "
            f"{s.recall_raw:.2f} | {s.f1:.2f} | {s.baseline_fp} |"
        )
    L.append("")
    return "\n".join(L)
