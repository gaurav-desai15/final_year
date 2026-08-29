"""Two measured hypotheses for the paper.

H3 -- compression ratio: how much smaller is the CPG-derived context slice
      than the whole file / the whole repo the model would otherwise have to
      read? (slice LoC / file LoC / repo LoC)

H5 -- grounded-findings ratio: what fraction of the model's findings cite
      line numbers that actually appear in the context it was shown? A high
      ratio means the model is reasoning about code it saw, not hallucinating
      locations.

Both are cheap, purely local computations over the persisted contexts +
findings -- no Joern, no LLM.
"""

from __future__ import annotations

from pathlib import Path
from statistics import median

from .models import Finding, FunctionContext

_SOURCE_SUFFIXES = {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".py"}
_SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "coverage", "__pycache__"}


def _nonblank_lines(text: str) -> int:
    return sum(1 for ln in text.splitlines() if ln.strip())


def count_repo_source_lines(repo_root: Path) -> int:
    total = 0
    for p in Path(repo_root).rglob("*"):
        if p.is_dir() or p.suffix.lower() not in _SOURCE_SUFFIXES:
            continue
        if any(part in _SKIP_DIRS for part in p.relative_to(repo_root).parts):
            continue
        try:
            total += _nonblank_lines(p.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    return total


def _file_lines(repo_root: Path, rel: str) -> int:
    p = Path(repo_root) / rel
    try:
        return _nonblank_lines(p.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return 0


def compression_summary(contexts: list[FunctionContext], repo_root: Path) -> dict:
    """Aggregate slice / file / repo LoC and the ratios over all contexts."""
    if not contexts:
        return {}
    repo_loc = count_repo_source_lines(repo_root)
    slice_locs, file_locs, slice_over_file = [], [], []
    file_cache: dict[str, int] = {}
    for ctx in contexts:
        s = _nonblank_lines(ctx.code)
        f = file_cache.setdefault(ctx.file, _file_lines(repo_root, ctx.file))
        slice_locs.append(s)
        file_locs.append(f)
        if f:
            slice_over_file.append(s / f)
    return {
        "contexts": len(contexts),
        "repo_source_loc": repo_loc,
        "slice_loc_median": int(median(slice_locs)),
        "slice_loc_mean": round(sum(slice_locs) / len(slice_locs), 1),
        "file_loc_median": int(median(file_locs)) if file_locs else 0,
        "slice_over_file_median": round(median(slice_over_file), 4) if slice_over_file else None,
        "slice_over_file_mean": round(sum(slice_over_file) / len(slice_over_file), 4) if slice_over_file else None,
        "slice_over_repo_mean": round((sum(slice_locs) / len(slice_locs)) / repo_loc, 6) if repo_loc else None,
    }


def _context_line_span(ctx: FunctionContext) -> tuple[int, int]:
    """The 1-indexed line range of the target file the model actually saw.

    For a `raw` context that's the whole (possibly truncated) file; for a CPG
    slice it's the candidate's own range, widened a little for the surrounding
    lines the renderer includes.
    """
    if ctx.grounding == "raw":
        return (1, ctx.start_line + ctx.code.count("\n") + 1)
    return (max(1, ctx.start_line - 3), ctx.end_line + 3)


def finding_is_grounded(finding: Finding, ctx: FunctionContext) -> bool:
    lo, hi = _context_line_span(ctx)
    a, b = min(finding.start_line, finding.end_line), max(finding.start_line, finding.end_line)
    # the cited range must overlap what was shown
    return a <= hi and b >= lo


def grounded_findings_ratio(findings: list[Finding], contexts: list[FunctionContext]) -> dict:
    by_id = {c.context_id: c for c in contexts}
    checked = grounded = 0
    for f in findings:
        ctx = by_id.get(f.context_id)
        if ctx is None:
            continue
        checked += 1
        if finding_is_grounded(f, ctx):
            grounded += 1
    return {
        "findings_checked": checked,
        "grounded": grounded,
        "ratio": round(grounded / checked, 3) if checked else None,
    }
