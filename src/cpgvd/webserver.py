"""Local web UI for cpgvd: run a scan from the browser, read its report, and
view the control-absence benchmark.

    cpgvd serve            # http://127.0.0.1:8000

FastAPI + a single static page (src/cpgvd/web/). The Scan page shells out to
`cpgvd analyze` in a background thread and streams its log over SSE; Report and
Benchmark just read JSON already on disk. Bound to localhost by default -- it
runs shell commands with the repo path you give it, so don't expose it.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

REPO_ROOT = Path(__file__).resolve().parents[2]
WEB_DIR = Path(__file__).resolve().parent / "web"
OUTPUT_DIR = REPO_ROOT / "cpgvd_output"
WEB_OUTPUT = OUTPUT_DIR / "web"
EVAL_DIR = REPO_ROOT / "corpus" / "eval"

# `/api/report` may only read report.json files under these roots.
_ALLOWED_REPORT_ROOTS = (OUTPUT_DIR.resolve(),)


# --------------------------------------------------------------------------- #
# scan jobs
# --------------------------------------------------------------------------- #
class ScanRequest(BaseModel):
    repo: str
    mode: str = "absence"
    grounding: str = "cpg"
    provider: str = "ollama"
    model: str = ""
    language: str = ""
    ref: str = ""
    max_contexts: int = 15


@dataclass
class ScanJob:
    id: str
    request: ScanRequest
    out_dir: Path
    status: str = "running"  # running | done | failed
    returncode: int | None = None
    log: list[str] = field(default_factory=list)
    started: float = field(default_factory=time.time)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def append(self, line: str) -> None:
        with self._lock:
            self.log.append(line)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "id": self.id,
                "status": self.status,
                "returncode": self.returncode,
                "log": "\n".join(self.log),
                "n_lines": len(self.log),
                "report_available": (self.out_dir / "report.json").exists(),
                "elapsed": round(time.time() - self.started, 1),
            }

    def lines_from(self, n: int) -> list[str]:
        with self._lock:
            return self.log[n:]


_JOBS: dict[str, ScanJob] = {}


def _cli() -> str:
    cand = Path(sys.executable).with_name("cpgvd")
    if cand.exists():
        return str(cand)
    found = shutil.which("cpgvd")
    if not found:
        raise HTTPException(500, "the `cpgvd` console script is not installed")
    return found


def _run_scan(job: ScanJob) -> None:
    r = job.request
    cmd = [
        _cli(), "analyze", r.repo,
        "--mode", r.mode, "--grounding", r.grounding,
        "--max-contexts", str(r.max_contexts),
        "--output-dir", str(job.out_dir), "-v",
    ]
    if r.provider == "anthropic":
        cmd += ["--provider", "anthropic"]
    if r.language.strip():
        cmd += ["--language", r.language.strip()]
    if r.model.strip():
        cmd += ["--model", r.model.strip()]
    if r.ref.strip():
        cmd += ["--ref", r.ref.strip()]

    job.append(f"$ {' '.join(cmd)}")
    try:
        proc = subprocess.Popen(
            cmd, cwd=str(REPO_ROOT), stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=1,
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            job.append(line.rstrip("\n"))
        job.returncode = proc.wait()
        job.status = "done" if job.returncode == 0 else "failed"
    except Exception as e:  # noqa: BLE001
        job.append(f"[server] scan crashed: {e}")
        job.status = "failed"
        job.returncode = -1


# --------------------------------------------------------------------------- #
# benchmark aggregation
# --------------------------------------------------------------------------- #
def _read_json(p: Path) -> dict | None:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _benchmark() -> dict:
    grounded = _read_json(EVAL_DIR / "_aggregate.json")
    raw = _read_json(EVAL_DIR / "_aggregate-raw.json")
    semgrep = _read_json(EVAL_DIR / "_aggregate-semgrep.json")

    overall = []
    for name, a in (("cpgvd (grounded)", grounded), ("cpgvd (ungrounded)", raw), ("semgrep (rules)", semgrep)):
        if not a:
            continue
        overall.append({
            "detector": name,
            "apps": a.get("apps"),
            "instances": a.get("mutations"),
            "precision": a.get("precision"),
            "recall": a.get("recall"),
            "recall_raw": a.get("recall_raw"),
            "f1": a.get("f1"),
            "fp_on_clean": a.get("baseline_fp_total"),
        })

    by_op: dict[str, dict] = {}
    for name, a in (("grounded", grounded), ("ungrounded", raw), ("semgrep", semgrep)):
        if not a:
            continue
        for op, b in (a.get("by_operator") or {}).items():
            by_op.setdefault(op, {"operator": op})[name] = b.get("recall")

    per_app = []
    if grounded and grounded.get("per_app"):
        for app, m in grounded["per_app"].items():
            per_app.append({"app": app, **m})

    heldout = []
    heldout_classes: dict[str, dict] = {}
    for p in sorted(EVAL_DIR.glob("heldout-*.json")):
        h = _read_json(p)
        if not h:
            continue
        run = p.stem.replace("heldout-", "")
        heldout.append({
            "run": run,
            "grounding": h.get("grounding"),
            "labels": h.get("n_labels"),
            "detected": h.get("n_detected"),
            "recall": h.get("recall"),
            "class_match": h.get("class_ok_rate"),
            "unmatched_findings": h.get("n_findings_unmatched"),
        })
        for c, b in (h.get("by_control_class") or {}).items():
            heldout_classes.setdefault(c, {"control_class": c})[f"{run}/{h.get('grounding')}"] = b.get("recall")

    results_md = (EVAL_DIR / "RESULTS.md")
    return {
        "overall": overall,
        "by_operator": sorted(by_op.values(), key=lambda d: d["operator"]),
        "per_app": per_app,
        "heldout": heldout,
        "heldout_classes": sorted(heldout_classes.values(), key=lambda d: d["control_class"]),
        "results_md": results_md.read_text(encoding="utf-8") if results_md.exists() else "",
        "has_data": bool(overall or heldout),
    }


# --------------------------------------------------------------------------- #
# reports on disk
# --------------------------------------------------------------------------- #
def _list_reports() -> list[dict]:
    """All report.json files under cpgvd_output/, newest first -- so the UI
    opens the most recent scan by default regardless of where it was written."""
    paths: list[Path] = []
    default = OUTPUT_DIR / "report.json"
    if default.exists():
        paths.append(default)
    if WEB_OUTPUT.exists():
        paths += WEB_OUTPUT.glob("*/report.json")
    paths.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    out = []
    for p in paths:
        d = _read_json(p) or {}
        out.append({
            "path": str(p.relative_to(REPO_ROOT)),
            "repo": d.get("repo", "?"),
            "model": d.get("model", "?"),
            "generated_at": d.get("generated_at", ""),
            "n_findings": len(d.get("findings", [])),
            "mtime": p.stat().st_mtime,
        })
    return out


def _looks_like_repo(p: Path) -> bool:
    return (p / ".git").exists() or (p / "package.json").exists() or (p / "pyproject.toml").exists() or (p / "requirements.txt").exists()


def _browse(raw: str | None, show_hidden: bool) -> dict:
    """List sub-directories of `raw` (default: home). Localhost single-user
    tool -- browsing the real filesystem is the point, so no sandboxing beyond
    'must be an existing directory'."""
    base = Path(raw).expanduser() if raw else Path.home()
    try:
        base = base.resolve()
    except OSError:
        base = Path.home()
    if not base.is_dir():
        base = Path.home()
    dirs = []
    try:
        for child in sorted(base.iterdir(), key=lambda c: c.name.lower()):
            if not child.is_dir():
                continue
            if not show_hidden and child.name.startswith("."):
                continue
            try:
                is_repo = _looks_like_repo(child)
            except OSError:
                is_repo = False
            dirs.append({"name": child.name, "path": str(child), "is_repo": is_repo})
    except PermissionError:
        pass
    return {
        "path": str(base),
        "parent": None if base.parent == base else str(base.parent),
        "is_repo": _looks_like_repo(base),
        "dirs": dirs,
        "home": str(Path.home()),
    }


def _resolve_report(rel: str) -> Path:
    p = (REPO_ROOT / rel).resolve()
    if not any(str(p).startswith(str(root)) for root in _ALLOWED_REPORT_ROOTS):
        raise HTTPException(403, "path outside the reports directory")
    if not p.exists():
        raise HTTPException(404, "no such report")
    return p


# --------------------------------------------------------------------------- #
# app
# --------------------------------------------------------------------------- #
def create_app() -> FastAPI:
    app = FastAPI(title="cpgvd", docs_url=None, redoc_url=None)

    @app.post("/api/scan")
    def start_scan(req: ScanRequest) -> dict:
        if not req.repo.strip():
            raise HTTPException(400, "repo is required")
        job_id = uuid.uuid4().hex[:12]
        out_dir = WEB_OUTPUT / f"{time.strftime('%Y%m%d-%H%M%S')}-{job_id}"
        out_dir.mkdir(parents=True, exist_ok=True)
        job = ScanJob(id=job_id, request=req, out_dir=out_dir)
        _JOBS[job_id] = job
        threading.Thread(target=_run_scan, args=(job,), daemon=True).start()
        return {"job_id": job_id}

    @app.get("/api/scan/{job_id}")
    def scan_status(job_id: str) -> dict:
        job = _JOBS.get(job_id)
        if not job:
            raise HTTPException(404, "unknown job")
        return job.snapshot()

    @app.get("/api/scan/{job_id}/stream")
    def scan_stream(job_id: str) -> StreamingResponse:
        job = _JOBS.get(job_id)
        if not job:
            raise HTTPException(404, "unknown job")

        def gen() -> Iterator[str]:
            sent = 0
            while True:
                for line in job.lines_from(sent):
                    yield f"data: {json.dumps({'line': line})}\n\n"
                    sent += 1
                if job.status != "running":
                    yield f"event: done\ndata: {json.dumps(job.snapshot())}\n\n"
                    return
                time.sleep(0.4)

        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.get("/api/scan/{job_id}/report")
    def scan_report(job_id: str) -> JSONResponse:
        job = _JOBS.get(job_id)
        if not job:
            raise HTTPException(404, "unknown job")
        rp = job.out_dir / "report.json"
        if not rp.exists():
            raise HTTPException(404, "no report yet")
        return JSONResponse(_read_json(rp))

    @app.get("/api/reports")
    def reports() -> list[dict]:
        return _list_reports()

    @app.get("/api/report")
    def report(path: str) -> JSONResponse:
        return JSONResponse(_read_json(_resolve_report(path)))

    @app.get("/api/benchmark")
    def benchmark() -> dict:
        return _benchmark()

    @app.get("/api/browse")
    def browse(path: str | None = None, hidden: bool = False) -> dict:
        return _browse(path, hidden)

    @app.get("/api/health")
    def health() -> dict:
        return {
            "joern": bool(shutil.which("joern-parse")),
            "ollama": _ollama_up(),
        }

    if WEB_DIR.exists():
        app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="web")

    return app


def _ollama_up() -> bool:
    try:
        import urllib.request

        urllib.request.urlopen("http://localhost:11434/api/tags", timeout=1).read()
        return True
    except Exception:  # noqa: BLE001
        return False


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    import uvicorn

    uvicorn.run(create_app(), host=host, port=port, log_level="warning")
