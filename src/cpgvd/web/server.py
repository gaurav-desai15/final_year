"""HTTP API and single-page console for cpgvd.

One web app over both halves of the project: the scan reports `cpgvd analyze`
writes, and the archived benchmark runs `benchmark.run` produces. Launch with

    cpgvd web

The server is deliberately read-only over artifacts already on disk -- it
never invokes Joern, an LLM, or a benchmark run. That keeps it safe to leave
open during a long scan, and means it can be pointed at any past output
directory without side effects.

Paths arriving from the client are resolved against an allow-list of roots
(`--scan-dir`, `--results-dir`, plus the project tree) before anything is
read. A dashboard that will open any path the URL names is a file-disclosure
bug, and this one is intended to be run on a shared machine.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Iterable

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
STATIC_DIR = Path(__file__).resolve().parent / "static"

DEFAULT_SCAN_DIR = REPO_ROOT / "cpgvd_output"
DEFAULT_RESULTS_DIR = REPO_ROOT / "benchmark" / "results"


class ArtifactStore:
    """Locates and loads scan reports and benchmark runs, safely.

    Every public method takes untrusted input from the client, so resolution
    goes through `_within_roots` -- symlinks included, since `Path.resolve()`
    follows them and a symlink into /etc is exactly the trick this guards
    against.
    """

    def __init__(self, scan_dirs: Iterable[Path], results_dir: Path) -> None:
        self.scan_dirs = [Path(p).resolve() for p in scan_dirs]
        self.results_dir = Path(results_dir).resolve()
        self.roots = [*self.scan_dirs, self.results_dir]

    def _within_roots(self, candidate: Path) -> Path:
        resolved = Path(candidate).resolve()
        for root in self.roots:
            if resolved == root or root in resolved.parents:
                return resolved
        raise PermissionError(f"Path is outside the allowed roots: {candidate}")

    # -- scans -----------------------------------------------------------

    def list_scans(self) -> list[dict[str, Any]]:
        """Every report.json under the configured scan directories."""
        seen: set[Path] = set()
        scans: list[dict[str, Any]] = []
        for directory in self.scan_dirs:
            if not directory.exists():
                continue
            for path in sorted(directory.rglob("report.json")):
                resolved = path.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    logger.warning("Skipping unreadable scan report: %s", path)
                    continue
                scans.append({
                    "path": str(resolved),
                    "name": _scan_label(resolved, directory),
                    "repo": data.get("repo", "?"),
                    "model": data.get("model", ""),
                    "generated_at": data.get("generated_at", ""),
                    "findings": len(data.get("findings", [])),
                })
        scans.sort(key=lambda s: s.get("generated_at", ""), reverse=True)
        return scans

    def load_scan(self, path: str) -> dict[str, Any]:
        resolved = self._within_roots(Path(path))
        if not resolved.exists():
            raise FileNotFoundError(f"No scan report at {path}")
        return json.loads(resolved.read_text(encoding="utf-8"))

    # -- benchmark runs --------------------------------------------------

    def list_runs(self) -> list[dict[str, Any]]:
        if not self.results_dir.exists():
            return []
        runs = []
        for directory in sorted(self.results_dir.iterdir(), reverse=True):
            manifest = directory / "manifest.json"
            if not (directory / "run.json").exists() or not manifest.exists():
                continue
            try:
                meta = json.loads(manifest.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                logger.warning("Skipping unreadable run manifest: %s", manifest)
                continue
            runs.append({
                "run_id": meta.get("run_id", directory.name),
                "label": meta.get("label", ""),
                "created_at": meta.get("created_at", ""),
                "model": meta.get("model", ""),
                "runner": meta.get("runner", ""),
                "synthetic": bool(meta.get("synthetic")),
                "datasets": meta.get("datasets", []),
            })
        return runs

    def load_run(self, run_id: str) -> dict[str, Any]:
        # run_id is a directory name from the client; join then re-check
        # rather than trusting it not to contain traversal segments.
        directory = self._within_roots(self.results_dir / run_id)
        path = directory / "run.json"
        if not path.exists():
            raise FileNotFoundError(f"No archived run '{run_id}'")
        return json.loads(path.read_text(encoding="utf-8"))


def _scan_label(path: Path, root: Path) -> str:
    """A short human label for a scan: its containing directory."""
    try:
        relative = path.relative_to(root)
    except ValueError:
        return path.parent.name or path.name
    parent = relative.parent.as_posix()
    return root.name if parent in ("", ".") else parent


def build_app(
    scan_dirs: Iterable[Path] | None = None,
    results_dir: Path | None = None,
):
    """Construct the FastAPI application.

    Imported lazily inside the function so the module can be imported (and
    unit-tested) without FastAPI installed -- it's an optional extra.
    """
    try:
        from fastapi import FastAPI, HTTPException, Query
        from fastapi.responses import FileResponse, JSONResponse
        from fastapi.staticfiles import StaticFiles
    except ImportError as exc:  # pragma: no cover - exercised by the CLI path
        raise RuntimeError(
            'The web console needs FastAPI. Install it with: pip install -e ".[web]"'
        ) from exc

    store = ArtifactStore(
        scan_dirs or [DEFAULT_SCAN_DIR, REPO_ROOT],
        results_dir or DEFAULT_RESULTS_DIR,
    )

    app = FastAPI(
        title="cpgvd console",
        description="Scan reports and benchmark analysis for cpgvd.",
        version="0.1.0",
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )
    app.state.store = store

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "scan_dirs": [str(p) for p in store.scan_dirs],
            "results_dir": str(store.results_dir),
        }

    @app.get("/api/scans")
    def scans() -> list[dict[str, Any]]:
        return store.list_scans()

    @app.get("/api/scan")
    def scan(path: str = Query(..., description="Absolute path to a report.json")):
        try:
            return JSONResponse(store.load_scan(path))
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=422, detail=f"Malformed report: {exc}") from exc

    @app.get("/api/runs")
    def runs() -> list[dict[str, Any]]:
        return store.list_runs()

    @app.get("/api/run/{run_id}")
    def run(run_id: str):
        try:
            return JSONResponse(store.load_run(run_id))
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=422, detail=f"Malformed run: {exc}") from exc

    @app.get("/")
    def index():
        return FileResponse(STATIC_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app


def serve(
    host: str = "127.0.0.1",
    port: int = 8000,
    scan_dirs: Iterable[Path] | None = None,
    results_dir: Path | None = None,
    reload: bool = False,
) -> None:
    import uvicorn

    uvicorn.run(
        build_app(scan_dirs, results_dir),
        host=host,
        port=port,
        log_level="info",
        reload=reload,
    )
