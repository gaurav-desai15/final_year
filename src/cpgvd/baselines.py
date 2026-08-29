"""Rule-only baselines for the comparative evaluation (plan Section 0, axis 2).

`run_semgrep` runs Semgrep's unprotected-route rule over a repo and returns
findings in the same `Finding` shape the LLM detector produces, so the exact
same scoring in `evaluation.py` applies. No Joern, no LLM -- this is the
"a pattern match is not a vulnerability" straw man the thesis argues against.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

from .models import Confidence, Finding, Severity

logger = logging.getLogger(__name__)

_SEMGREP_RULES = Path(__file__).resolve().parent.parent.parent / "rules" / "semgrep" / "unprotected_route.yml"


def _semgrep_cmd() -> list[str] | None:
    """The `semgrep` executable: PATH first, then next to the running python
    (the venv's bin), then `python -m semgrep` as a last resort."""
    exe = shutil.which("semgrep")
    if exe:
        return [exe]
    venv_exe = Path(sys.executable).parent / "semgrep"
    if venv_exe.exists():
        return [str(venv_exe)]
    if importlib.util.find_spec("semgrep") is not None:
        return [sys.executable, "-m", "semgrep"]
    return None


def semgrep_available() -> bool:
    return _semgrep_cmd() is not None


def run_semgrep(repo_path: Path, rules: Path | None = None, timeout_s: float = 300) -> list[Finding]:
    rules = rules or _SEMGREP_RULES
    base = _semgrep_cmd()
    if base is None:
        logger.warning("semgrep not available")
        return []
    cmd = base + [
        "--metrics=off", "--quiet", "--json",
        "--config", str(rules), str(repo_path),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.warning("semgrep failed: %s", e)
        return []
    if not proc.stdout:
        logger.warning("semgrep produced no output (stderr: %s)", proc.stderr[-500:])
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        logger.warning("semgrep output not JSON: %s", proc.stdout[:500])
        return []

    repo_path = Path(repo_path)
    findings: list[Finding] = []
    for res in data.get("results", []):
        path = res.get("path", "")
        try:
            rel = str(Path(path).relative_to(repo_path))
        except ValueError:
            rel = path
        start = res.get("start", {}).get("line", 0) or 0
        end = res.get("end", {}).get("line", start) or start
        extra = res.get("extra", {})
        findings.append(
            Finding(
                id=str(uuid.uuid4()),
                context_id=f"semgrep:{rel}:{start}",
                file=rel,
                start_line=start,
                end_line=end,
                function="",
                vulnerability_type="Missing Access Control",
                cwe=(extra.get("metadata", {}) or {}).get("cwe", "CWE-862"),
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                title="Unprotected Express route (semgrep)",
                description=extra.get("message", "route registered with no middleware"),
                context_reasoning="pattern match only -- no context, no exploitability judgement",
                model="semgrep/" + _SEMGREP_RULES.stem,
            )
        )
    return findings
