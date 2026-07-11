"""Wraps the `joern-parse` CLI and the `joern --server` CPGQL server process.

This module only shells out to Joern and manages its lifecycle. Query
construction and result parsing live in `cpg_client.py` /
`context_extractor.py` so this file stays a thin, testable process
wrapper.
"""

from __future__ import annotations

import logging
import shutil
import socket
import subprocess
import time
from pathlib import Path

from .config import Config

logger = logging.getLogger(__name__)

# Maps our internal language keys to joern-parse's `--language` frontend names.
# Passing an explicit frontend avoids relying on joern-parse's own (imperfect)
# auto-detection when a repo mixes languages.
_JOERN_FRONTEND = {
    "c": "C",
    "cpp": "NEWC",
    "java": "JAVA",
    "kotlin": "KOTLIN",
    "javascript": "JAVASCRIPT",
    "typescript": "JAVASCRIPT",
    "python": "PYTHONSRC",
    "go": "GOLANG",
    "csharp": "CSHARP",
    "php": "PHP",
    "ruby": "RUBYSRC",
    "swift": "SWIFTSRC",
}


class JoernNotFoundError(RuntimeError):
    pass


class JoernParseError(RuntimeError):
    pass


class JoernServerError(RuntimeError):
    pass


def check_joern_available(config: Config) -> None:
    for binary in ("joern-parse", "joern"):
        resolved = config.joern_binary(binary)
        if shutil.which(resolved) is None and not Path(resolved).exists():
            raise JoernNotFoundError(
                f"Could not find `{binary}` on PATH (or under JOERN_HOME). "
                "Install Joern first -- see scripts/setup_joern.sh."
            )


def parse_repo_to_cpg(
    repo_path: Path,
    cpg_out_path: Path,
    config: Config,
    *,
    language: str | None = None,
    timeout_s: float = 1800,
) -> Path:
    """Run `joern-parse` over `repo_path`, producing a CPG at `cpg_out_path`."""
    cpg_out_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [config.joern_binary("joern-parse"), str(repo_path), "-o", str(cpg_out_path)]

    frontend = _JOERN_FRONTEND.get((language or "").lower())
    if frontend:
        cmd += ["--language", frontend]

    logger.info("Running: %s", " ".join(cmd))
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )
    if proc.returncode != 0 or not cpg_out_path.exists():
        raise JoernParseError(
            f"joern-parse failed (exit {proc.returncode}).\n"
            f"stdout:\n{proc.stdout[-4000:]}\nstderr:\n{proc.stderr[-4000:]}"
        )
    return cpg_out_path


class JoernServer:
    """Manages a `joern --server` subprocess as a context manager.

    Usage::

        with JoernServer(config) as server:
            client = CpgClient(server.host, server.port)
            client.load_cpg(cpg_path)
            ...
    """

    def __init__(self, config: Config):
        self.config = config
        self.host = config.joern_server_host
        self.port = config.joern_server_port
        self._proc: subprocess.Popen | None = None

    def start(self) -> None:
        cmd = [
            self.config.joern_binary("joern"),
            "--server",
            "--server-host",
            self.host,
            "--server-port",
            str(self.port),
        ]
        logger.info("Starting Joern CPGQL server: %s", " ".join(cmd))
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self._wait_until_ready()

    def _wait_until_ready(self) -> None:
        deadline = time.monotonic() + self.config.joern_startup_timeout_s
        last_err: Exception | None = None
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                out = self._proc.stdout.read() if self._proc.stdout else ""
                raise JoernServerError(f"Joern server exited early:\n{out[-4000:]}")
            try:
                with socket.create_connection((self.host, self.port), timeout=1.0):
                    return
            except OSError as e:  # noqa: PERF203 - polling loop is intentional
                last_err = e
                time.sleep(1.0)
        raise JoernServerError(
            f"Timed out waiting for Joern server on {self.host}:{self.port}: {last_err}"
        )

    def stop(self) -> None:
        if self._proc is None:
            return
        logger.info("Stopping Joern CPGQL server")
        self._proc.terminate()
        try:
            self._proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self._proc.kill()
        self._proc = None

    def __enter__(self) -> "JoernServer":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()
