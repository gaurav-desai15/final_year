"""Runtime configuration, loaded from environment variables / .env."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

DEFAULT_MODEL = os.environ.get("CPGVD_MODEL", "claude-opus-4-8")
DEFAULT_JOERN_SERVER_HOST = "127.0.0.1"
DEFAULT_JOERN_SERVER_PORT = int(os.environ.get("CPGVD_JOERN_PORT", "8080"))

# "ollama" (default) is free and local -- no API key, no per-token cost.
# "anthropic" is paid and needs ANTHROPIC_API_KEY; opt in with --provider anthropic.
DEFAULT_LLM_PROVIDER = os.environ.get("CPGVD_LLM_PROVIDER", "ollama")
DEFAULT_OLLAMA_HOST = os.environ.get("CPGVD_OLLAMA_HOST", "http://localhost:11434")
DEFAULT_OLLAMA_MODEL = os.environ.get("CPGVD_OLLAMA_MODEL", "qwen2.5-coder:7b")


@dataclass
class Config:
    # Where cloned repos / generated CPGs / caches live.
    work_dir: Path = field(default_factory=lambda: Path(os.environ.get("CPGVD_WORK_DIR", ".cpgvd_cache")))

    # Joern
    joern_home: str | None = field(default_factory=lambda: os.environ.get("JOERN_HOME"))
    joern_server_host: str = DEFAULT_JOERN_SERVER_HOST
    joern_server_port: int = DEFAULT_JOERN_SERVER_PORT
    joern_startup_timeout_s: float = float(os.environ.get("CPGVD_JOERN_STARTUP_TIMEOUT", "120"))
    keep_cpg: bool = False

    # LLM
    llm_provider: str = DEFAULT_LLM_PROVIDER  # "ollama" (free, local) or "anthropic" (paid)
    model: str = DEFAULT_MODEL  # used when llm_provider == "anthropic"
    ollama_host: str = DEFAULT_OLLAMA_HOST
    ollama_model: str = DEFAULT_OLLAMA_MODEL
    ollama_timeout_s: float = float(os.environ.get("CPGVD_OLLAMA_TIMEOUT", "300"))
    max_context_chars: int = int(os.environ.get("CPGVD_MAX_CONTEXT_CHARS", "12000"))
    max_findings_per_context: int = 5
    llm_concurrency: int = int(os.environ.get("CPGVD_LLM_CONCURRENCY", "4"))
    effort: str = os.environ.get("CPGVD_EFFORT", "high")  # anthropic only

    # Analysis scope
    max_contexts: int = int(os.environ.get("CPGVD_MAX_CONTEXTS", "200"))
    caller_depth: int = 1
    callee_depth: int = 1
    max_related_functions: int = 5

    # Output
    output_dir: Path = field(default_factory=lambda: Path(os.environ.get("CPGVD_OUTPUT_DIR", "cpgvd_output")))

    def joern_binary(self, name: str) -> str:
        """Resolve a joern executable, preferring JOERN_HOME if set.

        Joern's own installer sometimes unpacks into a `joern-cli/`
        subdirectory of the install dir rather than putting binaries at
        its top level (varies by installer version) -- check both so
        JOERN_HOME works whichever layout the user actually has on disk.
        """
        if self.joern_home:
            for candidate in (
                Path(self.joern_home) / name,
                Path(self.joern_home) / "joern-cli" / name,
            ):
                if candidate.exists():
                    return str(candidate)
        return name  # fall back to PATH lookup
