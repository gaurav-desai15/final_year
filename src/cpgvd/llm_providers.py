"""LLM backends for `llm_analyzer.py`.

Two providers, same interface (`BaseProvider.complete_json`):

- `OllamaProvider` -- talks to a local Ollama server (https://ollama.com).
  Free: no API key, no per-token billing, everything runs on your machine.
  This is the default provider.
- `AnthropicProvider` -- talks to the Claude API. Paid, but higher quality.
  Opt in with `--provider anthropic` (or `CPGVD_LLM_PROVIDER=anthropic`) plus
  `ANTHROPIC_API_KEY`.

`llm_analyzer.py` builds the system prompt / JSON schema once and doesn't
care which provider is behind `complete_json` -- swapping providers doesn't
change any of the finding-parsing logic.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

import requests

from .config import Config

logger = logging.getLogger(__name__)


class LlmProviderError(RuntimeError):
    pass


class OllamaError(LlmProviderError):
    pass


@dataclass
class LlmResult:
    text: str
    input_tokens: int = 0
    output_tokens: int = 0
    refused: bool = False


class BaseProvider(Protocol):
    def complete_json(self, system: str, user: str, schema: dict) -> LlmResult: ...


class OllamaProvider:
    """Free, local inference via Ollama's `/api/chat` endpoint.

    Requires `ollama serve` running and the configured model pulled --
    see `scripts/setup_ollama.sh`. Uses Ollama's structured-output support
    (`format: <json schema>`, available since Ollama 0.5) so the response
    is (usually) already valid JSON.
    """

    def __init__(self, config: Config, session: requests.Session | None = None):
        self.host = config.ollama_host.rstrip("/")
        self.model = config.ollama_model
        self.timeout = config.ollama_timeout_s
        self._session = session or requests

    def complete_json(self, system: str, user: str, schema: dict) -> LlmResult:
        try:
            resp = self._session.post(
                f"{self.host}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "format": schema,
                    "stream": False,
                    "options": {"temperature": 0},
                },
                timeout=self.timeout,
            )
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            raise OllamaError(
                f"Could not reach Ollama at {self.host} ({e}). Is it running? "
                f"Start it with `ollama serve` and make sure the model is pulled: "
                f"`ollama pull {self.model}`."
            ) from e

        data = resp.json()
        text = data.get("message", {}).get("content", "")
        return LlmResult(
            text=text,
            input_tokens=data.get("prompt_eval_count") or 0,
            output_tokens=data.get("eval_count") or 0,
            refused=False,
        )


class AnthropicProvider:
    """Paid, hosted inference via the Claude API. Requires `anthropic` and
    an `ANTHROPIC_API_KEY` (or an `ant auth login` profile)."""

    def __init__(self, config: Config, client=None):
        import anthropic  # local import: not needed at all for the free/Ollama path

        self.config = config
        self.client = client or anthropic.Anthropic()

    def complete_json(self, system: str, user: str, schema: dict) -> LlmResult:
        response = self.client.messages.create(
            model=self.config.model,
            max_tokens=4096,
            system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            thinking={"type": "adaptive"},
            output_config={"effort": self.config.effort, "format": {"type": "json_schema", "schema": schema}},
            messages=[{"role": "user", "content": user}],
        )

        refused = response.stop_reason == "refusal"
        text = "" if refused else next((b.text for b in response.content if b.type == "text"), "")

        return LlmResult(
            text=text,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            refused=refused,
        )


def build_provider(config: Config) -> BaseProvider:
    if config.llm_provider == "ollama":
        return OllamaProvider(config)
    if config.llm_provider == "anthropic":
        return AnthropicProvider(config)
    raise ValueError(f"Unknown LLM provider {config.llm_provider!r}; expected 'ollama' or 'anthropic'")


def check_ollama_available(config: Config) -> None:
    """Fail fast (before doing any Joern work) if Ollama isn't reachable or
    the configured model hasn't been pulled yet."""
    host = config.ollama_host.rstrip("/")
    try:
        resp = requests.get(f"{host}/api/tags", timeout=5)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise OllamaError(
            f"Could not reach Ollama at {host} ({e}). Install and start it first -- "
            "see scripts/setup_ollama.sh -- or run `ollama serve`."
        ) from e

    pulled = {m.get("name", "").split(":")[0] for m in resp.json().get("models", [])}
    wanted = config.ollama_model.split(":")[0]
    if wanted not in pulled:
        raise OllamaError(
            f"Ollama is running but '{config.ollama_model}' isn't pulled yet. Run: "
            f"ollama pull {config.ollama_model}"
        )
