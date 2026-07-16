from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import requests

from cpgvd.config import Config
from cpgvd.llm_providers import (
    AnthropicProvider,
    OllamaError,
    OllamaProvider,
    build_provider,
    check_ollama_available,
)

SCHEMA = {"type": "object", "properties": {"findings": {"type": "array"}}}


def test_build_provider_defaults_to_ollama():
    config = Config()
    assert config.llm_provider == "ollama"
    provider = build_provider(config)
    assert isinstance(provider, OllamaProvider)


def test_build_provider_unknown_raises():
    config = Config()
    config.llm_provider = "not-a-real-provider"
    with pytest.raises(ValueError):
        build_provider(config)


def test_ollama_provider_success():
    config = Config()
    config.ollama_host = "http://localhost:11434"
    config.ollama_model = "qwen2.5-coder:7b"

    fake_response = MagicMock()
    fake_response.raise_for_status.return_value = None
    fake_response.json.return_value = {
        "message": {"role": "assistant", "content": '{"findings": []}'},
        "prompt_eval_count": 500,
        "eval_count": 80,
    }
    fake_session = MagicMock()
    fake_session.post.return_value = fake_response

    provider = OllamaProvider(config, session=fake_session)
    result = provider.complete_json("system prompt", "user prompt", SCHEMA)

    assert result.text == '{"findings": []}'
    assert result.input_tokens == 500
    assert result.output_tokens == 80
    assert result.refused is False

    call_kwargs = fake_session.post.call_args.kwargs
    assert call_kwargs["json"]["model"] == "qwen2.5-coder:7b"
    assert call_kwargs["json"]["format"] == SCHEMA
    assert call_kwargs["json"]["stream"] is False


def test_ollama_provider_connection_error_raises_helpful_message():
    config = Config()
    fake_session = MagicMock()
    fake_session.post.side_effect = requests.exceptions.ConnectionError("refused")

    provider = OllamaProvider(config, session=fake_session)

    with pytest.raises(OllamaError, match="Could not reach Ollama"):
        provider.complete_json("s", "u", SCHEMA)


def test_ollama_provider_timeout_raises_actionable_message():
    """A read timeout means the server is up but the model was too slow --
    the error must say so and suggest raising the timeout / lowering
    concurrency / switching models, not send the user chasing a dead
    server (observed running gpt-oss:20b at concurrency 4 on CPU)."""
    config = Config()
    config.ollama_model = "gpt-oss:20b"
    fake_session = MagicMock()
    fake_session.post.side_effect = requests.exceptions.ReadTimeout("read timed out")

    provider = OllamaProvider(config, session=fake_session)

    with pytest.raises(OllamaError, match="timed out") as exc:
        provider.complete_json("s", "u", SCHEMA)
    msg = str(exc.value)
    assert "CPGVD_LLM_CONCURRENCY=1" in msg
    assert "CPGVD_OLLAMA_TIMEOUT" in msg


def test_check_ollama_available_raises_when_unreachable(monkeypatch):
    config = Config()

    def fake_get(*args, **kwargs):
        raise requests.exceptions.ConnectionError("refused")

    monkeypatch.setattr("cpgvd.llm_providers.requests.get", fake_get)

    with pytest.raises(OllamaError, match="Could not reach Ollama"):
        check_ollama_available(config)


def test_check_ollama_available_raises_when_model_not_pulled(monkeypatch):
    config = Config()
    config.ollama_model = "qwen2.5-coder:7b"

    fake_response = MagicMock()
    fake_response.raise_for_status.return_value = None
    fake_response.json.return_value = {"models": [{"name": "llama3.2:3b"}]}
    monkeypatch.setattr("cpgvd.llm_providers.requests.get", lambda *a, **k: fake_response)

    with pytest.raises(OllamaError, match="isn't pulled yet"):
        check_ollama_available(config)


def test_check_ollama_available_passes_when_model_present(monkeypatch):
    config = Config()
    config.ollama_model = "qwen2.5-coder:7b"

    fake_response = MagicMock()
    fake_response.raise_for_status.return_value = None
    fake_response.json.return_value = {"models": [{"name": "qwen2.5-coder:7b"}]}
    monkeypatch.setattr("cpgvd.llm_providers.requests.get", lambda *a, **k: fake_response)

    check_ollama_available(config)  # should not raise


def test_anthropic_provider_returns_text_and_usage():
    config = Config()
    config.llm_provider = "anthropic"
    config.model = "claude-opus-4-8"

    mock_client = MagicMock()
    mock_client.messages.create.return_value = SimpleNamespace(
        stop_reason="end_turn",
        content=[SimpleNamespace(type="text", text='{"findings": []}')],
        usage=SimpleNamespace(input_tokens=200, output_tokens=30),
    )

    provider = AnthropicProvider(config, client=mock_client)
    result = provider.complete_json("system", "user", SCHEMA)

    assert result.text == '{"findings": []}'
    assert result.input_tokens == 200
    assert result.output_tokens == 30
    assert result.refused is False

    create_kwargs = mock_client.messages.create.call_args.kwargs
    assert create_kwargs["model"] == "claude-opus-4-8"
    assert create_kwargs["output_config"]["format"]["schema"] == SCHEMA


def test_anthropic_provider_handles_refusal():
    config = Config()
    config.llm_provider = "anthropic"

    mock_client = MagicMock()
    mock_client.messages.create.return_value = SimpleNamespace(
        stop_reason="refusal",
        content=[],
        usage=SimpleNamespace(input_tokens=50, output_tokens=0),
    )

    provider = AnthropicProvider(config, client=mock_client)
    result = provider.complete_json("system", "user", SCHEMA)

    assert result.refused is True
    assert result.text == ""
