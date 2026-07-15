#!/usr/bin/env bash
# Installs Ollama (https://ollama.com) and pulls the model cpgvd uses by
# default -- this is the free, local LLM backend, no API key required.
#
# Usage:
#   ./scripts/setup_ollama.sh [model]
#
# `model` defaults to qwen2.5-coder:7b (~4.7GB download, good code
# reasoning, runs fine on 8GB+ RAM).
#
# Recommended alternatives (see "Choosing a model" in README.md). The
# quality bottleneck for context judgment -- telling a hardcoded value
# from attacker-controlled input, understanding that a DAO delegates auth
# to its callers -- is the model, so a stronger one meaningfully cuts
# false positives:
#
#   Lighter than default (8GB RAM or less):
#     ./scripts/setup_ollama.sh qwen2.5-coder:3b
#     ./scripts/setup_ollama.sh llama3.2:3b
#
#   Better judgment (16GB+ RAM) -- recommended upgrade:
#     ./scripts/setup_ollama.sh qwen2.5-coder:14b   # safe drop-in, clearly better than 7b
#     ./scripts/setup_ollama.sh deepseek-coder-v2:16b # MoE, ~2.4B active -> near-7b speed, more knowledge
#     ./scripts/setup_ollama.sh gpt-oss:20b         # reasoning model, best at the exploitability call
#     ./scripts/setup_ollama.sh qwen3:14b           # reasoning + code, thinking mode
#
#   Strong GPU / 32GB+ RAM:
#     ./scripts/setup_ollama.sh qwen2.5-coder:32b   # near-frontier open coder
#     ./scripts/setup_ollama.sh qwen3:30b-a3b       # MoE, 30B total / 3B active -> fast for its size
#     ./scripts/setup_ollama.sh gpt-oss:120b        # needs ~64GB; strongest free reasoning here

set -euo pipefail

MODEL="${1:-qwen2.5-coder:7b}"

if ! command -v ollama >/dev/null 2>&1; then
  echo "Installing Ollama..."
  case "$(uname -s)" in
    Linux)
      curl -fsSL https://ollama.com/install.sh | sh
      ;;
    Darwin)
      echo "Download and install the macOS app from https://ollama.com/download,"
      echo "then re-run this script."
      exit 1
      ;;
    *)
      echo "Unsupported platform for this script. Install Ollama manually from"
      echo "https://ollama.com/download, then re-run this script."
      exit 1
      ;;
  esac
else
  echo "Ollama is already installed."
fi

# Start the server in the background if it isn't already running.
if ! curl -fsS http://localhost:11434/api/tags >/dev/null 2>&1; then
  echo "Starting Ollama server..."
  nohup ollama serve >/tmp/ollama-serve.log 2>&1 &
  for _ in $(seq 1 30); do
    curl -fsS http://localhost:11434/api/tags >/dev/null 2>&1 && break
    sleep 1
  done
fi

echo "Pulling model: ${MODEL} (this can take a few minutes the first time)"
ollama pull "${MODEL}"

echo
echo "Done. cpgvd defaults to CPGVD_OLLAMA_MODEL=qwen2.5-coder:7b."
if [ "${MODEL}" != "qwen2.5-coder:7b" ]; then
  echo "You pulled a different model -- set this before running cpgvd:"
  echo "  export CPGVD_OLLAMA_MODEL=\"${MODEL}\""
fi
echo "Verify with: ollama list"
