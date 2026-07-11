#!/usr/bin/env bash
# Installs Ollama (https://ollama.com) and pulls the model cpgvd uses by
# default -- this is the free, local LLM backend, no API key required.
#
# Usage:
#   ./scripts/setup_ollama.sh [model]
#
# `model` defaults to qwen2.5-coder:7b (~4.7GB download, good code
# reasoning, runs fine on 8GB+ RAM). For lower-end hardware, pass a smaller
# tag, e.g.:
#   ./scripts/setup_ollama.sh qwen2.5-coder:1.5b
#   ./scripts/setup_ollama.sh llama3.2:3b

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
