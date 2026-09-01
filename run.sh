#!/usr/bin/env bash
# ZAHRA — launch script for Kali/Ubuntu after install.sh has run once.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [ -d "$ROOT/.venv" ]; then
    # shellcheck disable=SC1091
    source "$ROOT/.venv/bin/activate"
fi

if command -v ollama >/dev/null 2>&1; then
    if ! pgrep -f "ollama serve" >/dev/null 2>&1; then
        (ollama serve >/tmp/zahra-ollama.log 2>&1 &) || true
        sleep 1
    fi
fi

export ZAHRA_LLM_BACKEND="${ZAHRA_LLM_BACKEND:-ollama}"
export ZAHRA_LLM_MODEL="${ZAHRA_LLM_MODEL:-zahra}"
export ZAHRA_LLM_BASE_URL="${ZAHRA_LLM_BASE_URL:-http://localhost:11434/v1}"

python main.py serve --port "${ZAHRA_PORT:-8090}" --host "${ZAHRA_HOST:-0.0.0.0}"
