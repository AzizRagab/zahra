#!/usr/bin/env bash
# ZAHRA — one-shot installer for Kali Linux / Ubuntu / Debian.
# Sets up the Python venv, installs deps, installs Ollama if missing,
# builds the "zahra" model from Modelfile.zahra, and prints how to launch.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

info()  { printf '\033[1;36m[*]\033[0m %s\n' "$1"; }
ok()    { printf '\033[1;32m[+]\033[0m %s\n' "$1"; }
warn()  { printf '\033[1;33m[!]\033[0m %s\n' "$1"; }
fail()  { printf '\033[1;31m[x]\033[0m %s\n' "$1"; exit 1; }

echo "============================================================"
echo "  ZAHRA — Agentic Pentest Platform — Linux Installer"
echo "============================================================"

# ---- Python -----------------------------------------------------------
PYBIN="$(command -v python3 || true)"
[ -n "$PYBIN" ] || fail "python3 not found. Install it: sudo apt install -y python3 python3-venv python3-pip"
ok "python3 found: $($PYBIN --version)"

# ---- venv ---------------------------------------------------------------
if [ ! -d "$ROOT/.venv" ]; then
    info "Creating virtual environment (.venv)..."
    "$PYBIN" -m venv "$ROOT/.venv"
fi
# shellcheck disable=SC1091
source "$ROOT/.venv/bin/activate"
ok "Virtual environment active"

info "Installing Python dependencies (this can take a few minutes)..."
pip install --upgrade pip >/dev/null
pip install -r requirements.txt
ok "Dependencies installed"

# ---- Ollama ---------------------------------------------------------------
if ! command -v ollama >/dev/null 2>&1; then
    warn "Ollama not found."
    read -r -p "Install Ollama now via the official install script? [Y/n] " ans
    ans=${ans:-Y}
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        curl -fsSL https://ollama.com/install.sh | sh
    else
        warn "Skipping Ollama install — ZAHRA will fall back to offline mode until it's installed."
    fi
fi

if command -v ollama >/dev/null 2>&1; then
    info "Starting Ollama service (background)..."
    (ollama serve >/tmp/zahra-ollama.log 2>&1 &) || true
    sleep 2

    info "Pulling base model (llama3.1:8b) referenced by Modelfile.zahra..."
    ollama pull llama3.1:8b || warn "Base model pull failed — check network/disk and retry: ollama pull llama3.1:8b"

    info "Building the 'zahra' model from Modelfile.zahra..."
    ollama create zahra -f "$ROOT/Modelfile.zahra"
    ok "Model 'zahra' ready (ollama list to verify)"
fi

# ---- data dirs ---------------------------------------------------------
mkdir -p "$ROOT/zahra_data"
ok "Data directory ready: $ROOT/zahra_data"

echo
echo "============================================================"
ok "Install complete."
echo "  Launch with:  ./run.sh"
echo "  Or manually:  source .venv/bin/activate && python main.py serve --port 8090"
echo "  Dashboard:    http://127.0.0.1:8090/"
echo "============================================================"
