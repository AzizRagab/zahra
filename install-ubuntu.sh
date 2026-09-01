#!/usr/bin/env bash
# ZAHRA workspace — full installer for Ubuntu (22.04/24.04).
# Installs all three services: zahra (Python), Pentest-Swarm-AI (Go),
# OmniRoute (Node/TypeScript). Each is a separate process — see
# start-all.sh to run them together.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

info()  { printf '\033[1;36m[*]\033[0m %s\n' "$1"; }
ok()    { printf '\033[1;32m[+]\033[0m %s\n' "$1"; }
warn()  { printf '\033[1;33m[!]\033[0m %s\n' "$1"; }
fail()  { printf '\033[1;31m[x]\033[0m %s\n' "$1"; exit 1; }

echo "============================================================"
echo "  ZAHRA workspace — Ubuntu full installer"
echo "  1) zahra (Python)  2) Pentest-Swarm-AI (Go)  3) OmniRoute (Node)"
echo "============================================================"

# ---- 1) zahra --------------------------------------------------------
info "[1/3] Installing zahra (Python)..."
if [ -x "$ROOT/install.sh" ]; then
    "$ROOT/install.sh"
else
    fail "install.sh not found at repo root"
fi

# ---- 2) Pentest-Swarm-AI ----------------------------------------------
info "[2/3] Installing Pentest-Swarm-AI (Go)..."
if [ -x "$ROOT/services/pentest-swarm/install-ubuntu.sh" ]; then
    "$ROOT/services/pentest-swarm/install-ubuntu.sh"
else
    fail "services/pentest-swarm/install-ubuntu.sh not found"
fi

# ---- 3) OmniRoute -------------------------------------------------------
info "[3/3] Installing OmniRoute (Node/TypeScript)..."
REQUIRED_NODE_MAJOR_MIN=22
NODE_OK=0
if command -v node >/dev/null 2>&1; then
    CUR_NODE_MAJOR="$(node -v | sed 's/^v//' | cut -d. -f1)"
    if [ "$CUR_NODE_MAJOR" -ge "$REQUIRED_NODE_MAJOR_MIN" ]; then
        NODE_OK=1
        ok "Node $(node -v) already installed"
    else
        warn "Node $(node -v) found but OmniRoute requires >=22.22.2 <23 or >=24"
    fi
fi

if [ "$NODE_OK" = "0" ]; then
    info "Installing Node 24.x via NodeSource..."
    curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash -
    sudo apt-get install -y nodejs
    ok "Node installed: $(node -v)"
fi

cd "$ROOT/services/omniroute"
if command -v pnpm >/dev/null 2>&1; then
    info "Installing OmniRoute dependencies with pnpm..."
    pnpm install
else
    warn "pnpm not found — falling back to npm (OmniRoute ships a pnpm-workspace.yaml; if npm install fails on workspace resolution, install pnpm: npm i -g pnpm)"
    npm install
fi
ok "OmniRoute dependencies installed"
cd "$ROOT"

echo
echo "============================================================"
ok "All three services installed."
echo "  Run everything:  ./start-all.sh --with-zahra"
echo "  Or individually — see each service's README."
echo "============================================================"
