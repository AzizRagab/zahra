#!/usr/bin/env bash
# ZAHRA workspace — starts the LLM gateway (OmniRoute) and the pentest
# swarm backend (Pentest-Swarm-AI) as separate processes, wired together
# only over HTTP (OmniRoute's OpenAI-compatible endpoint). See
# services/pentest-swarm/config.example.yaml for the wiring.
#
# Usage: ./start-all.sh [--with-zahra] [--no-omniroute] [--no-swarm]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

WITH_ZAHRA=0
WITH_OMNIROUTE=1
WITH_SWARM=1
for arg in "$@"; do
    case "$arg" in
        --with-zahra) WITH_ZAHRA=1 ;;
        --no-omniroute) WITH_OMNIROUTE=0 ;;
        --no-swarm) WITH_SWARM=0 ;;
    esac
done

info()  { printf '\033[1;36m[*]\033[0m %s\n' "$1"; }
ok()    { printf '\033[1;32m[+]\033[0m %s\n' "$1"; }
warn()  { printf '\033[1;33m[!]\033[0m %s\n' "$1"; }
fail()  { printf '\033[1;31m[x]\033[0m %s\n' "$1"; exit 1; }

PIDS=()
cleanup() {
    for pid in "${PIDS[@]:-}"; do
        kill "$pid" >/dev/null 2>&1 || true
    done
}
trap cleanup EXIT INT TERM

wait_for_http() {
    local url="$1" name="$2" tries="${3:-30}"
    for _ in $(seq 1 "$tries"); do
        if curl -fsS -o /dev/null "$url" 2>/dev/null; then
            ok "$name is up ($url)"
            return 0
        fi
        sleep 1
    done
    warn "$name did not respond at $url within ${tries}s — check its logs"
    return 1
}

echo "============================================================"
echo "  ZAHRA workspace — OmniRoute (gateway) + Pentest-Swarm-AI"
echo "============================================================"

# ---- OmniRoute (LLM gateway, TypeScript/Node) ---------------------------
if [ "$WITH_OMNIROUTE" = "1" ]; then
    OR_DIR="$ROOT/services/omniroute"
    if [ ! -d "$OR_DIR/node_modules" ]; then
        warn "OmniRoute dependencies not installed yet."
        echo "    Run once:  cd services/omniroute && (pnpm install || npm install)"
        fail "Install OmniRoute deps first, then re-run this script."
    fi
    info "Starting OmniRoute on http://localhost:20128 ..."
    ( cd "$OR_DIR" && npm run start >"$ROOT/omniroute.log" 2>&1 ) &
    PIDS+=($!)
    wait_for_http "http://localhost:20128/v1" "OmniRoute" 40 || true
fi

# ---- Pentest-Swarm-AI (Go) -----------------------------------------------
if [ "$WITH_SWARM" = "1" ]; then
    PS_DIR="$ROOT/services/pentest-swarm"
    if [ ! -f "$PS_DIR/config.yaml" ]; then
        warn "services/pentest-swarm/config.yaml not found."
        echo "    Copy the example first: cp services/pentest-swarm/config.example.yaml services/pentest-swarm/config.yaml"
        echo "    Then edit the orchestrator section (OmniRoute profile is documented inline)."
        fail "Create config.yaml before starting the swarm backend."
    fi
    BIN="$PS_DIR/bin/pentestswarm"
    if [ ! -x "$BIN" ]; then
        info "Building pentestswarm (first run)..."
        ( cd "$PS_DIR" && go build -o bin/pentestswarm ./cmd/pentestswarm )
        ok "Built $BIN"
    fi
    info "Starting Pentest-Swarm-AI API on http://localhost:8080 ..."
    ( cd "$PS_DIR" && "$BIN" serve >"$ROOT/pentest-swarm.log" 2>&1 ) &
    PIDS+=($!)
    wait_for_http "http://localhost:8080/api/v1/health" "Pentest-Swarm-AI" 30 || true
fi

# ---- zahra (Python, optional) --------------------------------------------
if [ "$WITH_ZAHRA" = "1" ]; then
    info "Starting zahra on http://localhost:8090 ..."
    ( cd "$ROOT" && ./run.sh >"$ROOT/zahra.log" 2>&1 ) &
    PIDS+=($!)
    wait_for_http "http://localhost:8090/" "zahra" 30 || true
fi

echo
echo "============================================================"
ok "Workspace running. Logs: omniroute.log, pentest-swarm.log$( [ "$WITH_ZAHRA" = "1" ] && echo ', zahra.log' )"
echo "  OmniRoute gateway:    http://localhost:20128/v1"
echo "  Pentest-Swarm-AI API: http://localhost:8080"
[ "$WITH_ZAHRA" = "1" ] && echo "  zahra dashboard:      http://localhost:8090"
echo "  Ctrl+C stops everything this script started."
echo "============================================================"

wait
