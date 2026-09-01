#!/usr/bin/env pwsh
# ============================================================================
# ZAHRA — Master Launch Script (PowerShell)
# ============================================================================
# This script launches the complete ZAHRA platform with one click:
#   ✅ API Server (FastAPI) on port 8090
#   ✅ Dashboard Frontend (served by API)
#   ✅ SQLite Database (zahra_brain.db)
#   ✅ AI Agent + RAG Memory
#   ✅ ZahraController + Orchestrator + Swarm
#   ✅ WebSocket for live streaming
#   ✅ Auto-opens browser
# ============================================================================

param(
    [int]$Port = 8090,
    [string]$Host = "127.0.0.1",
    [switch]$NoBrowser,
    [switch]$Help
)

if ($Help) {
    Write-Host @"
ZAHRA - Master Launch Script

Usage: .\start_zahra.ps1 [-Port 8090] [-Host 127.0.0.1] [-NoBrowser]

Options:
  -Port       Port to bind the server (default: 8090)
  -Host       Host to bind (default: 127.0.0.1)
  -NoBrowser  Don't open browser automatically
  -Help       Show this help
"@
    exit 0
}

$ZAHRA_ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path

# ===== ANSI Colors =====
$RED = "`e[91m"
$GREEN = "`e[92m"
$YELLOW = "`e[93m"
$CYAN = "`e[96m"
$BOLD = "`e[1m"
$RESET = "`e[0m"

Write-Host @"
${CYAN}================================================================================
  ███████╗ █████╗ ██╗  ██╗██████╗  █████╗
  ╚══███╔╝██╔══██╗██║  ██║██╔══██╗██╔══██╗
    ███╔╝ ███████║███████║██████╔╝███████║
   ███╔╝  ██╔══██║██╔══██║██╔══██╗██╔══██║
  ███████╗██║  ██║██║  ██║██║  ██║██║  ██║
  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
================================================================================${RESET}
${GREEN}  AI-Powered Penetration Testing Swarm Platform${RESET}
  Version 2.0.0  |  Attribution: Amshararou
  Mode: Operator-Authorized  |  No LLaMA enforced
${CYAN}================================================================================${RESET}
"@

# ===== Step 1: Check Python =====
Write-Host "`n[.] Checking Python..." -ForegroundColor Yellow
try {
    $pyVersion = & python --version 2>&1
    Write-Host "[✓] $pyVersion" -ForegroundColor Green
} catch {
    Write-Host "[✗] Python not found! Please install Python 3.10+" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# ===== Step 2: Check/Install dependencies =====
Write-Host "[.] Checking dependencies..." -ForegroundColor Yellow
$depsCheck = & python -c "import fastapi, uvicorn, pydantic, requests, chromadb, websockets" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[.] Installing required packages..." -ForegroundColor Yellow
    & pip install -r "$ZAHRA_ROOT\requirements.txt" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[✗] Failed to install dependencies" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
    Write-Host "[✓] Dependencies installed" -ForegroundColor Green
} else {
    Write-Host "[✓] Dependencies ready" -ForegroundColor Green
}

# ===== Step 3: Ensure data directories =====
if (-not (Test-Path "$ZAHRA_ROOT\zahra_data")) {
    New-Item -ItemType Directory -Path "$ZAHRA_ROOT\zahra_data" -Force | Out-Null
}
Write-Host "[✓] Data directory ready" -ForegroundColor Green

# ===== Step 4: Check for Ollama model (optional) =====
Write-Host "[.] Checking for Ollama model (zahra:latest)..." -ForegroundColor Yellow
$ollamaCheck = & ollama list 2>&1 | Select-String "zahra"
if ($LASTEXITCODE -eq 0) {
    Write-Host "[✓] Found zahra:latest in Ollama" -ForegroundColor Green
    $env:ZAHRA_LLM_BACKEND = "ollama"
    $env:ZAHRA_LLM_MODEL = "zahra:latest"
    $env:ZAHRA_LLM_BASE_URL = "http://localhost:11434"
} else {
    Write-Host "[!] No Ollama model found. Using offline mode (RAG-only responses)." -ForegroundColor Yellow
    $env:ZAHRA_LLM_BACKEND = "offline"
}

# ===== Step 5: Set environment variables =====
$env:ZAHRA_UNRESTRICTED = "1"
$env:PYTHONPATH = "$ZAHRA_ROOT;$env:PYTHONPATH"

# ===== Step 6: Start Server =====
Write-Host @"
`n${CYAN}================================================================================${RESET}
${GREEN}  Starting ZAHRA Server on http://${Host}:${Port}${RESET}
  Dashboard:  http://127.0.0.1:${Port}/
  API:        http://127.0.0.1:${Port}/api/info
  Chat:       http://127.0.0.1:${Port}/api/chat
  WebSocket:  ws://127.0.0.1:${Port}/ws/attack
${CYAN}================================================================================${RESET}
"@

# Open browser after 3 seconds
if (-not $NoBrowser) {
    $scriptBlock = {
        Start-Sleep -Seconds 3
        Start-Process "http://127.0.0.1:$using:Port/"
    }
    Start-Job -ScriptBlock $scriptBlock | Out-Null
}

# Run the API server
try {
    & python "$ZAHRA_ROOT\interfaces\api_server.py" --host $Host --port $Port
} catch {
    Write-Host "[✗] Server error: $_" -ForegroundColor Red
}

Write-Host "`n[✗] Server stopped." -ForegroundColor Red
Read-Host "Press Enter to exit"