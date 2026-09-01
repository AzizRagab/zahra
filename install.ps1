# ZAHRA — one-shot installer for Windows (PowerShell 7+).
# Sets up the venv, installs deps, installs/starts Ollama if missing,
# builds the "zahra" model from Modelfile.zahra.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

function Info($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }
function Fail($m) { Write-Host "[x] $m" -ForegroundColor Red; exit 1 }

Write-Host "============================================================"
Write-Host "  ZAHRA - Agentic Pentest Platform - Windows Installer"
Write-Host "============================================================"

# ---- Python ----------------------------------------------------------
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { Fail "python not found. Install Python 3.10+ from https://python.org and re-run." }
Ok "python found: $(python --version)"

# ---- venv --------------------------------------------------------------
if (-not (Test-Path "$Root\.venv")) {
    Info "Creating virtual environment (.venv)..."
    python -m venv "$Root\.venv"
}
$venvPy = "$Root\.venv\Scripts\python.exe"
Ok "Virtual environment ready"

Info "Installing Python dependencies (this can take a few minutes)..."
& $venvPy -m pip install --upgrade pip | Out-Null
& $venvPy -m pip install -r requirements.txt
Ok "Dependencies installed"

# ---- Ollama --------------------------------------------------------------
$ollama = Get-Command ollama -ErrorAction SilentlyContinue
if (-not $ollama) {
    Warn "Ollama not found."
    $ans = Read-Host "Download and install Ollama for Windows now? [Y/n]"
    if ($ans -eq "" -or $ans -match "^[Yy]") {
        Info "Opening Ollama download page (winget fallback if available)..."
        $winget = Get-Command winget -ErrorAction SilentlyContinue
        if ($winget) {
            winget install -e --id Ollama.Ollama
        } else {
            Start-Process "https://ollama.com/download/windows"
            Warn "Install Ollama from the opened page, then re-run this script."
        }
    } else {
        Warn "Skipping Ollama install - ZAHRA will fall back to offline mode until it's installed."
    }
    $ollama = Get-Command ollama -ErrorAction SilentlyContinue
}

if ($ollama) {
    Info "Ensuring Ollama service is running..."
    Start-Process -WindowStyle Hidden -FilePath "ollama" -ArgumentList "serve" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    Info "Pulling base model (llama3.1:8b) referenced by Modelfile.zahra..."
    try { ollama pull llama3.1:8b } catch { Warn "Base model pull failed - retry manually: ollama pull llama3.1:8b" }

    Info "Building the 'zahra' model from Modelfile.zahra..."
    ollama create zahra -f "$Root\Modelfile.zahra"
    Ok "Model 'zahra' ready (run 'ollama list' to verify)"
}

New-Item -ItemType Directory -Force -Path "$Root\zahra_data" | Out-Null
Ok "Data directory ready: $Root\zahra_data"

Write-Host ""
Write-Host "============================================================"
Ok "Install complete."
Write-Host "  Launch with:  .\run.ps1"
Write-Host "  Dashboard:    http://127.0.0.1:8090/"
Write-Host "============================================================"
