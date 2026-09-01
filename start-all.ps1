# ZAHRA workspace — starts the LLM gateway (OmniRoute) and the pentest
# swarm backend (Pentest-Swarm-AI) as separate processes, wired together
# only over HTTP (OmniRoute's OpenAI-compatible endpoint). See
# services/pentest-swarm/config.example.yaml for the wiring.
#
# Usage: .\start-all.ps1 [-WithZahra] [-NoOmniRoute] [-NoSwarm]
param(
    [switch]$WithZahra,
    [switch]$NoOmniRoute,
    [switch]$NoSwarm
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

function Info($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }
function Fail($m) { Write-Host "[x] $m" -ForegroundColor Red; exit 1 }

$Jobs = @()
function Wait-ForHttp($Url, $Name, $Tries = 30) {
    for ($i = 0; $i -lt $Tries; $i++) {
        try {
            Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 2 | Out-Null
            Ok "$Name is up ($Url)"
            return $true
        } catch { Start-Sleep -Seconds 1 }
    }
    Warn "$Name did not respond at $Url within ${Tries}s - check its log"
    return $false
}

Write-Host "============================================================"
Write-Host "  ZAHRA workspace - OmniRoute (gateway) + Pentest-Swarm-AI"
Write-Host "============================================================"

# ---- OmniRoute (LLM gateway, TypeScript/Node) ----------------------------
if (-not $NoOmniRoute) {
    $OrDir = "$Root\services\omniroute"
    if (-not (Test-Path "$OrDir\node_modules")) {
        Warn "OmniRoute dependencies not installed yet."
        Write-Host "    Run once:  cd services\omniroute; pnpm install (or npm install)"
        Fail "Install OmniRoute deps first, then re-run this script."
    }
    Info "Starting OmniRoute on http://localhost:20128 ..."
    $Jobs += Start-Process -FilePath "npm" -ArgumentList "run","start" -WorkingDirectory $OrDir `
        -RedirectStandardOutput "$Root\omniroute.log" -RedirectStandardError "$Root\omniroute.err.log" `
        -PassThru -WindowStyle Hidden
    Wait-ForHttp "http://localhost:20128/v1" "OmniRoute" 40 | Out-Null
}

# ---- Pentest-Swarm-AI (Go) ------------------------------------------------
if (-not $NoSwarm) {
    $PsDir = "$Root\services\pentest-swarm"
    if (-not (Test-Path "$PsDir\config.yaml")) {
        Warn "services\pentest-swarm\config.yaml not found."
        Write-Host "    Copy the example first: copy services\pentest-swarm\config.example.yaml services\pentest-swarm\config.yaml"
        Write-Host "    Then edit the orchestrator section (OmniRoute profile is documented inline)."
        Fail "Create config.yaml before starting the swarm backend."
    }
    $Bin = "$PsDir\bin\pentestswarm.exe"
    if (-not (Test-Path $Bin)) {
        Info "Building pentestswarm (first run)..."
        Push-Location $PsDir
        go build -o bin\pentestswarm.exe .\cmd\pentestswarm
        Pop-Location
        Ok "Built $Bin"
    }
    Info "Starting Pentest-Swarm-AI API on http://localhost:8080 ..."
    $Jobs += Start-Process -FilePath $Bin -ArgumentList "serve" -WorkingDirectory $PsDir `
        -RedirectStandardOutput "$Root\pentest-swarm.log" -RedirectStandardError "$Root\pentest-swarm.err.log" `
        -PassThru -WindowStyle Hidden
    Wait-ForHttp "http://localhost:8080/api/v1/health" "Pentest-Swarm-AI" 30 | Out-Null
}

# ---- zahra (Python, optional) ---------------------------------------------
if ($WithZahra) {
    Info "Starting zahra on http://localhost:8090 ..."
    $Jobs += Start-Process -FilePath "powershell" -ArgumentList "-File",".\run.ps1" -WorkingDirectory $Root `
        -RedirectStandardOutput "$Root\zahra.log" -RedirectStandardError "$Root\zahra.err.log" `
        -PassThru -WindowStyle Hidden
    Wait-ForHttp "http://localhost:8090/" "zahra" 30 | Out-Null
}

Write-Host ""
Write-Host "============================================================"
Ok "Workspace running. Logs: omniroute.log, pentest-swarm.log$(if ($WithZahra) { ', zahra.log' })"
Write-Host "  OmniRoute gateway:    http://localhost:20128/v1"
Write-Host "  Pentest-Swarm-AI API: http://localhost:8080"
if ($WithZahra) { Write-Host "  zahra dashboard:      http://localhost:8090" }
Write-Host "  Press Ctrl+C to stop; running processes are listed below (Stop-Process -Id <pid> to kill manually)."
Write-Host "============================================================"
$Jobs | ForEach-Object { Write-Host "  PID $($_.Id): $($_.ProcessName)" }

try {
    Wait-Process -Id ($Jobs | ForEach-Object { $_.Id })
} finally {
    foreach ($j in $Jobs) {
        try { Stop-Process -Id $j.Id -Force -ErrorAction SilentlyContinue } catch {}
    }
}
