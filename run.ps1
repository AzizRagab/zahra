# ZAHRA — launch script for Windows after install.ps1 has run once.
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

$venvPy = "$Root\.venv\Scripts\python.exe"
if (-not (Test-Path $venvPy)) { $venvPy = "python" }

if (Get-Command ollama -ErrorAction SilentlyContinue) {
    $running = Get-Process ollama -ErrorAction SilentlyContinue
    if (-not $running) {
        Start-Process -WindowStyle Hidden -FilePath "ollama" -ArgumentList "serve" -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
    }
}

if (-not $env:ZAHRA_LLM_BACKEND)  { $env:ZAHRA_LLM_BACKEND  = "ollama" }
if (-not $env:ZAHRA_LLM_MODEL)    { $env:ZAHRA_LLM_MODEL    = "zahra" }
if (-not $env:ZAHRA_LLM_BASE_URL) { $env:ZAHRA_LLM_BASE_URL = "http://localhost:11434/v1" }
$port = if ($env:ZAHRA_PORT) { $env:ZAHRA_PORT } else { "8090" }

Start-Process -FilePath "http://127.0.0.1:$port/" -ErrorAction SilentlyContinue | Out-Null
& $venvPy "$Root\main.py" serve --port $port --host 0.0.0.0
