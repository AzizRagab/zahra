@echo off
title ZAHRA - AI Pentest Swarm Platform
cd /d "%~dp0"

:: ============================================================================
:: ZAHRA — Master Launch Script (زر واحد شغال كل حاجة)
:: ============================================================================
:: This script launches the complete ZAHRA platform:
::   ✅ API Server (FastAPI) on port 8090
::   ✅ Dashboard Frontend (served by API)
::   ✅ SQLite Database
::   ✅ AI Agent + RAG Memory
::   ✅ ZahraController + Orchestrator
::   ✅ Swarm Manager + All Agents
::   ✅ WebSocket for live streaming
::   ✅ Automatically opens browser
:: ============================================================================

set "ZAHRA_ROOT=%~dp0"
set "ZAHRA_PORT=8090"
set "ZAHRA_HOST=127.0.0.1"

echo ============================================================================
echo   ███████╗ █████╗ ██╗  ██╗██████╗  █████╗
echo   ╚══███╔╝██╔══██╗██║  ██║██╔══██╗██╔══██╗
echo     ███╔╝ ███████║███████║██████╔╝███████║
echo    ███╔╝  ██╔══██║██╔══██║██╔══██╗██╔══██║
echo   ███████╗██║  ██║██║  ██║██║  ██║██║  ██║
echo   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
echo ============================================================================
echo   AI-Powered Penetration Testing Swarm Platform
echo   Version 2.0.0  |  Attribution: Amshararou
echo   Mode: UNRESTRICTED  |  No LLaMA enforced
echo ============================================================================
echo.
echo [✓] Starting ZAHRA Platform...
echo.

:: ===== Step 1: Set Python path =====
set "PYTHONPATH=%ZAHRA_ROOT%;%PYTHONPATH%"

:: ===== Step 2: Check Python =====
where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [✗] Python not found! Please install Python 3.10+
    pause
    exit /b 1
)
echo [✓] Python found: 
python --version

:: ===== Step 3: Check/Install dependencies =====
echo [.] Checking dependencies...
python -c "import fastapi, uvicorn, pydantic, requests, chromadb" 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [.] Installing required packages...
    pip install -r "%ZAHRA_ROOT%requirements.txt"
    if %ERRORLEVEL% NEQ 0 (
        echo [✗] Failed to install dependencies
        pause
        exit /b 1
    )
    echo [✓] Dependencies installed
) else (
    echo [✓] Dependencies ready
)

:: ===== Step 4: Ensure data directories =====
if not exist "%ZAHRA_ROOT%zahra_data" mkdir "%ZAHRA_ROOT%zahra_data"
echo [✓] Data directory ready

:: ===== Step 5: Start API Server =====
echo.
echo ============================================================================
echo   Starting ZAHRA Server on http://%ZAHRA_HOST%:%ZAHRA_PORT%
echo   Dashboard:  http://127.0.0.1:%ZAHRA_PORT%/
echo   API:        http://127.0.0.1:%ZAHRA_PORT%/api/info
echo   Chat:       http://127.0.0.1:%ZAHRA_PORT%/api/chat
echo   WebSocket:  ws://127.0.0.1:%ZAHRA_PORT%/ws/attack
echo ============================================================================
echo.
echo   Press Ctrl+C to stop the server
echo.

:: Open browser after a short delay
start /b "" cmd /c "timeout /t 3 /nobreak >nul && start http://127.0.0.1:%ZAHRA_PORT%/"

:: Run the API server
python "%ZAHRA_ROOT%interfaces\api_server.py" --host %ZAHRA_HOST% --port %ZAHRA_PORT%

:: If server exits, pause
echo.
echo [✗] Server stopped.
pause