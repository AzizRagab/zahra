#!/usr/bin/env python3
"""ZAHRA — Unified Launcher & Integration Hub.

This module wires together every subsystem of the ZAHRA platform:
  * Backend (FastAPI server)
  * Frontend (Dashboard)
  * Database (SQLite)
  * AI Agent + RAG Memory
  * ZahraController + Orchestrator + Swarm
  * WebSocket live streaming
  * Ollama model (zahra:latest) integration

Usage:
    python launcher.py                # Start everything on port 8090
    python launcher.py --port 9000    # Custom port
    python launcher.py --no-browser   # Don't open browser
    python launcher.py --check        # Health check only
"""

from __future__ import annotations

import sys
import io

# Force UTF-8 output on Windows (fixes UnicodeEncodeError with ✓/✗)
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr.encoding and sys.stderr.encoding.lower() != "utf-8":
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import argparse
import json
import logging
import os
import subprocess
import threading
import webbrowser
from pathlib import Path
from typing import Any, Dict

# Ensure project root is on path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("zahra.launcher")

# ── Constants ────────────────────────────────────────────────────────────────

DEFAULT_PORT = 8090
DEFAULT_HOST = "127.0.0.1"
OLLAMA_URL = os.environ.get("ZAHRA_OLLAMA_URL", "http://localhost:11434")
ZAHRA_MODEL = os.environ.get("ZAHRA_MODEL", "zahra:latest")


# ── Health checks ────────────────────────────────────────────────────────────

def check_ollama() -> Dict[str, Any]:
    """Check if Ollama is running and the zahra model is available."""
    import urllib.request

    result: Dict[str, Any] = {"available": False, "model": ZAHRA_MODEL, "error": ""}
    try:
        req = urllib.request.Request(
            f"{OLLAMA_URL}/api/tags",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        models = [m.get("name", "") for m in data.get("models", [])]
        result["available"] = any(ZAHRA_MODEL in m for m in models)
        result["models"] = models
        if not result["available"]:
            result["error"] = f"Model '{ZAHRA_MODEL}' not found in Ollama"
    except Exception as exc:
        result["error"] = str(exc)
    return result


def check_database() -> Dict[str, Any]:
    """Check the SQLite database status."""
    result: Dict[str, Any] = {"available": False, "path": "", "tables": []}
    try:
        import sqlite3
        db_path = ROOT / "zahra_brain.db"
        result["path"] = str(db_path)
        if db_path.exists():
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            result["tables"] = [r[0] for r in cursor.fetchall()]
            conn.close()
            result["available"] = True
    except Exception as exc:
        result["error"] = str(exc)
    return result


def check_dependencies() -> Dict[str, Any]:
    """Check that all required Python packages are installed."""
    required = ["fastapi", "uvicorn", "pydantic", "requests", "chromadb", "websockets"]
    result: Dict[str, Any] = {"available": True, "missing": []}
    for pkg in required:
        try:
            __import__(pkg)
        except ImportError:
            result["available"] = False
            result["missing"].append(pkg)
    return result


# ── System status ────────────────────────────────────────────────────────────

def get_system_status() -> Dict[str, Any]:
    """Get a comprehensive status of all subsystems."""
    return {
        "name": "ZAHRA",
        "version": "2.0.0",
        "attribution": "Amshararou",
        "mode": "authorized",
        "status": "ready",
        "components": {
            "ollama": check_ollama(),
            "database": check_database(),
            "dependencies": check_dependencies(),
        },
        "paths": {
            "root": str(ROOT),
            "database": str(ROOT / "zahra_brain.db"),
            "reports": str(ROOT / "reports"),
            "wordlists": str(ROOT / "wordlists"),
            "model": str(ROOT / "zahra_model"),
        },
    }


# ── Main launcher ────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="ZAHRA — Unified Launcher & Integration Hub",
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help="Host to bind")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to bind")
    parser.add_argument("--no-browser", action="store_true", help="Don't open browser")
    parser.add_argument("--check", action="store_true", help="Run health check only")
    parser.add_argument("--no-platform", action="store_true",
                        help="Run with only the chat brain (skip full platform)")
    args = parser.parse_args()

    # ── Health check mode ────────────────────────────────────────────────
    if args.check:
        status = get_system_status()
        print(json.dumps(status, indent=2, ensure_ascii=False))
        return 0

    # ── Print banner ─────────────────────────────────────────────────────
    print("=" * 70)
    print("  ZAHRA — AI-Powered Penetration Testing Swarm Platform")
    print("  Version 2.0.0  |  Attribution: Amshararou")
    print("  Mode: Operator-Authorized  |  No LLaMA enforced")
    print("=" * 70)
    print()

    # ── Check dependencies ───────────────────────────────────────────────
    deps = check_dependencies()
    if not deps["available"]:
        print(f"[!] Missing packages: {', '.join(deps['missing'])}")
        print("[.] Installing dependencies...")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", str(ROOT / "requirements.txt")],
            check=False,
        )
        deps = check_dependencies()
        if not deps["available"]:
            print("[✗] Failed to install dependencies")
            return 1
    print("[✓] Dependencies ready")

    # ── Check Ollama ─────────────────────────────────────────────────────
    ollama = check_ollama()
    if ollama["available"]:
        print(f"[✓] Ollama model '{ZAHRA_MODEL}' available")
        os.environ["ZAHRA_LLM_BACKEND"] = "ollama"
        os.environ["ZAHRA_LLM_MODEL"] = ZAHRA_MODEL
        os.environ["ZAHRA_LLM_BASE_URL"] = OLLAMA_URL
    else:
        print(f"[!] Ollama model '{ZAHRA_MODEL}' not available: {ollama.get('error', '')}")
        print("[!] Using offline mode (RAG-only responses)")
        os.environ["ZAHRA_LLM_BACKEND"] = "offline"

    # ── Check database ───────────────────────────────────────────────────
    db = check_database()
    if db["available"]:
        print(f"[✓] Database ready: {len(db['tables'])} tables")
    else:
        print("[.] Database will be created on first run")

    # ── Set environment ──────────────────────────────────────────────────
    os.environ["ZAHRA_UNRESTRICTED"] = "1"
    os.environ["PYTHONPATH"] = f"{ROOT};{os.environ.get('PYTHONPATH', '')}"

    # ── Open browser after delay ─────────────────────────────────────────
    if not args.no_browser:
        url = f"http://{args.host}:{args.port}/"
        threading.Timer(3.0, lambda: webbrowser.open(url)).start()

    # ── Start the API server ─────────────────────────────────────────────
    print()
    print("=" * 70)
    print(f"  Starting ZAHRA Server on http://{args.host}:{args.port}")
    print(f"  Dashboard:  http://127.0.0.1:{args.port}/")
    print(f"  API:        http://127.0.0.1:{args.port}/api/info")
    print(f"  Chat:       http://127.0.0.1:{args.port}/api/chat")
    print(f"  WebSocket:  ws://127.0.0.1:{args.port}/ws/attack")
    print("=" * 70)
    print()
    print("  Press Ctrl+C to stop the server")
    print()

    # Import and run the API server
    from interfaces.api_server import run_api_server

    if args.no_platform:
        run_api_server(host=args.host, port=args.port)
        return 0

    # Build the full platform
    from main import build_platform
    from interfaces.api_server import setup_api

    print("[ZAHRA] Building full platform (controller, swarm, RAG, brain)...")
    cli = build_platform()

    setup_api(
        orchestrator_instance=cli.orch,
        agentic_core_instance=cli.controller.agentic_core,
        blackboard_instance=cli.controller.blackboard,
        event_emitter_instance=cli.controller.event_emitter,
        database_instance=cli.controller.database,
        ai_agent_instance=cli.controller.ai_agent,
        controller_instance=cli.controller,
    )
    print(f"[ZAHRA] Platform ready — serving dashboard on http://{args.host}:{args.port}")
    run_api_server(host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())