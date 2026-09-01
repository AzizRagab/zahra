#!/usr/bin/env python3
"""zahra — Adaptive RAG Pentest System entry point.

This is the main entry point for the zahra platform. It wires together
the LLM wrapper, swarm manager, orchestrator, and CLI/API interfaces.

The platform features an Adaptive RAG system (a growing brain) that:
* Stores every finding, command, and evasion technique in a vector DB
* Lets agents query past experience before planning new actions
* Supports web search / OSINT for CVE discovery
* Applies intelligent, RAG-driven evasion tuning

Usage:
    python main.py recon example.com
    python main.py scan 192.168.1.1
    python main.py exploit https://target.com
    python main.py full pentest example.com
    python main.py status
    python main.py serve --port 8000

Environment variables:
    ZAHRA_LLM_BACKEND   - openwebui, huggingface, ollama, openai, offline
    ZAHRA_LLM_BASE_URL  - Base URL of the LLM API
    ZAHRA_LLM_API_KEY   - API key
    ZAHRA_LLM_MODEL     - Model name
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

# Ensure the project root is on the path
sys.path.insert(0, str(Path(__file__).parent))

from agents.skills import register_skill
from agents.skills.proxy import ProxySkill
from agents.skills.reporting import ReportingSkill
from agents.skills.web_search import WebSearchSkill
from core.zahra_config import ZahraConfig
from core.zahra_controller import ZahraController
from interfaces.cli import CLI, print_banner
from zahra_agent import ZahraAgent

logger = logging.getLogger("zahra")


def build_platform() -> CLI:
    """Build the complete zahra platform with the ZahraController.

    The ZahraController is the personal, operator-directed controller model
    that owns and coordinates every subsystem:

    1. **LLM Wrapper** (non-LLaMA — Mistral, Gemma, Phi, Qwen, etc.)
    2. **Blackboard** (stigmergic coordination with pheromones)
    3. **Event Emitter** (structured observability)
    4. **Agentic Core** (strategic brain, phase management)
    5. **Skills** (web_search, reporting, proxy)
    6. **Swarm Manager** (Recon, Scan, Exploit, C2, MITM agents)
    7. **Router** (LLM-assisted intent classification)
    8. **Memory Store** (persistent + RAG via ChromaDB)
    9. **Database** (SQLite persistence)
    10. **Orchestrator** (campaign management and execution)
    11. **AI Agent** (ReAct thinking brain with RAG + web search)
    12. **CLI interface**

    All of the above are created internally by the ZahraController.
    The controller enforces:
    * **No LLaMA** — model validation at startup and runtime
    * **Authorized-only operation** — designed for engagements the operator
      has authorized; scope and legality remain the operator's responsibility
    * **Named "zahra"** — attributed to Amshararou
    """
    # Create the ZahraController from environment / config file
    config = ZahraConfig.from_env()
    controller = ZahraController(config)

    # Start the controller (activates agentic core)
    controller.start()

    # Register skills on the controller's swarm
    register_skill(WebSearchSkill())
    register_skill(ReportingSkill())
    register_skill(ProxySkill())
    logger.info("Registered skills: web_search, reporting, proxy")

    # Create the safe ZahraAgent master brain (human-in-the-loop)
    brain = ZahraAgent()

    # Create CLI with the controller's orchestrator, controller, and safe brain
    cli = CLI(
        orchestrator=controller.orchestrator,
        controller=controller,
        brain=brain,
    )

    logger.info("=" * 60)
    logger.info("ZAHRA - Agentic Pentest System Initialized")
    logger.info("=" * 60)
    logger.info("Controller: %s v%s (attribution: %s)", controller.name, controller.version, controller.attribution)
    logger.info("Mode: %s", controller.mode)
    logger.info("LLM Backend: %s", controller.llm.config.backend)
    logger.info("Model: %s (non-LLaMA enforced)", controller.llm.config.model or "offline")
    logger.info("Features: Skills ✓, Blackboard ✓, Events ✓, RAG ✓, Agentic Core ✓, AI Agent ✓")
    logger.info("=" * 60)
    return cli


def main() -> int:
    """Main entry point."""
    print_banner()
    
    # Check if we should run the API server
    if len(sys.argv) > 1 and sys.argv[1] == "serve":
        # Run API server
        from interfaces.api_server import run_api_server
        import argparse
        
        parser = argparse.ArgumentParser(description="Start the ZAHRA web dashboard server")
        parser.add_argument("--host", default="0.0.0.0", help="Host to bind to (default: 0.0.0.0)")
        parser.add_argument("--port", type=int, default=8080, help="Port to bind to (default: 8080)")
        parser.add_argument("--tunnel", action="store_true", help="Expose the dashboard to the internet via cloudflared/ngrok")
        args = parser.parse_args(sys.argv[2:])
        
        # Build platform in a background thread so the server can start
        import threading
        cli = build_platform()
        
        # Setup API with platform components from the ZahraController
        from interfaces.api_server import setup_api, run_api_server
        setup_api(
            orchestrator_instance=cli.orch,
            agentic_core_instance=cli.controller.agentic_core,
            blackboard_instance=cli.controller.blackboard,
            event_emitter_instance=cli.controller.event_emitter,
            database_instance=cli.controller.database,
            ai_agent_instance=cli.controller.ai_agent,
            controller_instance=cli.controller,
        )
        
        logger.info("Starting API server on %s:%d", args.host, args.port)
        
        # Start tunnel if requested
        if args.tunnel:
            _start_tunnel(args.port)
        
        run_api_server(host=args.host, port=args.port)
        return 0
    
    # Check for tunnel-only command
    if len(sys.argv) > 1 and sys.argv[1] == "tunnel":
        import argparse
        parser = argparse.ArgumentParser(description="Expose ZAHRA dashboard to the internet")
        parser.add_argument("--port", type=int, default=8080, help="Port to tunnel (default: 8080)")
        parser.add_argument("--host", default="0.0.0.0", help="Host to bind to (default: 0.0.0.0)")
        args = parser.parse_args(sys.argv[2:])
        
        # Build platform
        cli = build_platform()
        
        # Setup API
        from interfaces.api_server import setup_api, run_api_server
        setup_api(
            orchestrator_instance=cli.orch,
            agentic_core_instance=cli.controller.agentic_core,
            blackboard_instance=cli.controller.blackboard,
            event_emitter_instance=cli.controller.event_emitter,
            database_instance=cli.controller.database,
            ai_agent_instance=cli.controller.ai_agent,
            controller_instance=cli.controller,
        )
        
        # Start server in background thread
        import threading
        server_thread = threading.Thread(
            target=run_api_server,
            kwargs={"host": args.host, "port": args.port},
            daemon=True
        )
        server_thread.start()
        
        # Start tunnel
        _start_tunnel(args.port)
        return 0
    
    cli = build_platform()
    return cli.run(sys.argv[1:])


def _start_tunnel(port: int = 8000) -> None:
    """Start a tunnel to expose the local server to the internet.
    
    Tries cloudflared first, then ngrok. Prints the public URL if successful.
    """
    import shutil
    import subprocess
    import time
    
    tunnel_tool = None
    proc = None
    
    # Check for cloudflared
    if shutil.which("cloudflared"):
        tunnel_tool = "cloudflared"
    # Check for ngrok
    elif shutil.which("ngrok"):
        tunnel_tool = "ngrok"
    else:
        print("\n" + "="*70)
        print("TUNNEL SETUP REQUIRED")
        print("="*70)
        print("To enable remote access, install one of the following:")
        print()
        print("  1. cloudflared (recommended):")
        print("     - Download: https://github.com/cloudflare/cloudflared/releases")
        print("     - Windows: choco install cloudflared")
        print("     - Mac: brew install cloudflared")
        print("     - Linux: wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb && sudo dpkg -i cloudflared-linux-amd64.deb")
        print()
        print("  2. ngrok:")
        print("     - Download: https://ngrok.com/download")
        print("     - Sign up for free at https://dashboard.ngrok.com/signup")
        print("     - Run: ngrok config add-authtoken <YOUR_TOKEN>")
        print("="*70)
        print()
        return
    
    print(f"\n[*] Starting tunnel with {tunnel_tool} on port {port}...")
    print("[*] Press Ctrl+C to stop\n")
    
    try:
        if tunnel_tool == "cloudflared":
            # Start cloudflared tunnel
            proc = subprocess.Popen(
                ["cloudflared", "tunnel", "--url", f"http://localhost:{port}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Parse output to find the public URL
            print("[*] Waiting for tunnel to initialize...")
            if proc.stdout is None:
                proc.wait()
                return
            for line in proc.stdout:
                line = line.strip()
                if line:
                    print(f"   {line}")
                # Look for the trycloudflare.com URL
                if "trycloudflare.com" in line:
                    import re
                    urls = re.findall(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com", line)
                    if urls:
                        print("\n" + "="*70)
                        print("TUNNEL ACTIVE")
                        print("="*70)
                        print(f"Public URL: {urls[0]}")
                        print(f"Local URL:  http://localhost:{port}")
                        print("="*70)
                        print("\nShare the public URL to access ZAHRA from anywhere!")
                        print("Press Ctrl+C to stop the tunnel\n")
            
            proc.wait()
            
        elif tunnel_tool == "ngrok":
            # Start ngrok tunnel
            proc = subprocess.Popen(
                ["ngrok", "http", str(port)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            print("[*] Waiting for tunnel to initialize...")
            time.sleep(2)  # Give ngrok a moment to start
            
            # Try to get the public URL from ngrok's API
            try:
                import urllib.request
                import json
                for _ in range(10):  # Try for 10 seconds
                    try:
                        resp = urllib.request.urlopen("http://localhost:4040/api/tunnels", timeout=1)
                        data = json.loads(resp.read())
                        tunnels = data.get("tunnels", [])
                        for tunnel in tunnels:
                            public_url = tunnel.get("public_url", "")
                            if public_url:
                                print("\n" + "="*70)
                                print("TUNNEL ACTIVE")
                                print("="*70)
                                print(f"Public URL: {public_url}")
                                print(f"Local URL:  http://localhost:{port}")
                                print("="*70)
                                print("\nShare the public URL to access ZAHRA from anywhere!")
                                print("Press Ctrl+C to stop the tunnel\n")
                                break
                    except Exception:
                        pass
                    time.sleep(1)
            except Exception:
                pass
            
            proc.wait()
            
    except KeyboardInterrupt:
        print("\n\n[*] Stopping tunnel...")
        try:
            if proc is not None:
                proc.terminate()
                proc.wait(timeout=5)
        except Exception:
            pass
        print("[*] Tunnel stopped")


if __name__ == "__main__":
    sys.exit(main())