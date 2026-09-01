"""CLI interface — command-line interface for the zahra platform.

Provides a rich terminal experience for running campaigns, viewing
findings, and managing memory.

Usage:
    python main.py scan example.com
    python main.py recon 192.168.1.1
    python main.py exploit https://target.com
    python main.py full pentest example.com
    python main.py status
    python main.py memory
    python main.py serve --port 8000
"""

from __future__ import annotations

import argparse
import json
import logging
from typing import Any

import pyfiglet  # type: ignore

from core.orchestrator import Orchestrator
from zahra_agent import ZahraAgent

logger = logging.getLogger("zahra.interfaces.cli")


# ANSI color codes for terminal output
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def print_banner() -> None:
    """Print the ZAHRA ASCII-art banner using pyfiglet."""
    banner: str = pyfiglet.figlet_format("ZAHRA", font="slant")  # type: ignore
    print(banner)  # type: ignore
    print("      AI Pentest Swarm Platform\n")


def main() -> int:
    """Entry point for the global `zahra` command.
    
    Creates a default CLI instance and processes command-line arguments.
    """
    import sys
    from pathlib import Path
    
    # Ensure the project root is on the path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
    
    cli = CLI()
    return cli.run()


class CLI:
    """Command-line interface for the zahra platform."""

    def __init__(
        self,
        orchestrator: Orchestrator | None = None,
        controller: Any = None,
        brain: Any = None,
    ) -> None:
        self.orch = orchestrator or Orchestrator()
        self.controller = controller  # ZahraController instance (optional)
        self.brain = brain  # Safe ZahraAgent master brain (optional)
    
    def __getattr__(self, name: str) -> Any:
        """Allow access to orchestrator attributes for backward compatibility."""
        return getattr(self.orch, name)

    # -- entry point -------------------------------------------------------

    def run(self, args: list[str] | None = None) -> int:
        """Parse arguments and dispatch to the appropriate command."""
        parser = self._build_parser()
        parsed = parser.parse_args(args)

        # Set up logging
        logging.basicConfig(
            level=getattr(logging, parsed.log_level.upper()),
            format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
            datefmt="%H:%M:%S",
        )

        if not parsed.command:
            parser.print_help()
            return 0

        # Dispatch
        dispatch: dict[str, Any] = {
            "scan": self._cmd_scan,
            "recon": self._cmd_recon,
            "exploit": self._cmd_exploit,
            "c2": self._cmd_c2,
            "mitm": self._cmd_mitm,
            "full": self._cmd_full,
            "status": self._cmd_status,
            "memory": self._cmd_memory,
            "campaigns": self._cmd_campaigns,
            "serve": self._cmd_serve,
            "tunnel": self._cmd_tunnel,
            "controller": self._cmd_controller,
            "think": self._cmd_think,
            "decide": self._cmd_decide,
            "deploy": self._cmd_deploy,
            "cmd": self._cmd_cmd,
            "brain": self._cmd_brain,
        }

        handler = dispatch.get(parsed.command)
        if handler is None:
            print(f"{Colors.RED}Unknown command: {parsed.command}{Colors.RESET}")
            return 1

        return handler(parsed)

    # -- parser ------------------------------------------------------------

    def _build_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="zahra",
            description="Zahra — AI Pentest Swarm Platform",
        )
        parser.add_argument(
            "--log-level",
            default="INFO",
            choices=["DEBUG", "INFO", "WARNING", "ERROR"],
            help="Logging verbosity (default: INFO)",
        )

        sub = parser.add_subparsers(dest="command")

        # scan
        p_scan = sub.add_parser("scan", help="Run vulnerability scan on a target")
        p_scan.add_argument("target", help="Target host, IP, or URL")
        p_scan.add_argument("--json", action="store_true", help="Output as JSON")

        # recon
        p_recon = sub.add_parser("recon", help="Run reconnaissance on a target")
        p_recon.add_argument("target", help="Target host, IP, or URL")
        p_recon.add_argument("--json", action="store_true", help="Output as JSON")

        # exploit
        p_exploit = sub.add_parser("exploit", help="Run exploitation on a target")
        p_exploit.add_argument("target", help="Target host, IP, or URL")
        p_exploit.add_argument("--json", action="store_true", help="Output as JSON")

        # c2
        p_c2 = sub.add_parser("c2", help="Run Command & Control operations on a target")
        p_c2.add_argument("target", help="Target host, IP, or URL")
        p_c2.add_argument("--json", action="store_true", help="Output as JSON")

        # mitm
        p_mitm = sub.add_parser("mitm", help="Run Man-in-the-Middle attack on a target")
        p_mitm.add_argument("target", help="Target host, IP, or URL")
        p_mitm.add_argument("--json", action="store_true", help="Output as JSON")

        # full
        p_full = sub.add_parser("full", help="Full pentest: recon → scan → exploit")
        p_full.add_argument("target", help="Target host, IP, or URL")
        p_full.add_argument("--json", action="store_true", help="Output as JSON")

        # status
        sub.add_parser("status", help="Show platform status")

        # memory
        p_mem = sub.add_parser("memory", help="View memory store")
        p_mem.add_argument("--clear", action="store_true", help="Clear all memory")

        # campaigns
        sub.add_parser("campaigns", help="List all campaigns")

        # serve
        p_serve = sub.add_parser("serve", help="Start the REST API server")
        p_serve.add_argument("--host", default="0.0.0.0", help="Bind address")
        p_serve.add_argument("--port", type=int, default=8000, help="Port number")
        p_serve.add_argument("--tunnel", action="store_true", help="Expose dashboard to the internet via cloudflared/ngrok")

        # tunnel — expose dashboard to internet
        p_tunnel = sub.add_parser("tunnel", help="Expose ZAHRA dashboard to the internet")
        p_tunnel.add_argument("--port", type=int, default=8000, help="Port to tunnel (default: 8000)")
        p_tunnel.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")

        # controller — ZahraController specific commands
        p_ctrl = sub.add_parser(
            "controller",
            help="ZahraController — the operator-directed controller (manages everything)",
        )
        p_ctrl.add_argument(
            "--json", action="store_true", help="Output as JSON"
        )

        # think — ask the controller's AI to think about a task
        p_think = sub.add_parser(
            "think",
            help="Ask the ZahraController's AI agent to think about a task",
        )
        p_think.add_argument("task", help="The task for the controller to think about")
        p_think.add_argument("--json", action="store_true", help="Output as JSON")

        # decide — make a strategic decision
        p_decide = sub.add_parser(
            "decide",
            help="Ask the ZahraController to make a strategic decision",
        )
        p_decide.add_argument("command_str", help="The command to decide on")
        p_decide.add_argument("--json", action="store_true", help="Output as JSON")

        # deploy — deploy a specific agent
        p_deploy = sub.add_parser(
            "deploy",
            help="Deploy a specific swarm agent directly via the ZahraController",
        )
        p_deploy.add_argument(
            "agent",
            choices=["recon_agent", "scan_agent", "exploit_agent", "c2_agent", "mitm_agent"],
            help="Agent to deploy",
        )
        p_deploy.add_argument("target", help="Target host, IP, or URL")
        p_deploy.add_argument("--json", action="store_true", help="Output as JSON")

        # cmd — execute a system command directly (unrestricted)
        p_cmd = sub.add_parser(
            "cmd",
            help="Execute a system command directly via the ZahraController (unrestricted)",
        )
        p_cmd.add_argument("command", help="The command to execute")
        p_cmd.add_argument(
            "--timeout", type=int, default=300, help="Timeout in seconds"
        )
        p_cmd.add_argument("--json", action="store_true", help="Output as JSON")

        # brain — Master Controller Brain (unrestricted by default)
        p_brain = sub.add_parser(
            "brain",
            help="ZahraAgent — Master Controller Brain (unrestricted by default)",
        )
        brain_sub = p_brain.add_subparsers(dest="brain_command", required=True)

        pb_think = brain_sub.add_parser("think", help="Generate a strategic plan for a goal")
        pb_think.add_argument("goal", help="High-level goal, e.g. 'recon 127.0.0.1'")

        pb_run = brain_sub.add_parser("run", help="Run a full campaign autonomously (add --restricted for approval prompts)")
        pb_run.add_argument("goal", help="High-level goal, e.g. 'recon 127.0.0.1'")
        pb_run.add_argument("--restricted", action="store_true",
                            help="Require operator approval per command + enforce scope.")

        pb_assess = brain_sub.add_parser(
            "assess", help="Full auto assessment: recon + scan + attack library + report")
        pb_assess.add_argument("targets", nargs="+",
                               help="Targets: hosts, IPs, CIDR ranges, URLs")
        pb_assess.add_argument("--fast", action="store_true",
                               help="Fast top-ports scan only.")
        pb_assess.add_argument("--no-report", action="store_true",
                               help="Do not write an HTML report.")

        pb_shell = brain_sub.add_parser("shell", help="Interactive shell (type goals, explore)")

        pb_recall = brain_sub.add_parser("recall", help="Query memory for similar past experiences")
        pb_recall.add_argument("query", help="Search query, e.g. 'port scan'")
        pb_recall.add_argument("--top-k", type=int, default=5)

        pb_skills = brain_sub.add_parser("skills", help="List learned skills")
        pb_skills.add_argument("--category", default=None)

        pb_osint = brain_sub.add_parser(
            "osint", help="Agent-Reach OSINT integration (dynamic channels, deep learning)"
        )
        osint_sub = pb_osint.add_subparsers(dest="osint_command", required=True)
        osint_sub.add_parser("channels", help="List loaded Agent-Reach channels")
        po_search = osint_sub.add_parser("search", help="Search one channel")
        po_search.add_argument("channel", help="e.g. reddit, github, twitter, web")
        po_search.add_argument("query", help="Search query")
        po_read = osint_sub.add_parser("read", help="Read a URL via a channel")
        po_read.add_argument("channel", help="e.g. web, github, youtube")
        po_read.add_argument("url", help="URL to read")
        po_sim = osint_sub.add_parser(
            "simulate", help="Offline simulated OSINT search (integration test)"
        )
        po_sim.add_argument("query", help="Query to simulate")
        po_sim.add_argument("--channels", nargs="*",
                            default=["github", "reddit", "twitter", "v2ex"])

        pb_attacks = brain_sub.add_parser(
            "attacks", help="Attack knowledge base (service-aware techniques)"
        )
        attacks_sub = pb_attacks.add_subparsers(dest="attacks_command", required=True)
        attacks_sub.add_parser("seed", help="Seed the attack library into the brain")
        pa_list = attacks_sub.add_parser(
            "list", help="List attack techniques (optionally for one service)"
        )
        pa_list.add_argument("service", nargs="?", default=None)
        pa_search = attacks_sub.add_parser("search", help="Search the attack library")
        pa_search.add_argument("query")
        pa_plan = attacks_sub.add_parser(
            "plan", help="Build attack commands for a service against a target"
        )
        pa_plan.add_argument("service")
        pa_plan.add_argument("target")

        brain_sub.add_parser("stats", help="Show brain memory statistics")

        return parser

    # -- commands ----------------------------------------------------------

    def _cmd_scan(self, args: argparse.Namespace) -> int:
        return self._run_campaign(f"scan {args.target}", args)

    def _cmd_recon(self, args: argparse.Namespace) -> int:
        return self._run_campaign(f"recon {args.target}", args)

    def _cmd_exploit(self, args: argparse.Namespace) -> int:
        return self._run_campaign(f"exploit {args.target}", args)

    def _cmd_c2(self, args: argparse.Namespace) -> int:
        return self._run_campaign(f"c2 {args.target}", args)

    def _cmd_mitm(self, args: argparse.Namespace) -> int:
        return self._run_campaign(f"mitm {args.target}", args)

    def _cmd_full(self, args: argparse.Namespace) -> int:
        return self._run_campaign(f"full pentest {args.target}", args)

    def _run_campaign(self, command: str, args: argparse.Namespace) -> int:
        print(f"{Colors.BOLD}Command:{Colors.RESET} {command}")
        print(f"{Colors.BOLD}Target:{Colors.RESET} {getattr(args, 'target', 'N/A')}")
        print()

        campaign = self.orch.create_campaign(command)
        print(f"{Colors.GREEN}✓ Campaign created: {campaign.id}{Colors.RESET}")
        print(f"  Intent: {campaign.intent.value}")
        print(f"  Target: {campaign.target}")
        print()

        print(f"{Colors.YELLOW}▶ Running campaign...{Colors.RESET}")
        campaign = self.orch.run_campaign(campaign.id)

        if campaign.status.value == "completed":
            print(f"\n{Colors.GREEN}✓ Campaign completed!{Colors.RESET}")
        else:
            print(f"\n{Colors.RED}✗ Campaign {campaign.status.value}{Colors.RESET}")
            if campaign.error:
                print(f"  Error: {campaign.error}")

        print(f"\n{Colors.BOLD}Findings ({len(campaign.findings)}):{Colors.RESET}")
        if getattr(args, "json", False):
            print(json.dumps([f.to_dict() for f in campaign.findings], indent=2))
        else:
            self._print_findings(campaign.findings)

        return 0 if campaign.status.value == "completed" else 1

    def _cmd_status(self, args: argparse.Namespace) -> int:
        status = self.orch.status()
        print(f"{Colors.BOLD}Platform Status{Colors.RESET}")
        print(f"  Campaigns:  {status['campaigns']}")
        print(f"  Active:     {status['active']}")
        print(f"  Completed:  {status['completed']}")
        print(f"  Budget:      {status['budget']}")
        print(f"  Memory:     {status['memory']}")
        return 0

    def _cmd_memory(self, args: argparse.Namespace) -> int:
        if getattr(args, "clear", False):
            self.orch.memory.clear()
            print(f"{Colors.YELLOW}Memory cleared.{Colors.RESET}")
            return 0

        summary = self.orch.memory.summary()
        print(f"{Colors.BOLD}Memory Store{Colors.RESET}")
        print(f"  Entries:   {summary['entries']}")
        print(f"  Findings:  {summary['findings']}")
        print(f"  Categories: {summary.get('categories', {})}")
        print(f"  Severities: {summary.get('severities', {})}")

        print(f"\n{Colors.BOLD}Recent Findings:{Colors.RESET}")
        findings = self.orch.memory.all_findings()[-10:]
        self._print_findings(findings)
        return 0

    def _cmd_campaigns(self, args: argparse.Namespace) -> int:
        campaigns = self.orch.list_campaigns()
        print(f"{Colors.BOLD}Campaigns ({len(campaigns)}):{Colors.RESET}\n")
        for c in campaigns:
            status_color = (
                Colors.GREEN
                if c.status.value == "completed"
                else Colors.RED
                if c.status.value == "failed"
                else Colors.YELLOW
            )
            print(f"  {status_color}[{c.status.value.upper()}]{Colors.RESET} {c.id[:8]} — {c.target} ({c.intent.value})")
        return 0

    def _cmd_serve(self, args: argparse.Namespace) -> int:
        print(f"{Colors.BOLD}Starting API server on {args.host}:{args.port}{Colors.RESET}")
        try:
            import uvicorn

            from interfaces.api import create_app

            app = create_app(self.orch)
            uvicorn.run(app, host=args.host, port=args.port)
            return 0
        except ImportError:
            print(f"{Colors.RED}uvicorn and fastapi are required to serve the API.{Colors.RESET}")
            print(f"Install with: {Colors.YELLOW}pip install uvicorn fastapi pydantic{Colors.RESET}")
            return 1

    def _cmd_tunnel(self, args: argparse.Namespace) -> int:
        """Expose the ZAHRA dashboard to the internet using cloudflared or ngrok."""
        import threading

        # Build the full platform using main.py's logic
        from main import build_platform, _start_tunnel
        from interfaces.api_server import setup_api, run_api_server

        print(f"{Colors.BOLD}Building ZAHRA platform...{Colors.RESET}")
        cli = build_platform()

        print(f"{Colors.BOLD}Setting up API server on {args.host}:{args.port}{Colors.RESET}")
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
        server_thread = threading.Thread(
            target=run_api_server,
            kwargs={"host": args.host, "port": args.port},
            daemon=True
        )
        server_thread.start()

        # Start tunnel (this blocks until Ctrl+C)
        _start_tunnel(args.port)
        return 0

    # -- ZahraController commands ------------------------------------------

    def _cmd_controller(self, args: argparse.Namespace) -> int:
        """Show the ZahraController status."""
        if not self.controller:
            print(f"{Colors.RED}ZahraController not initialised.{Colors.RESET}")
            print(f"{Colors.YELLOW}Run with --llm-backend to configure.{Colors.RESET}")
            return 1

        status = self.controller.status()
        if getattr(args, "json", False):
            print(json.dumps(status, indent=2, default=str))
            return 0

        print(f"{Colors.MAGENTA}╔══════════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.MAGENTA}║  ZAHRA CONTROLLER  —  Operator-Authorized Mode        ║{Colors.RESET}")
        print(f"{Colors.MAGENTA}╚══════════════════════════════════════════════════════╝{Colors.RESET}")
        print()
        print(f"  {Colors.BOLD}Name:{Colors.RESET}          {status['name']}")
        print(f"  {Colors.BOLD}Version:{Colors.RESET}       {status['version']}")
        print(f"  {Colors.BOLD}Attribution:{Colors.RESET}   {status['attribution']}")
        print(f"  {Colors.BOLD}Mode:{Colors.RESET}          {status['mode']}")
        print(f"  {Colors.BOLD}Running:{Colors.RESET}       {'✅ YES' if status['running'] else '❌ NO'}")
        print(f"  {Colors.BOLD}LLM Backend:{Colors.RESET}   {status['llm_backend']}")
        print(f"  {Colors.BOLD}Model:{Colors.RESET}         {status['model']}")
        print(f"  {Colors.BOLD}No LLaMA:{Colors.RESET}       {'✅ YES' if status['no_llama'] else '❌ NO'}")
        print(f"  {Colors.BOLD}Offline:{Colors.RESET}        {'✅ YES' if status['is_offline'] else '❌ NO'}")
        print()

        print(f"{Colors.BOLD}Execution Settings:{Colors.RESET}")
        ur = status.get("unrestricted", {})
        for key, val in ur.items():
            enabled = "✅" if val else "❌" if isinstance(val, bool) else val
            print(f"  {key:.<30} {enabled}")

        print()
        print(f"{Colors.BOLD}Resource Budget (unlimited):{Colors.RESET}")
        budget = status.get("budget", {})
        print(f"  max_tokens:       {budget.get('max_tokens', 'N/A')}")
        print(f"  max_agent_hours:  {budget.get('max_agent_hours', 'N/A')}")
        print(f"  unlimited:        {budget.get('unlimited', False)}")

        print()
        print(f"{Colors.BOLD}Campaigns:{Colors.RESET}")
        camps = status.get("campaigns", {})
        print(f"  Total:     {camps.get('total', 0)}")
        print(f"  Active:    {camps.get('active', 0)}")
        print(f"  Completed: {camps.get('completed', 0)}")

        print()
        print(f"{Colors.BOLD}Agents ({len(status.get('agents', []))}):{Colors.RESET}")
        for agent in status.get("agents", []):
            print(f"  • {agent}")

        print()
        mem = status.get("memory", {})
        print(f"{Colors.BOLD}Memory / RAG:{Colors.RESET}")
        print(f"  Entries:   {mem.get('entries', 0)}")
        print(f"  Findings:  {mem.get('findings', 0)}")

        personal = status.get("personalization", {})
        print()
        print(f"{Colors.BOLD}Personalization:{Colors.RESET}")
        print(f"  User:       {personal.get('user_name', 'operator')}")
        print(f"  Personal RAG: {'✅' if personal.get('personal_rag') else '❌'}")

        return 0

    def _cmd_think(self, args: argparse.Namespace) -> int:
        """Ask the ZahraController's AI to think about a task."""
        if not self.controller:
            print(f"{Colors.RED}ZahraController not initialised.{Colors.RESET}")
            return 1

        result = self.controller.think(args.task)
        if getattr(args, "json", False):
            print(json.dumps(result, indent=2, default=str))
            return 0

        print(f"{Colors.CYAN}+- ZahraController Think -------------------------------+{Colors.RESET}")
        print(f"{Colors.CYAN}|{Colors.RESET} Task: {args.task}")
        print(f"{Colors.CYAN}|{Colors.RESET} Action: {result.get('action', 'unknown')}")
        if "reasoning" in result:
            reason = result.get("reasoning", "")
            print(f"{Colors.CYAN}|{Colors.RESET} Reasoning: {reason[:200]}")
        if "command" in result and result["command"]:
            print(f"{Colors.CYAN}|{Colors.RESET} Command: {result['command']}")
        if "summary" in result:
            print(f"{Colors.CYAN}|{Colors.RESET} Summary: {result['summary'][:200]}")
        print(f"{Colors.CYAN}+------------------------------------------------------+{Colors.RESET}")
        return 0

    def _cmd_decide(self, args: argparse.Namespace) -> int:
        """Ask the ZahraController to make a strategic decision."""
        if not self.controller:
            print(f"{Colors.RED}ZahraController not initialised.{Colors.RESET}")
            return 1

        decision = self.controller.decide(args.command_str)
        if getattr(args, "json", False):
            print(json.dumps(decision, indent=2, default=str))
            return 0

        print(f"{Colors.MAGENTA}┌─ ZahraController Decision ────────────────────────────┐{Colors.RESET}")
        print(f"{Colors.MAGENTA}│{Colors.RESET} Command:  {args.command_str}")
        print(f"{Colors.MAGENTA}│{Colors.RESET} Intent:   {decision.get('intent', 'unknown')}")
        print(f"{Colors.MAGENTA}│{Colors.RESET} Target:   {decision.get('target', 'N/A')}")
        print(f"{Colors.MAGENTA}│{Colors.RESET} Model:    {decision.get('llm_model', 'N/A')}  (no LLaMA)")
        print(f"{Colors.MAGENTA}│{Colors.RESET} Budget:   {'unlimited' if decision.get('budget_unlimited') else 'capped'}")
        print(f"{Colors.MAGENTA}│{Colors.RESET} Plan:")
        for i, step in enumerate(decision.get("plan", []), 1):
            print(f"{Colors.MAGENTA}│{Colors.RESET}   {i}. {step}")
        print(f"{Colors.MAGENTA}└──────────────────────────────────────────────────────┘{Colors.RESET}")
        return 0

    def _cmd_deploy(self, args: argparse.Namespace) -> int:
        """Deploy a specific agent via the ZahraController."""
        if not self.controller:
            print(f"{Colors.RED}ZahraController not initialised.{Colors.RESET}")
            return 1

        print(f"{Colors.YELLOW}▶ Deploying {args.agent} against {args.target}...{Colors.RESET}")
        finding = self.controller.deploy_agent(args.agent, args.target)

        if getattr(args, "json", False):
            print(json.dumps(finding.to_dict(), indent=2, default=str))
            return 0

        print(f"{Colors.GREEN}✓ Deployment complete{Colors.RESET}")
        print(f"  Finding Type: {finding.finding_type}")
        print(f"  Severity:     {finding.severity}")
        print(f"  Description:  {finding.description[:200]}")
        if finding.evidence:
            print(f"  Evidence:     {finding.evidence[:200]}")
        print(f"  Confidence:   {finding.confidence:.0%}")
        return 0

    def _cmd_cmd(self, args: argparse.Namespace) -> int:
        """Execute a system command directly (unrestricted)."""
        if not self.controller:
            print(f"{Colors.RED}ZahraController not initialised.{Colors.RESET}")
            return 1

        print(f"{Colors.YELLOW}▶ Executing: {args.command}{Colors.RESET}")
        result = self.controller.run_command(args.command, timeout=getattr(args, "timeout", 300))

        if getattr(args, "json", False):
            print(json.dumps(result, indent=2, default=str))
            return 0

        rc = result.get("return_code", -1)
        if rc == 0:
            print(f"{Colors.GREEN}✅ Command succeeded (rc=0){Colors.RESET}")
        else:
            print(f"{Colors.RED}❌ Command returned rc={rc}{Colors.RESET}")

        if result.get("stdout"):
            print(f"\n{Colors.BOLD}STDOUT:{Colors.RESET}")
            print(result["stdout"][:2000])
        if result.get("stderr"):
            print(f"\n{Colors.BOLD}STDERR:{Colors.RESET}")
            print(result["stderr"][:1000])
        return 0 if rc == 0 else 1

    # -- Safe Master Brain commands ----------------------------------------

    def _cmd_brain(self, args: argparse.Namespace) -> int:
        """Handle the Master Controller Brain subcommands."""
        from zahra_agent import ZahraAgent

        # Use the shared brain instance if provided, otherwise create one
        if self.brain is None:
            unrestricted = not getattr(args, "restricted", False)
            self.brain = ZahraAgent(unrestricted=unrestricted)

        brain_cmd = args.brain_command

        if brain_cmd == "assess":
            goal = " ".join(args.targets)
            self.brain.assess(goal, fast=args.fast, save_report=not args.no_report)
            return 0

        if brain_cmd == "shell":
            self.brain.shell()
            return 0

        if brain_cmd == "think":
            plan = self.brain.think(args.goal)
            print(f"\n{Colors.BOLD}[GOAL]{Colors.RESET} {args.goal}")
            print(f"{Colors.BOLD}[PLAN]{Colors.RESET}")
            for step in plan:
                print(f"  - {Colors.CYAN}{step['phase']}{Colors.RESET}: {step['action']}")
            return 0

        if brain_cmd == "run":
            self.brain.run_campaign(
                args.goal,
                auto_approve=not getattr(args, "restricted", False),
            )
            return 0

        if brain_cmd == "recall":
            results = self.brain.recall(args.query, top_k=args.top_k)
            if not results:
                print(f"\nNo similar past experiences found for: {args.query}")
            else:
                print(f"\nTop {len(results)} similar past experiences for: {args.query}")
                for r in results:
                    status = "SUCCESS" if r["success"] else "FAILED"
                    print(f"\n  [{r['similarity']:.3f}] {status} | {r['timestamp']}")
                    print(f"    goal:    {r['goal']}")
                    print(f"    phase:   {r['phase']}")
                    print(f"    command: {r['command']}")
            return 0

        if brain_cmd == "skills":
            skills = self.brain.memory.get_skills(category=getattr(args, "category", None))
            if not skills:
                print("\nNo skills learned yet.")
            else:
                print(f"\n{len(skills)} skill(s):")
                for s in skills:
                    print(f"  - [{s['category']}] {s['name']}: {s['description']}")
            return 0

        if brain_cmd == "osint":
            print(self.brain.ar.summary())
            osint_cmd = args.osint_command
            if osint_cmd == "channels":
                return 0
            if osint_cmd == "search":
                result = self.brain.agent_reach_search(args.channel, args.query)
                print(f"\n{Colors.BOLD}[OSINT SEARCH]{Colors.RESET} "
                      f"channel={result['channel']} ok={result['ok']}")
                print(result["output"][:3000] if result["ok"] else result.get("error"))
                return 0 if result["ok"] else 1
            if osint_cmd == "read":
                result = self.brain.agent_reach_read(args.channel, args.url)
                print(f"\n{Colors.BOLD}[OSINT READ]{Colors.RESET} "
                      f"channel={result['channel']} ok={result['ok']}")
                print(result["output"][:3000] if result["ok"] else result.get("error"))
                return 0 if result["ok"] else 1
            if osint_cmd == "simulate":
                result = self.brain.execute_osint(
                    query=f"simulated OSINT search for: {args.query}",
                    goal=args.query,
                    phase="OSINT",
                    channels=args.channels,
                    require_approval=False,
                    simulate=True,
                )
                print(f"\n[SIMULATED OSINT] query={args.query!r} ok={result['ok']} "
                      f"winner={result['channel']}")
                for attempt in result.get("attempts", []):
                    mark = "OK " if attempt["ok"] else "FAIL"
                    print(f"  [{mark}] {attempt['channel']}: "
                          f"{attempt['error'] or 'results returned'}")
                return 0 if result["ok"] else 1
            return 1

        if brain_cmd == "attacks":
            from zahra_agent import ATTACK_LIBRARY, normalize_service
            acmd = args.attacks_command
            if acmd == "seed":
                n = self.brain._seed_attack_library()
                print(f"Seeded {n} new item(s). Brain now holds "
                      f"{len(self.brain.memory.get_skills())} skill(s).")
                return 0
            if acmd == "list":
                service = getattr(args, "service", None)
                if service:
                    canonical = normalize_service(service)
                    print(f"\n[{canonical}] {len(ATTACK_LIBRARY.get(canonical, []))} technique(s):")
                    for t in ATTACK_LIBRARY.get(canonical, []):
                        print(f"  - [{t['category']}] {t['name']}: {t['description']}")
                        print(f"      {t['command']}")
                else:
                    total = sum(len(v) for v in ATTACK_LIBRARY.values())
                    print(f"\nAttack library: {len(ATTACK_LIBRARY)} service(s), "
                          f"{total} technique(s).")
                    for service, techs in sorted(ATTACK_LIBRARY.items()):
                        print(f"  {service:<14} {len(techs):>2} techniques")
                return 0
            if acmd == "search":
                q = args.query.lower()
                hits = [(s, t) for s, techs in ATTACK_LIBRARY.items() for t in techs
                        if q in " ".join([s, t["name"], t["description"],
                                          t["command"], " ".join(t["tags"])]).lower()]
                print(f"\n{len(hits)} match(es) for {q!r}:")
                for service, t in hits:
                    print(f"  [{service}] {t['name']}: {t['description']}")
                return 0
            if acmd == "plan":
                canonical = normalize_service(args.service)
                print(f"\n[{canonical}] attack plan for {args.target}:")
                for t in ATTACK_LIBRARY.get(canonical, []):
                    cmd = t["command"].replace("{target}", args.target) \
                                     .replace("{service}", canonical)
                    print(f"  - [{t['category']}] {t['name']}")
                    print(f"      {cmd}")
                return 0
            return 1

        if brain_cmd == "stats":
            stats = self.brain.memory.stats()
            print("\n[SAFE BRAIN STATS]")
            for key, value in stats.items():
                print(f"  {key}: {value}")
            return 0

        print(f"{Colors.RED}Unknown brain command: {brain_cmd}{Colors.RESET}")
        return 1

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _print_findings(findings: list[Any]) -> None:
        if not findings:
            print("  (no findings)")
            return

        severity_colors: dict[str, str] = {
            "critical": Colors.RED,
            "high": Colors.RED,
            "medium": Colors.YELLOW,
            "low": Colors.BLUE,
            "info": Colors.RESET,
        }

        for f in findings:
            severity = getattr(f, 'severity', 'info')
            finding_type = getattr(f, 'finding_type', 'unknown')
            description = getattr(f, 'description', '')
            evidence = getattr(f, 'evidence', '')
            agent_name = getattr(f, 'agent_name', 'unknown')
            confidence = getattr(f, 'confidence', 0.0)

            color = severity_colors.get(severity, Colors.RESET)
            print(f"  {color}[{severity.upper()}]{Colors.RESET} {finding_type}: {description}")
            if evidence:
                print(f"         Evidence: {evidence[:100]}")
            print(f"         Agent: {agent_name} | Confidence: {confidence:.0%}")
            print()
