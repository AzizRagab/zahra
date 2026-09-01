"""AI Agent CLI — command-line interface for the autonomous agent.

Usage:
    python -m ai_agent.cli run "Analyze target: 10.0.0.1"
    python -m ai_agent.cli analyze --data "scan results" --prompt "Find vulnerabilities"
    python -m ai_agent.cli search "CVE-2024-1234"
    python -m ai_agent.cli status
    python -m ai_agent.cli hf-space --generate
    python -m ai_agent.cli hf-space --deploy
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from ai_agent.agent_core import AIAgent, AgentConfig
from ai_agent.hf_integration import HFDeployer


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="zahra-ai-agent",
        description="ZAHRA AI Agent — autonomous agent with RAG, Web Search, and HF",
    )
    sub = parser.add_subparsers(dest="command")

    # run
    p_run = sub.add_parser("run", help="Run the agent on a task")
    p_run.add_argument("task", help="The task to run")
    p_run.add_argument("--iterations", type=int, default=5, help="Max iterations")

    # analyze
    p_an = sub.add_parser("analyze", help="Analyze data")
    p_an.add_argument("--data", required=True, help="Data to analyze")
    p_an.add_argument("--prompt", default="Analyze this data for security issues", help="Analysis prompt")

    # search
    p_search = sub.add_parser("search", help="Search the web")
    p_search.add_argument("query", help="Search query")

    # status
    sub.add_parser("status", help="Show agent status")

    # hf-space
    p_hf = sub.add_parser("hf-space", help="Generate/deploy Hugging Face Space")
    p_hf.add_argument("--generate", action="store_true", help="Generate Space files")
    p_hf.add_argument("--deploy", action="store_true", help="Deploy to Hugging Face")
    p_hf.add_argument("--name", default="zahra-ai-agent", help="Space name")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    # Create agent
    config = AgentConfig.from_env()
    agent = AIAgent(config)

    # Dispatch
    if args.command == "run":
        print(f"Running agent on task: {args.task}")
        print(f"Max iterations: {args.iterations}")
        print("-" * 60)
        agent.config.max_iterations = args.iterations
        findings = agent.run(args.task)
        print(f"\nFindings ({len(findings)}):")
        print(json.dumps(findings, indent=2, default=str))
        return 0

    if args.command == "analyze":
        result = agent.analyze(args.data, args.prompt)
        print(json.dumps(result, indent=2, default=str))
        return 0

    if args.command == "search":
        if agent.web_search is None:
            print("Web search disabled")
            return 1
        results = agent.web_search.search(args.query)
        print(json.dumps(results, indent=2, default=str))
        return 0

    if args.command == "status":
        print(json.dumps(agent.status(), indent=2))
        # Also show RAG stats
        if agent.rag:
            print(f"\nRAG: {json.dumps(agent.rag.stats(), indent=2)}")
        return 0

    if args.command == "hf-space":
        hf = HFDeployer(space_name=args.name)
        if args.generate:
            files = hf.generate_space_files("hf_space")
            print(f"Generated {len(files)} files in hf_space/")
            for name in files:
                print(f"  - {name}")
        if args.deploy:
            result = hf.deploy_space()
            print(json.dumps(result, indent=2, default=str))
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())