"""Hugging Face Integration — deploy and run the AI agent on Hugging Face Spaces.

This module provides:
1. Space deployment (Gradio UI for the agent)
2. Model inference via Hugging Face Inference API
3. Space configuration generation
4. Local model loading with transformers
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger("zahra.ai_agent.hf")


class HFDeployer:
    """Deploy the AI agent to Hugging Face Spaces."""

    def __init__(self, token: str = "", space_name: str = "zahra-ai-agent") -> None:
        self.token = token or os.getenv("HF_TOKEN", "")
        self.space_name = space_name

    # -- Space files generation ---------------------------------------------

    def generate_space_files(self, output_dir: str | Path = "hf_space") -> dict[str, Path]:
        """Generate all files needed for a Hugging Face Space."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        files = {
            "app.py": self._generate_app_py(),
            "requirements.txt": self._generate_requirements(),
            "README.md": self._generate_readme(),
            "Dockerfile": self._generate_dockerfile(),
        }

        written: dict[str, Path] = {}
        for name, content in files.items():
            path = out / name
            path.write_text(content, encoding="utf-8")
            written[name] = path
            logger.info("Generated %s", path)

        return written

    def _generate_app_py(self) -> str:
        """Generate the Gradio app for the Space."""
        return '''"""ZAHRA AI Agent — Hugging Face Space App."""

import gradio as gr
import json
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ai_agent.agent_core import AIAgent, AgentConfig

# Create agent with HF backend
config = AgentConfig(
    backend="huggingface",
    model=os.getenv("AI_AGENT_MODEL", "mistralai/Mistral-7B-Instruct-v0.2"),
    api_key=os.getenv("HF_TOKEN", ""),
    rag_enabled=True,
    web_search_enabled=True,
)
agent = AIAgent(config)


def run_agent(task: str, max_iterations: int = 5) -> str:
    """Run the agent on a task and return results."""
    agent.config.max_iterations = max_iterations
    findings = agent.run(task)
    return json.dumps(findings, indent=2, default=str)


def analyze_data(data: str, prompt: str) -> str:
    """Analyze data with the agent."""
    result = agent.analyze(data, prompt)
    return json.dumps(result, indent=2, default=str)


def search_web(query: str) -> str:
    """Search the web."""
    if agent.web_search:
        results = agent.web_search.search(query)
        return json.dumps(results, indent=2, default=str)
    return "Web search disabled"


def agent_status() -> str:
    """Get agent status."""
    return json.dumps(agent.status(), indent=2)


# Build Gradio interface
with gr.Blocks(title="ZAHRA AI Agent", theme=gr.themes.Soft()) as demo:
    gr.Markdown("# 🐉 ZAHRA AI Agent")
    gr.Markdown("Autonomous AI agent with Adaptive RAG, Web Search, and Hugging Face integration.")

    with gr.Tab("🤖 Run Agent"):
        task_input = gr.Textbox(label="Task", placeholder="e.g. Analyze this target: 10.0.0.1")
        iterations = gr.Slider(1, 10, value=5, label="Max Iterations")
        run_btn = gr.Button("Run Agent")
        output = gr.Textbox(label="Results", lines=20)

        run_btn.click(run_agent, inputs=[task_input, iterations], outputs=output)

    with gr.Tab("🔍 Analyze Data"):
        data_input = gr.Textbox(label="Data", lines=10)
        prompt_input = gr.Textbox(label="Analysis Prompt", value="Analyze this data for security issues")
        analyze_btn = gr.Button("Analyze")
        analyze_output = gr.Textbox(label="Analysis", lines=15)

        analyze_btn.click(analyze_data, inputs=[data_input, prompt_input], outputs=analyze_output)

    with gr.Tab("🌐 Web Search"):
        query_input = gr.Textbox(label="Search Query")
        search_btn = gr.Button("Search")
        search_output = gr.Textbox(label="Results", lines=15)

        search_btn.click(search_web, inputs=query_input, outputs=search_output)

    with gr.Tab("📊 Status"):
        status_btn = gr.Button("Get Status")
        status_output = gr.Textbox(label="Status", lines=10)

        status_btn.click(agent_status, outputs=status_output)

if __name__ == "__main__":
    demo.launch()
'''

    def _generate_requirements(self) -> str:
        return """gradio>=4.0.0
requests>=2.31.0
transformers>=4.36.0
torch>=2.1.0
chromadb>=0.4.0
"""

    def _generate_readme(self) -> str:
        return """---
title: ZAHRA AI Agent
emoji: 🐉
colorFrom: green
colorTo: blue
sdk: gradio
sdk_version: 4.0.0
app_file: app.py
pinned: false
---

# 🐉 ZAHRA AI Agent

Autonomous AI agent with:
- **Adaptive RAG** — learns from every interaction
- **Web Search** — real-time intelligence gathering
- **Hugging Face Models** — Mistral, Llama, and more
- **ReAct Loop** — thinks, acts, and observes

## Usage

1. Set `HF_TOKEN` in Space secrets for API access
2. Choose a model via `AI_AGENT_MODEL` env var
3. Run tasks, analyze data, or search the web
"""

    def _generate_dockerfile(self) -> str:
        return """FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 7860

CMD ["python", "app.py"]
"""

    # -- Space deployment ----------------------------------------------------

    def deploy_space(self, local_dir: str | Path = "hf_space") -> dict[str, Any]:
        """Deploy the generated Space to Hugging Face."""
        if not self.token:
            return {"error": "HF_TOKEN not set. Set it to deploy."}

        try:
            from huggingface_hub import HfApi

            api = HfApi(token=self.token)

            # Create or get the Space
            try:
                api.create_repo(
                    repo_id=self.space_name,
                    repo_type="space",
                    space_sdk="gradio",
                    exist_ok=True,
                )
            except Exception:
                pass

            # Upload files
            api.upload_folder(
                repo_id=self.space_name,
                repo_type="space",
                folder_path=str(local_dir),
            )

            return {
                "status": "deployed",
                "space": f"https://huggingface.co/spaces/{self.space_name}",
            }
        except ImportError:
            return {"error": "huggingface_hub not installed. Run: pip install huggingface_hub"}
        except Exception as exc:
            return {"error": str(exc)}

    # -- Model inference -----------------------------------------------------

    def infer(self, prompt: str, model: str = "mistralai/Mistral-7B-Instruct-v0.2") -> str:
        """Run inference via Hugging Face Inference API."""
        if not self.token:
            return "HF_TOKEN not set"

        import requests

        url = f"https://router.huggingface.co/hf-inference/models/{model}"
        headers = {"Authorization": f"Bearer {self.token}"}
        payload = {
            "inputs": prompt,
            "parameters": {
                "temperature": 0.3,
                "max_new_tokens": 1024,
                "return_full_text": False,
            },
        }
        resp = requests.post(url, headers=headers, json=payload, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list) and data:
            return data[0].get("generated_text", "")
        return str(data)

    # -- Local model loading -------------------------------------------------

    def load_local_model(self, model_name: str, use_gpu: bool = True) -> Any:
        """Load a model locally with transformers."""
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline

            device = 0 if use_gpu else -1
            return pipeline(
                "text-generation",
                model=model_name,
                device=device,
                torch_dtype="auto",
            )
        except ImportError:
            logger.warning("transformers not installed")
            return None