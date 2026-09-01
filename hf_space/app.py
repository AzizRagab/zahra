"""ZAHRA AI Agent — Hugging Face Space App."""

import gradio as gr
import json
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ai_agent.agent_core import AIAgent, AgentConfig
from ai_agent.train import DEFAULT_KNOWLEDGE, train

# Create agent with HF backend
config = AgentConfig(
    backend="huggingface",
    model=os.getenv("AI_AGENT_MODEL", "mistralai/Mistral-7B-Instruct-v0.2"),
    api_key=os.getenv("HF_TOKEN", ""),
    rag_enabled=True,
    web_search_enabled=True,
)
agent = AIAgent(config)

# Auto-train RAG with pentest knowledge on startup
if agent.rag is not None and agent.rag.stats()["total_entries"] == 0:
    train(agent.rag, DEFAULT_KNOWLEDGE)


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
    status = agent.status()
    if agent.rag:
        status["rag"] = agent.rag.stats()
    return json.dumps(status, indent=2)


def train_agent() -> str:
    """Train the agent's RAG with pentest knowledge."""
    if agent.rag is None:
        return "RAG disabled"
    count = train(agent.rag, DEFAULT_KNOWLEDGE)
    return json.dumps(
        {"trained": count, "stats": agent.rag.stats()},
        indent=2,
        default=str,
    )


def rag_search(query: str, top_k: int = 5) -> str:
    """Search the agent's RAG memory."""
    if agent.rag is None:
        return "RAG disabled"
    results = agent.rag.search(query, top_k=top_k)
    return json.dumps(results, indent=2, default=str)


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

    with gr.Tab("🧠 RAG Memory"):
        rag_query = gr.Textbox(label="Search Memory", placeholder="e.g. SQL injection")
        rag_topk = gr.Slider(1, 10, value=5, label="Top K")
        rag_search_btn = gr.Button("Search Memory")
        rag_output = gr.Textbox(label="Results", lines=15)

        rag_search_btn.click(rag_search, inputs=[rag_query, rag_topk], outputs=rag_output)

        train_btn = gr.Button("Train with Pentest Knowledge")
        train_output = gr.Textbox(label="Training Result", lines=10)

        train_btn.click(train_agent, outputs=train_output)

    with gr.Tab("📊 Status"):
        status_btn = gr.Button("Get Status")
        status_output = gr.Textbox(label="Status", lines=10)

        status_btn.click(agent_status, outputs=status_output)

if __name__ == "__main__":
    demo.launch()