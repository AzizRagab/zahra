"""AI Agent Core — the thinking brain of the autonomous agent.

This module implements a complete AI agent that:
1. Uses LLM backends (Hugging Face, Ollama, OpenAI) to think and analyze
2. Maintains a ReAct loop (Reason → Act → Observe)
3. Integrates with Adaptive RAG for memory and learning
4. Uses Web Search for real-time intelligence gathering
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from ai_engine.prompt_engineer import WEB_SEARCH_AGENT_SYSTEM_PROMPT

logger = logging.getLogger("zahra.ai_agent")

# =============================================================================
# Configuration
# =============================================================================


@dataclass
class AgentConfig:
    """Configuration for the AI agent."""

    backend: str = "huggingface"  # huggingface, ollama, openai, offline
    model: str = "mistralai/Mistral-7B-Instruct-v0.2"
    base_url: str = ""
    api_key: str = ""
    temperature: float = 0.3
    max_tokens: int = 2048
    max_iterations: int = 10
    thinking_enabled: bool = True
    rag_enabled: bool = True
    web_search_enabled: bool = True
    use_gpu: bool = True
    system_prompt: str = WEB_SEARCH_AGENT_SYSTEM_PROMPT

    @classmethod
    def from_env(cls) -> "AgentConfig":
        return cls(
            backend=os.getenv("AI_AGENT_BACKEND", "huggingface"),
            model=os.getenv("AI_AGENT_MODEL", "mistralai/Mistral-7B-Instruct-v0.2"),
            base_url=os.getenv("AI_AGENT_BASE_URL", ""),
            api_key=os.getenv("AI_AGENT_API_KEY", os.getenv("HF_TOKEN", "")),
            temperature=float(os.getenv("AI_AGENT_TEMPERATURE", "0.3")),
            max_tokens=int(os.getenv("AI_AGENT_MAX_TOKENS", "2048")),
            max_iterations=int(os.getenv("AI_AGENT_MAX_ITERATIONS", "10")),
            rag_enabled=os.getenv("AI_AGENT_RAG", "true").lower() == "true",
            web_search_enabled=os.getenv("AI_AGENT_WEB_SEARCH", "true").lower() == "true",
        )


# =============================================================================
# LLM Backend
# =============================================================================


class HFLocalBackend:
    """Local Hugging Face model backend (runs on GPU/CPU)."""

    def __init__(self, model_name: str, use_gpu: bool = True) -> None:
        self.model_name = model_name
        self.use_gpu = use_gpu
        self._pipe = None

    def _load(self) -> Any:
        if self._pipe is not None:
            return self._pipe
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer
            from transformers import pipeline

            device = 0 if self.use_gpu else -1
            self._pipe = pipeline(
                "text-generation",
                model=self.model_name,
                device=device,
                torch_dtype="auto",
            )
            return self._pipe
        except ImportError:
            logger.warning("transformers not installed; using API backend")
            return None

    def generate(self, prompt: str, temperature: float, max_tokens: int) -> str:
        pipe = self._load()
        if pipe is None:
            return ""
        result = pipe(
            prompt,
            max_new_tokens=max_tokens,
            temperature=temperature,
            do_sample=True,
        )
        return result[0]["generated_text"][len(prompt):]


class HFAPIBackend:
    """Hugging Face Inference API backend."""

    def __init__(self, model: str, api_key: str) -> None:
        self.model = model
        self.api_key = api_key

    def generate(self, prompt: str, temperature: float, max_tokens: int) -> str:
        import requests

        url = f"https://router.huggingface.co/hf-inference/models/{self.model}"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        payload = {
            "inputs": prompt,
            "parameters": {
                "temperature": temperature,
                "max_new_tokens": max_tokens,
                "return_full_text": False,
            },
        }
        resp = requests.post(url, headers=headers, json=payload, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list) and data:
            return data[0].get("generated_text", "")
        return str(data)


class OllamaBackend:
    """Ollama local backend."""

    def __init__(self, base_url: str, model: str) -> None:
        self.base_url = base_url or "http://localhost:11434/v1"
        self.model = model

    def generate(self, prompt: str, temperature: float, max_tokens: int) -> str:
        import requests

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        resp = requests.post(
            f"{self.base_url.replace('/v1', '')}/api/generate",
            json=payload,
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json().get("response", "")


class LLMBackend:
    """Unified LLM backend with automatic fallback."""

    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self._backend: Any = None
        self._setup()

    def _setup(self) -> None:
        backend = self.config.backend.lower()
        if backend == "huggingface":
            if self.config.api_key:
                self._backend = HFAPIBackend(self.config.model, self.config.api_key)
            else:
                self._backend = HFLocalBackend(self.config.model, self.config.use_gpu)
        elif backend == "ollama":
            self._backend = OllamaBackend(self.config.base_url, self.config.model)
        elif backend == "offline":
            self._backend = None
        else:
            self._backend = None

    def generate(self, prompt: str, system: str = "") -> str:
        full_prompt = f"{system}\n\n{prompt}" if system else prompt
        try:
            if self._backend is not None:
                return self._backend.generate(
                    full_prompt,
                    self.config.temperature,
                    self.config.max_tokens,
                )
        except Exception:
            logger.exception("LLM generation failed")
        return ""


# =============================================================================
# JSON Decision Parser
# =============================================================================


class DecisionParser:
    """Parses LLM responses into structured decisions."""

    @staticmethod
    def parse(response: str) -> dict[str, Any]:
        """Extract a decision dict from raw LLM output."""
        # Try direct parse
        try:
            return json.loads(response)
        except Exception:
            pass

        # Try brace extraction
        start = response.find("{")
        end = response.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(response[start : end + 1])
            except Exception:
                pass

        # Try to find action keywords (tool actions first, then control)
        for action in (
            "web_search",
            "search_and_fetch",
            "search_cve",
            "search_exploit",
            "fetch",
            "run_command",
            "analyze",
            "answer",
            "search",
            "done",
            "finding",
            "think",
        ):
            if action in response.lower():
                return {"action": action, "raw": response.strip()}

        return {"action": "think", "reasoning": response.strip()}


# =============================================================================
# AI Agent Core
# =============================================================================


class AIAgent:
    """The autonomous AI agent that thinks, analyzes, and acts."""

    def __init__(self, config: AgentConfig | None = None) -> None:
        self.config = config or AgentConfig.from_env()
        self.llm = LLMBackend(self.config)

        # Optional components (lazy-loaded to avoid hard deps)
        self.rag: Any = None
        self.web_search: Any = None

        if self.config.rag_enabled:
            from ai_agent.adaptive_rag import AdaptiveRAG

            self.rag = AdaptiveRAG()
        if self.config.web_search_enabled:
            from ai_agent.web_search import WebSearch

            self.web_search = WebSearch()

        self._history: list[dict[str, Any]] = []
        self._callbacks: list[Callable[[dict[str, Any]], None]] = []
        # Evidence grounding state for the tool-calling loop
        self._sources: list[dict[str, Any]] = []
        self._tool_calls: list[dict[str, Any]] = []

    # -- event system --------------------------------------------------------

    def on_event(self, callback: Callable[[dict[str, Any]], None]) -> None:
        self._callbacks.append(callback)

    def _emit(self, event: dict[str, Any]) -> None:
        for cb in self._callbacks:
            try:
                cb(event)
            except Exception:
                logger.exception("event callback failed")

    # -- public API ----------------------------------------------------------

    def think(self, task: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        """Think about a task and produce a decision.

        Returns:
            A dict with keys: action, command, reasoning, finding.
        """
        context = context or {}

        # 1. Check RAG memory for relevant past experience
        rag_context = ""
        if self.rag is not None:
            results = self.rag.search(task)
            if results:
                rag_context = "Past experience:\n" + "\n".join(
                    f"- {r.get('content', '')[:200]}" for r in results[:3]
                )

        # 2. Build the prompt (web intelligence is fetched via TOOL CALLS,
        #    not injected here, so the model controls the search flow)
        prompt = (
            f"TASK: {task}\n\n"
            f"Context: {json.dumps(context, default=str)[:2000]}\n\n"
        )
        if rag_context:
            prompt += f"{rag_context}\n\n"
        prompt += (
            "You work in a Thought -> Action -> Observation loop to answer the task using real evidence.\n"
            "Only answer from retrieved sources. Call ONE tool per turn whenever you need evidence.\n"
            "Available actions (respond in JSON):\n"
            '{"action":"web_search","query":"...","max_results":8}\n'
            '{"action":"search_and_fetch","query":"...","max_results":5}\n'
            '{"action":"search_cve","cve":"CVE-2024-..."}\n'
            '{"action":"search_exploit","software":"...","version":"..."}\n'
            '{"action":"fetch","url":"https://..."}\n'
            '{"action":"run_command","command":"..."}\n'
            '{"action":"finding","type":"...","severity":"...","description":"..."}\n'
            '{"action":"answer","answer":"...","confidence":"high|medium|low",'
            '"key_points":[{"point":"...","confidence":"high","sources":["https://..."]}],'
            '"limitations":[...]}\n'
            '{"action":"done","summary":"..."}\n'
            "Rules:\n"
            "- Do NOT produce a final answer for a research question unless you have retrieved sources "
            "(call web_search / search_and_fetch first).\n"
            "- If search results are weak or empty, call web_search again with a rewritten, more specific query.\n"
            "- For every claim include the source URL(s).\n"
            "- When you have enough evidence, respond with a single {\"action\":\"answer\", ...} that includes citations.\n"
        )

        # Emit thinking event
        self._emit({"type": "thinking", "task": task})

        # 4. Get LLM response
        response = self.llm.generate(prompt, self.config.system_prompt)
        if not response:
            return {"action": "think", "reasoning": "LLM unavailable", "response": ""}

        # 5. Parse decision
        decision = DecisionParser.parse(response)
        decision["response"] = response
        decision["timestamp"] = time.time()

        # 6. Store in history and RAG
        self._history.append({"task": task, "decision": decision})
        if self.rag is not None:
            self.rag.store(
                content=f"Task: {task}\nDecision: {json.dumps(decision, default=str)[:500]}",
                category="thinking",
                metadata={"task": task},
            )

        self._emit({"type": "decision", "decision": decision})
        return decision

    def analyze(self, data: Any, prompt: str) -> dict[str, Any]:
        """Analyze data (e.g. scan results, web pages)."""
        text_data = str(data)[:4000]
        analysis_prompt = (
            f"{prompt}\n\n"
            f"DATA TO ANALYZE:\n{text_data}\n\n"
            "Respond with JSON: "
            '{"summary": "...", "findings": ["..."], "risks": ["..."], "recommendations": ["..."]}'
        )
        response = self.llm.generate(analysis_prompt)
        return DecisionParser.parse(response) if response else {"summary": "No analysis available"}

    def execute_command(self, command: str) -> dict[str, Any]:
        """Execute a system command safely and capture output."""
        import subprocess

        self._emit({"type": "command", "command": command})
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=60,
            )
            output = {
                "command": command,
                "stdout": result.stdout[:3000],
                "stderr": result.stderr[:1000],
                "return_code": result.returncode,
            }
            if self.rag is not None:
                self.rag.store(
                    content=f"Command: {command}\nResult: {result.returncode}\n{result.stdout[:500]}",
                    category="commands",
                    metadata={"command": command, "success": result.returncode == 0},
                )
            return output
        except subprocess.TimeoutExpired:
            return {"command": command, "error": "timeout", "return_code": -2}
        except Exception as exc:
            return {"command": command, "error": str(exc), "return_code": -1}

    def run(self, task: str) -> list[dict[str, Any]]:
        """Run the agent on a task with the full ReAct loop."""
        findings: list[dict[str, Any]] = []
        current_task = task

        for iteration in range(self.config.max_iterations):
            self._emit({"type": "iteration", "iteration": iteration + 1})

            decision = self.think(
                current_task,
                {"iteration": iteration, "findings_so_far": findings[-5:]},
            )

            action = decision.get("action", "think")

            if action == "run_command":
                output = self.execute_command(decision.get("command", ""))
                current_task = (
                    f"Task: {task}\n"
                    f"Command executed: {decision.get('command', '')}\n"
                    f"Output: {json.dumps(output, default=str)[:1500]}\n\n"
                    "Analyze the output and decide the next action."
                )
            elif action == "search":
                if self.web_search is not None:
                    results = self.web_search.search(decision.get("query", ""))
                    current_task = (
                        f"Task: {task}\n"
                        f"Search results: {json.dumps(results, default=str)[:1500]}\n\n"
                        "Analyze the results and decide the next action."
                    )
                else:
                    current_task = task
            elif action == "finding":
                findings.append(
                    {
                        "type": decision.get("type", "info"),
                        "severity": decision.get("severity", "info"),
                        "description": decision.get("description", ""),
                        "confidence": decision.get("confidence", 0.5),
                    }
                )
                if self.rag is not None:
                    self.rag.store(
                        content=decision.get("description", ""),
                        category="findings",
                        metadata={"severity": decision.get("severity", "info")},
                    )
            elif action == "done":
                break

        return findings

    def status(self) -> dict[str, Any]:
        return {
            "backend": self.config.backend,
            "model": self.config.model,
            "rag_enabled": self.config.rag_enabled,
            "web_search_enabled": self.config.web_search_enabled,
            "history_length": len(self._history),
        }