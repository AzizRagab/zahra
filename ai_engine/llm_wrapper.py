"""LLM wrapper — unified interface to Open WebUI, Hugging Face, and Ollama.

Inspired by Pentest-Swarm-AI's ``llm/provider.go`` Provider interface.
The wrapper abstracts away the differences between LLM backends so agents
and the router can talk to any model with a single API.

Supported backends:
* **Open WebUI** — local Open WebUI instance (OpenAI-compatible API)
* **Hugging Face** — HF Inference API
* **Ollama** — local Ollama instance
* **OpenAI** — direct OpenAI API (also works for any OpenAI-compatible endpoint)

If no backend is configured, the wrapper operates in **offline mode** —
it returns canned responses so the platform is usable for testing
without an LLM.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("zahra.ai_engine.llm")


@dataclass
class LLMConfig:
    """Configuration for the LLM wrapper.

    Attributes:
        backend: Which backend to use — ``openwebui``, ``huggingface``,
            ``ollama``, ``openai``, or ``offline``.
        base_url: Base URL of the LLM API.
        api_key: API key (if required).
        model: Model name to use.
        temperature: Sampling temperature (0.0 – 1.0).
        max_tokens: Maximum tokens to generate.
        timeout: Request timeout in seconds.
    """

    backend: str = "offline"
    base_url: str = ""
    api_key: str = ""
    model: str = "zahra-ai"
    temperature: float = 0.7
    max_tokens: int = 2048
    timeout: int = 60

    @classmethod
    def from_env(cls) -> "LLMConfig":
        """Load config from environment variables."""
        return cls(
            backend=os.getenv("ZAHRA_LLM_BACKEND", "offline"),
            base_url=os.getenv("ZAHRA_LLM_BASE_URL", ""),
            api_key=os.getenv("ZAHRA_LLM_API_KEY", ""),
            model=os.getenv("ZAHRA_LLM_MODEL", ""),
            temperature=float(os.getenv("ZAHRA_LLM_TEMPERATURE", "0.7")),
            max_tokens=int(os.getenv("ZAHRA_LLM_MAX_TOKENS", "2048")),
            timeout=int(os.getenv("ZAHRA_LLM_TIMEOUT", "60")),
        )


class LLMWrapper:
    """Unified LLM interface for the zahra platform.

    The wrapper provides a single :meth:`complete` method that works
    regardless of the configured backend. It also exposes
    :meth:`health_check` for the orchestrator's startup diagnostics.
    """

    def __init__(self, config: LLMConfig | None = None) -> None:
        self.config = config or LLMConfig.from_env()
        self._client: Any = None
        self._setup()
        # LRU response cache — identical prompts never hit the network twice.
        # The swarm agents re-ask very similar questions in their loops, so
        # this makes long campaigns dramatically faster.
        self._cache: dict[str, tuple[str, float]] = {}
        self._cache_lock = threading.Lock()
        self._cache_max = 512
        self._cache_ttl = 60.0

    def _setup(self) -> None:
        """Initialize the backend client."""
        backend = self.config.backend.lower()

        if backend == "offline":
            logger.info("LLM wrapper in offline mode — no external calls")
            return

        if backend in ("openai", "openwebui"):
            try:
                import openai

                self._client = openai.OpenAI(
                    base_url=self.config.base_url or None,
                    api_key=self.config.api_key or "dummy",
                    timeout=self.config.timeout,
                )
                logger.info("LLM wrapper: OpenAI-compatible backend (%s)", backend)
            except ImportError:
                logger.warning("openai package not installed; falling back to offline")
                self.config.backend = "offline"

        elif backend == "ollama":
            try:
                import openai

                self._client = openai.OpenAI(
                    base_url=self.config.base_url or "http://localhost:11434/v1",
                    api_key="ollama",
                    timeout=self.config.timeout,
                )
                logger.info("LLM wrapper: Ollama backend")
            except ImportError:
                logger.warning("openai package not installed; falling back to offline")
                self.config.backend = "offline"

        elif backend == "huggingface":
            try:
                import requests

                self._client = requests.Session()
                if self.config.api_key:
                    self._client.headers["Authorization"] = f"Bearer {self.config.api_key}"
                logger.info("LLM wrapper: Hugging Face backend")
            except ImportError:
                logger.warning("requests package not installed; falling back to offline")
                self.config.backend = "offline"
        else:
            logger.warning("unknown backend '%s'; falling back to offline", backend)
            self.config.backend = "offline"

    # -- public API --------------------------------------------------------

    def complete(
        self,
        prompt: str,
        *,
        system: str = "",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        """Send a completion request and return the text response.

        Args:
            prompt: The user prompt.
            system: Optional system prompt.
            temperature: Override config temperature.
            max_tokens: Override config max_tokens.

        Returns:
            The LLM's text response.
        """
        temp = temperature if temperature is not None else self.config.temperature
        tokens = max_tokens if max_tokens is not None else self.config.max_tokens

        if self.config.backend == "offline":
            return self._offline_complete(prompt, system)
        if self._client is None:
            return self._offline_complete(prompt, system)

        # Cache lookup (fast path)
        key = f"{self.config.backend}|{self.config.model}|{temp}|{tokens}|{system}|{prompt}"
        now = time.time()
        with self._cache_lock:
            hit = self._cache.get(key)
            if hit and (now - hit[1]) < self._cache_ttl:
                return hit[0]

        try:
            if self.config.backend in ("openai", "openwebui", "ollama"):
                result = self._openai_complete(prompt, system, temp, tokens)
            elif self.config.backend == "huggingface":
                result = self._hf_complete(prompt, system, temp, tokens)
            else:
                result = self._offline_complete(prompt, system)
        except Exception:
            logger.exception("LLM completion failed; falling back to offline")
            return self._offline_complete(prompt, system)

        # Cache store (LRU eviction)
        if result:
            with self._cache_lock:
                if len(self._cache) >= self._cache_max:
                    oldest = min(self._cache, key=lambda k: self._cache[k][1])
                    self._cache.pop(oldest, None)
                self._cache[key] = (result, now)
        return result

    def health_check(self) -> bool:
        """Check if the LLM backend is reachable."""
        if self.config.backend == "offline":
            return True
        if self._client is None:
            return False
        try:
            if self.config.backend in ("openai", "openwebui", "ollama"):
                self._client.models.list()
                return True
            elif self.config.backend == "huggingface":
                resp = self._client.get(
                    f"{self.config.base_url}/health", timeout=5
                )
                return bool(resp.status_code == 200)
        except Exception:
            return False
        return False

    @property
    def model_name(self) -> str:
        return self.config.model or "offline"

    @property
    def is_offline(self) -> bool:
        return self.config.backend == "offline"

    # -- backend implementations ------------------------------------------

    def _openai_complete(
        self, prompt: str, system: str, temperature: float, max_tokens: int
    ) -> str:
        """OpenAI-compatible completion (works for OpenAI, Open WebUI, Ollama)."""
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        response = self._client.chat.completions.create(
            model=self.config.model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return response.choices[0].message.content or ""

    def _hf_complete(
        self, prompt: str, system: str, temperature: float, max_tokens: int
    ) -> str:
        """Hugging Face Inference API completion."""
        full_prompt = f"{system}\n\n{prompt}" if system else prompt
        url = f"{self.config.base_url}/models/{self.config.model}"
        payload = {
            "inputs": full_prompt,
            "parameters": {
                "temperature": temperature,
                "max_new_tokens": max_tokens,
                "return_full_text": False,
            },
        }
        resp = self._client.post(url, json=payload, timeout=self.config.timeout)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list) and data:
            generated = data[0].get("generated_text", "")
            return str(generated)
        return str(data)

    @staticmethod
    def _offline_complete(prompt: str, system: str) -> str:
        """Offline fallback — returns a canned response for testing.

        The response is deterministic and includes the prompt so tests
        can verify the pipeline end-to-end without an LLM.
        """
        return (
            f"[offline-mode] I would analyze this request:\n"
            f"---\n{prompt[:500]}\n---\n"
            f"This is a simulated response. Configure an LLM backend "
            f"(openwebui, huggingface, ollama, or openai) for real AI analysis."
        )