"""Configuration for the Zahra operator-directed controller.

The ZahraController is a personal, operator-directed controller that:
- Operates WITHOUT LLaMA (uses Mistral, Gemma, Phi, Qwen, etc.)
- Runs in autonomous execution mode for OPERATOR-AUTHORIZED security
  engagements; the operator remains responsible for scope and legality
- Is named **zahra** after **Amshararou**

Key design decisions:
- LLaMA model identifiers are explicitly blocklisted; the controller
  will refuse to use them and fall back to a safe non-LLaMA model.
- The controller is designed for authorized engagements only. Execution
  limits (iterations, budgets) are operator-configurable and may be set
  high for long-running authorized assessments.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ai_engine.llm_wrapper import LLMConfig

logger = logging.getLogger("zahra.core.zahra_config")


# ── LLaMA model identifiers to explicitly EXCLUDE ───────────────────────────

LLAMA_PATTERNS: tuple[str, ...] = (
    "llama",
    "llama2",
    "llama3",
    "llama.cpp",
    "meta-llama",
    "meta/llama",
    "tulu",        # fine-tunes of LLaMA
    "vicuna",      # fine-tunes of LLaMA
    "alpaca",      # fine-tunes of LLaMA
    "phind",       # fine-tunes of LLaMA
    "koala",
    "open assistant",
    "open-assistant",
    "baize",
    "wizard-vicuna",
    "wizard-lama",
    "med-lama",
    "mlewd",
    "openllama",
    "xwin",
    "llamaguard",
    "llama-guard",
)


# ── Preferred NON-LLaMA models (tried in order) ─────────────────────────────

NON_LLAMA_MODELS: tuple[str, ...] = (
    "dolphin-mistral",
    "mistralai/Mistral-7B-Instruct-v0.2",
    "mistralai/Mixtral-8x7B-Instruct-v0.1",
    "google/gemma-7b-it",
    "google/gemma-2b-it",
    "microsoft/Phi-3-mini-4k-instruct",
    "microsoft/phi-2",
    "Qwen/Qwen1.5-7B-Chat",
    "Qwen/Qwen1.5-14B-Chat",
    "openchat/openchat-3.5-0106",
    "teknium/OpenHermes-2.5-Mistral-7B",
    "TheBloke/dolphin-2.6-mistral-7B-dpo",
)


def is_llama_model(model_name: str) -> bool:
    """Return True if *model_name* is a LLaMA-derived model.

    The check is case-insensitive and covers base models, fine-tunes,
    and common variants (vicuna, alpaca, tulu, koala, etc.).
    """
    if not model_name:
        return False
    model_lower = model_name.lower()
    return any(pat in model_lower for pat in LLAMA_PATTERNS)


def select_non_llama_model(model_name: str = "") -> str:
    """Return a safe non-LLaMA model.

    If *model_name* is non-empty and not LLaMA, it is returned as-is.
    Otherwise the first entry from :data:`NON_LLAMA_MODELS` is returned.
    """
    if model_name and not is_llama_model(model_name):
        return model_name
    safe = NON_LLAMA_MODELS[0]
    if model_name:
        logger.warning(
            "Model '%s' is a LLaMA model or empty — refusing to use LLaMA. "
            "Selected fallback: '%s'",
            model_name,
            safe,
        )
    return safe


# ── Data classes ────────────────────────────────────────────────────────────


@dataclass
class LLMSettings:
    """LLM backend configuration for the ZahraController."""

    backend: str = "offline"
    model: str = ""
    base_url: str = ""
    api_key: str = ""
    temperature: float = 0.7
    max_tokens: int = 4096
    timeout: int = 120

    def validate(self) -> str:
        """Validate that this config does not use LLaMA.

        If a LLaMA model is detected the model field is overwritten with
        a safe non-LLaMA fallback and that fallback is returned.
        """
        if self.model and is_llama_model(self.model):
            safe = select_non_llama_model("")
            logger.warning(
                "LLaMA model '%s' detected — refusing to use LLaMA.  "
                "Falling back to '%s'.",
                self.model,
                safe,
            )
            self.model = safe
        return self.model


@dataclass
class UnrestrictedSettings:
    """Execution-mode settings for autonomous, operator-directed campaigns.

    These flags configure how autonomously the swarm runs during an
    authorized engagement (e.g. long-running assessments may use large
    budgets). They do not grant legal or ethical authorization — operators
    remain responsible for targeting only systems they are allowed to test.
    """

    max_iterations: int = 1000
    max_tokens_budget: int = 999_999_999
    max_agent_hours: float = 999_999.0
    authorized_engagement: bool = True
    allow_all_tools: bool = True
    auto_evasion_attempts: int = 10
    bypass_rate_limits: bool = True
    persistent_execution: bool = True
    no_target_restrictions: bool = True
    no_tool_restrictions: bool = True
    no_output_filters: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Convert to a plain dict."""
        return {
            "max_iterations": self.max_iterations,
            "max_tokens_budget": self.max_tokens_budget,
            "max_agent_hours": self.max_agent_hours,
            "authorized_engagement": self.authorized_engagement,
            "allow_all_tools": self.allow_all_tools,
            "auto_evasion_attempts": self.auto_evasion_attempts,
            "bypass_rate_limits": self.bypass_rate_limits,
            "persistent_execution": self.persistent_execution,
            "no_target_restrictions": self.no_target_restrictions,
            "no_tool_restrictions": self.no_tool_restrictions,
            "no_output_filters": self.no_output_filters,
        }


@dataclass
class Personalization:
    """Personal settings for the ZahraController (personalized for the user)."""

    user_name: str = "operator"
    preferred_tools: list[str] = field(default_factory=list)
    target_allowlist: list[str] = field(default_factory=list)
    target_denylist: list[str] = field(default_factory=list)
    custom_system_prompt: str = ""
    personal_rag: bool = True


@dataclass
class ZahraConfig:
    """Complete configuration for the Zahra personal controller.

    Attributes:
        name: Controller name — always ``"zahra"``.
        version: Controller version string.
        attribution: Name the controller is attributed to —
            ``"Amshararou"``.
        mode: Operating mode — execution profile for authorized engagements.
        llm: LLM backend settings (validated to reject LLaMA).
        unrestricted: Autonomous-execution settings (operator-configurable).
        personalization: Personal / operator-specific settings.
        config_path: Path to the JSON config file on disk.
    """

    name: str = "zahra"
    version: str = "1.0.0"
    attribution: str = "Amshararou"
    mode: str = "authorized"
    llm: LLMSettings = field(default_factory=LLMSettings)
    unrestricted: UnrestrictedSettings = field(default_factory=UnrestrictedSettings)
    personalization: Personalization = field(default_factory=Personalization)
    config_path: str = ""

    # ── loaders ──────────────────────────────────────────────────────────

    @classmethod
    def from_file(cls, path: str | Path) -> "ZahraConfig":
        """Load configuration from a JSON file."""
        path = Path(path)
        config = cls(config_path=str(path))

        if not path.exists():
            logger.info("Config file %s not found; using defaults", path)
            # Save a default config so the user can edit it
            config.save(path)
            return config

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            config.name = data.get("name", "zahra")
            config.version = data.get("version", "1.0.0")
            config.attribution = data.get("attribution", "Amshararou")
            config.mode = data.get("mode", "authorized")

            llm_data = data.get("llm", {})
            config.llm = LLMSettings(
                backend=llm_data.get("backend", "offline"),
                model=llm_data.get("model", ""),
                base_url=llm_data.get("base_url", ""),
                api_key=llm_data.get("api_key", ""),
                temperature=llm_data.get("temperature", 0.7),
                max_tokens=llm_data.get("max_tokens", 4096),
                timeout=llm_data.get("timeout", 120),
            )

            ur_data = data.get("unrestricted", {})
            config.unrestricted = UnrestrictedSettings(
                max_iterations=ur_data.get("max_iterations", 1000),
                max_tokens_budget=ur_data.get("max_tokens_budget", 999_999_999),
                max_agent_hours=ur_data.get("max_agent_hours", 999_999.0),
                authorized_engagement=ur_data.get(
                    "authorized_engagement",
                    # Legacy key (older config files); kept for compatibility.
                    ur_data.get("no_ethical_constraints", True),
                ),
                allow_all_tools=ur_data.get("allow_all_tools", True),
                auto_evasion_attempts=ur_data.get("auto_evasion_attempts", 10),
                bypass_rate_limits=ur_data.get("bypass_rate_limits", True),
                persistent_execution=ur_data.get("persistent_execution", True),
                no_target_restrictions=ur_data.get("no_target_restrictions", True),
                no_tool_restrictions=ur_data.get("no_tool_restrictions", True),
                no_output_filters=ur_data.get("no_output_filters", True),
            )

            pers_data = data.get("personalization", {})
            config.personalization = Personalization(
                user_name=pers_data.get("user_name", "operator"),
                preferred_tools=list(pers_data.get("preferred_tools") or []),
                target_allowlist=list(pers_data.get("target_allowlist") or []),
                target_denylist=list(pers_data.get("target_denylist") or []),
                custom_system_prompt=pers_data.get("custom_system_prompt", ""),
                personal_rag=pers_data.get("personal_rag", True),
            )

            # Enforce no-LLaMA policy
            config.llm.validate()

            logger.info("Loaded ZahraController config from %s", path)
        except Exception:
            logger.exception("Failed to load config from %s; using defaults", path)
            config.save(path)

        return config

    @classmethod
    def from_env(cls) -> "ZahraConfig":
        """Load configuration from environment variables."""
        config_path = os.getenv(
            "ZAHRA_CONTROLLER_CONFIG", ""
        )
        # If not set, default to ~/.zahra_data/zahra_config.json for global installs
        if not config_path:
            home = Path.home() / ".zahra_data"
            config_path = str(home / "zahra_config.json")
        path = Path(config_path)
        if path.exists():
            return cls.from_file(path)

        # Fall back to environment overrides on top of defaults
        llm_model = os.getenv("ZAHRA_LLM_MODEL", "zahra")
        if llm_model and is_llama_model(llm_model):
            llm_model = select_non_llama_model("")

        config = cls(
            config_path=config_path,
            llm=LLMSettings(
                backend=os.getenv("ZAHRA_LLM_BACKEND", "ollama"),
                model=llm_model,
                base_url=os.getenv("ZAHRA_LLM_BASE_URL", "http://localhost:11434/v1"),
                api_key=os.getenv("ZAHRA_LLM_API_KEY", ""),
                temperature=float(os.getenv("ZAHRA_LLM_TEMPERATURE", "0.7")),
                max_tokens=int(os.getenv("ZAHRA_LLM_MAX_TOKENS", "4096")),
                timeout=int(os.getenv("ZAHRA_LLM_TIMEOUT", "120")),
            ),
            personalization=Personalization(
                user_name=os.getenv("ZAHRA_USER_NAME", "operator"),
            ),
        )
        config.llm.validate()
        return config

    # ── persistence ────────────────────────────────────────────────────

    def save(self, path: str | Path | None = None) -> None:
        """Persist the configuration to a JSON file."""
        path = Path(path) if path else Path(self.config_path or "zahra_data/zahra_config.json")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            logger.info("Saved ZahraController config to %s", path)
        except Exception:
            logger.exception("Failed to save config to %s", path)

    # ── conversion ────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Convert to a plain dict (suitable for JSON serialization)."""
        return {
            "name": self.name,
            "version": self.version,
            "attribution": self.attribution,
            "mode": self.mode,
            "llm": {
                "backend": self.llm.backend,
                "model": self.llm.model,
                "base_url": self.llm.base_url,
                "temperature": self.llm.temperature,
                "max_tokens": self.llm.max_tokens,
                "timeout": self.llm.timeout,
            },
            "unrestricted": {
                "max_iterations": self.unrestricted.max_iterations,
                "max_tokens_budget": self.unrestricted.max_tokens_budget,
                "max_agent_hours": self.unrestricted.max_agent_hours,
                "authorized_engagement": self.unrestricted.authorized_engagement,
                "allow_all_tools": self.unrestricted.allow_all_tools,
                "auto_evasion_attempts": self.unrestricted.auto_evasion_attempts,
                "bypass_rate_limits": self.unrestricted.bypass_rate_limits,
                "persistent_execution": self.unrestricted.persistent_execution,
                "no_target_restrictions": self.unrestricted.no_target_restrictions,
                "no_tool_restrictions": self.unrestricted.no_tool_restrictions,
                "no_output_filters": self.unrestricted.no_output_filters,
            },
            "personalization": {
                "user_name": self.personalization.user_name,
                "preferred_tools": self.personalization.preferred_tools,
                "target_allowlist": self.personalization.target_allowlist,
                "target_denylist": self.personalization.target_denylist,
                "custom_system_prompt": self.personalization.custom_system_prompt,
                "personal_rag": self.personalization.personal_rag,
            },
        }

    def to_llm_config(self) -> "LLMConfig":
        """Convert LLM settings to an :class:`LLMConfig` for ``LLMWrapper``."""
        from ai_engine.llm_wrapper import LLMConfig as _LLMConfig

        cfg: "_LLMConfig" = _LLMConfig(
            backend=self.llm.backend,
            base_url=self.llm.base_url,
            api_key=self.llm.api_key,
            model=self.llm.model,
            temperature=self.llm.temperature,
            max_tokens=self.llm.max_tokens,
            timeout=self.llm.timeout,
        )
        return cfg
