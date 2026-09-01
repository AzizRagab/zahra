"""AI Agent — Autonomous agent with Adaptive RAG, Web Search, and Hugging Face integration.

This module provides a complete AI agent system that:
1. Thinks and analyzes using LLM backends (Hugging Face, Ollama, OpenAI)
2. Learns adaptively via RAG (Retrieval-Augmented Generation)
3. Searches the web for real-time intelligence
4. Can be deployed to Hugging Face Spaces
"""

from ai_agent.agent_core import AIAgent, AgentConfig
from ai_agent.adaptive_rag import AdaptiveRAG
from ai_agent.web_search import WebSearch
from ai_agent.hf_integration import HFDeployer

__all__ = ["AIAgent", "AgentConfig", "AdaptiveRAG", "WebSearch", "HFDeployer"]