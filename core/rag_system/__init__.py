"""Adaptive RAG System for Zahra.

This module provides a growing brain that learns from every campaign:
- Stores successful commands, payloads, and evasion techniques
- Queries past experience before planning new actions
- Gets smarter with each campaign
"""

from .chromadb_wrapper import (
    CHROMADB_AVAILABLE,
    ChromaDBWrapper,
    FallbackRAG,
    RAGDocument,
    create_rag_system,
)

__all__ = [
    "CHROMADB_AVAILABLE",
    "ChromaDBWrapper",
    "FallbackRAG",
    "RAGDocument",
    "create_rag_system",
]