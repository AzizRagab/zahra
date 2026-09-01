"""ChromaDB wrapper for Adaptive RAG system.

This module provides a vector database for storing and retrieving:
- Successful commands
- Payloads
- Evasion techniques
- CVE information
- Past experiences

The RAG system learns from every campaign and gets smarter over time.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

logger = logging.getLogger("zahra.core.rag_system")

# Try to import chromadb
try:
    import chromadb  # type: ignore
    from chromadb.config import Settings  # type: ignore
    CHROMADB_AVAILABLE = True
except ImportError:
    CHROMADB_AVAILABLE = False
    logger.warning("chromadb not installed. RAG system will use fallback mode.")


@dataclass
class RAGDocument:
    """A document stored in the RAG system."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    content: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    embedding: list[float] | None = None
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "content": self.content,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
        }


class ChromaDBWrapper:
    """Wrapper for ChromaDB vector database."""
    
    def __init__(self, persist_directory: str = "zahra_data/chromadb") -> None:
        """Initialize ChromaDB wrapper.
        
        Args:
            persist_directory: Directory to persist the database
        """
        self.persist_directory = persist_directory
        self.client = None
        self.collections: dict[str, Any] = {}
        
        if CHROMADB_AVAILABLE:
            self._initialize()
    
    def _initialize(self) -> None:
        """Initialize ChromaDB client and collections."""
        try:
            self.client = chromadb.PersistentClient(path=self.persist_directory)
            
            # Create collections for different types of knowledge
            self.collections = {
                "commands": self.client.get_or_create_collection(
                    name="commands",
                    metadata={"description": "Successful pentest commands"}
                ),
                "payloads": self.client.get_or_create_collection(
                    name="payloads",
                    metadata={"description": "Exploit payloads and techniques"}
                ),
                "evasions": self.client.get_or_create_collection(
                    name="evasions",
                    metadata={"description": "Evasion techniques that worked"}
                ),
                "cves": self.client.get_or_create_collection(
                    name="cves",
                    metadata={"description": "CVE information and exploits"}
                ),
                "findings": self.client.get_or_create_collection(
                    name="findings",
                    metadata={"description": "Past findings and lessons learned"}
                ),
            }
            
            logger.info("ChromaDB initialized with %d collections", len(self.collections))
        except Exception as exc:
            logger.error("Failed to initialize ChromaDB: %s", exc)
            self.client = None
    
    def add_document(self, collection_name: str, document: RAGDocument) -> bool:
        """Add a document to a collection.
        
        Args:
            collection_name: Name of the collection
            document: Document to add
            
        Returns:
            True if successful
        """
        if not self.client:
            return False
        
        try:
            collection = self.collections.get(collection_name)
            if not collection:
                return False
            
            collection.add(
                documents=[document.content],
                metadatas=[document.metadata],
                ids=[document.id],
            )
            
            logger.debug("Added document to %s: %s", collection_name, document.id)
            return True
        except Exception as exc:
            logger.error("Failed to add document: %s", exc)
            return False
    
    def query(self, collection_name: str, query_text: str, n_results: int = 5) -> list[dict[str, Any]]:
        """Query a collection for similar documents.
        
        Args:
            collection_name: Name of the collection
            query_text: Query text
            n_results: Number of results to return
            
        Returns:
            List of similar documents
        """
        if not self.client:
            return []
        
        try:
            collection = self.collections.get(collection_name)
            if not collection:
                return []
            
            results = collection.query(
                query_texts=[query_text],
                n_results=n_results,
            )
            
            # Format results
            documents = []
            if results and results.get("documents"):
                for i, doc in enumerate(results["documents"][0]):
                    documents.append({
                        "content": doc,
                        "metadata": results["metadatas"][0][i] if results.get("metadatas") else {},
                        "distance": results["distances"][0][i] if results.get("distances") else 0.0,
                    })
            
            return documents
        except Exception as exc:
            logger.error("Failed to query collection: %s", exc)
            return []
    
    def record_command(self, command: str, success: bool, context: dict[str, Any]) -> None:
        """Record a command execution in the RAG system.
        
        Args:
            command: Command that was executed
            success: Whether it succeeded
            context: Execution context
        """
        doc = RAGDocument(
            content=command,
            metadata={
                "success": success,
                "timestamp": datetime.now().isoformat(),
                **context,
            },
        )
        self.add_document("commands", doc)
    
    def record_evasion(self, technique: str, target: str, agent: str, waf: str, success: bool) -> None:
        """Record an evasion technique.
        
        Args:
            technique: Evasion technique used
            target: Target host
            agent: Agent that used it
            waf: WAF/blocker that was evaded
            success: Whether it worked
        """
        doc = RAGDocument(
            content=technique,
            metadata={
                "target": target,
                "agent": agent,
                "waf": waf,
                "success": success,
                "timestamp": datetime.now().isoformat(),
            },
        )
        self.add_document("evasions", doc)
    
    def find_evasion_for(self, error: str) -> str | None:
        """Find a past evasion technique for a similar error.
        
        Args:
            error: Error message or blocked command
            
        Returns:
            Evasion technique or None
        """
        results = self.query("evasions", error, n_results=1)
        if results and results[0].get("metadata", {}).get("success"):
            return results[0]["content"]
        return None
    
    def record_cve(self, cve_id: str, description: str, exploit: str) -> None:
        """Record CVE information.
        
        Args:
            cve_id: CVE identifier
            description: CVE description
            exploit: Exploit code or technique
        """
        doc = RAGDocument(
            content=f"{cve_id}: {description}\n{exploit}",
            metadata={
                "cve_id": cve_id,
                "timestamp": datetime.now().isoformat(),
            },
        )
        self.add_document("cves", doc)
    
    def record_finding(self, finding: dict[str, Any]) -> None:
        """Record a finding for future reference.
        
        Args:
            finding: Finding dictionary
        """
        doc = RAGDocument(
            content=finding.get("description", ""),
            metadata={
                "type": finding.get("type", "unknown"),
                "severity": finding.get("severity", "info"),
                "confidence": finding.get("confidence", 0.0),
                "timestamp": datetime.now().isoformat(),
            },
        )
        self.add_document("findings", doc)
    
    def get_stats(self) -> dict[str, int]:
        """Get statistics about the RAG system."""
        if not self.client:
            return {}
        
        stats = {}
        for name, collection in self.collections.items():
            try:
                stats[name] = collection.count()
            except Exception:
                stats[name] = 0
        return stats


class FallbackRAG:
    """Fallback RAG system when ChromaDB is not available."""
    
    def __init__(self) -> None:
        """Initialize fallback RAG."""
        self.commands: list[dict[str, Any]] = []
        self.evasions: list[dict[str, Any]] = []
        self.cves: list[dict[str, Any]] = []
        self.findings: list[dict[str, Any]] = []
    
    def record_command(self, command: str, success: bool, context: dict[str, Any]) -> None:
        """Record a command."""
        self.commands.append({
            "command": command,
            "success": success,
            "context": context,
        })
    
    def record_evasion(self, technique: str, target: str, agent: str, waf: str, success: bool) -> None:
        """Record an evasion technique."""
        self.evasions.append({
            "technique": technique,
            "target": target,
            "agent": agent,
            "waf": waf,
            "success": success,
        })
    
    def find_evasion_for(self, error: str) -> str | None:
        """Find a past evasion technique."""
        for evasion in self.evasions:
            if evasion.get("success") and error.lower() in evasion.get("technique", "").lower():
                return evasion["technique"]
        return None
    
    def record_cve(self, cve_id: str, description: str, exploit: str) -> None:
        """Record CVE information."""
        self.cves.append({
            "cve_id": cve_id,
            "description": description,
            "exploit": exploit,
        })
    
    def record_finding(self, finding: dict[str, Any]) -> None:
        """Record a finding."""
        self.findings.append(finding)
    
    def get_stats(self) -> dict[str, int]:
        """Get statistics."""
        return {
            "commands": len(self.commands),
            "evasions": len(self.evasions),
            "cves": len(self.cves),
            "findings": len(self.findings),
        }


# Factory function
def create_rag_system(persist_directory: str = "zahra_data/chromadb") -> ChromaDBWrapper | FallbackRAG:
    """Create a RAG system (ChromaDB if available, otherwise fallback).
    
    Args:
        persist_directory: Directory to persist the database
        
    Returns:
        RAG system instance
    """
    if CHROMADB_AVAILABLE:
        return ChromaDBWrapper(persist_directory)
    else:
        logger.warning("Using fallback RAG system (ChromaDB not available)")
        return FallbackRAG()