# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-08-31

### Added

- **Adaptive RAG brain** — every finding, command, and evasion technique is
  stored in a vector database (ChromaDB) and reused across campaigns.
- **Multi-agent swarm** — Recon, Scan, Exploit, C2, and MITM agents coordinated
  on a stigmergic blackboard with pheromone-weighted findings.
- **ZahraController** — operator-directed controller orchestrating the
  LLM wrapper, blackboard, event emitter, agentic core, skills, swarm manager,
  router, memory, database, and orchestrator.
- **Multi-backend LLM wrapper** — Ollama (default `zahra` model),
  OpenAI-compatible endpoints, and offline RAG-only mode.
- **Web dashboard** — login/signup, live agent cards, real-time activity feed,
  intelligence search (RAG + OSINT), campaign tracking, and chat over WebSocket.
- **Cross-platform support** — one-shot installers for Windows
  (`install.ps1`), Kali Linux, and Ubuntu (`install.sh`,
  `install-kali.sh`, `install-ubuntu.sh`).
- **Merged monorepo** — Pentest-Swarm-AI (Go reference implementation) under
  `services/pentest-swarm/` and the OmniRoute LLM gateway (Node) under
  `services/omniroute/`, wired together over HTTP.

### Changed

- CLI, launcher, and start scripts standardized for consistent output across
  operating systems.

### Fixed

- UTF-8 output handling on Windows consoles.
