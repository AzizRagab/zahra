# 🐉 ZAHRA - Agentic Pentest System

<div align="center">

![Version](https://img.shields.io/badge/version-2.0.0-blue)
![Python](https://img.shields.io/badge/python-3.9%2B-green)
![License](https://img.shields.io/badge/license-MIT-red)
![Status](https://img.shields.io/badge/status-active-success)

**AI-Powered Penetration Testing Swarm Platform**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Architecture](#-architecture) • [Documentation](#-documentation)

</div>

---

## 🎯 What is ZAHRA?

ZAHRA is an **Agentic Pentest System** that uses AI to automate penetration testing. It's a swarm of intelligent agents that work together to:

- 🔍 **Reconnaissance** - Enumerate targets, discover services
- 🎯 **Vulnerability Scanning** - Find CVEs and misconfigurations
- 💥 **Exploitation** - Automatically exploit discovered vulnerabilities
- 🎮 **C2 Operations** - Command & Control, persistence, reverse shells
- 🕵️ **MITM Attacks** - Traffic interception, credential harvesting
- 🧠 **Learning** - Gets smarter with each campaign (RAG)
- 🚀 **Auto-Evasion** - Bypasses WAFs and rate limits automatically

### Key Differentiators

| Feature | ZAHRA | Traditional Tools |
|---------|-------|-------------------|
| **AI-Driven** | ✅ Autonomous agents | ❌ Manual configuration |
| **Learning** | ✅ Adaptive RAG | ❌ Static rules |
| **Coordination** | ✅ Swarm intelligence | ❌ Sequential scans |
| **Evasion** | ✅ Intelligent bypass | ❌ Basic techniques |
| **Interface** | ✅ CLI + API + Web UI | ❌ CLI only |

---

## ✨ Features

### 🤖 Agentic Core
- **Strategic Brain** - Coordinates the entire swarm
- **Task Distribution** - Assigns work to specialized agents
- **Phase Management** - Recon → Scan → Exploit → Report
- **RAG Learning** - Learns from past campaigns

### 🎓 Adaptive RAG System
- **Vector Database** - Stores commands, payloads, techniques
- **Experience Reuse** - Queries past successful attacks
- **Continuous Learning** - Gets smarter with each campaign
- **Evasion Memory** - Remembers what bypassed WAFs

### 🦾 Operator-Directed Autonomous Mode
- **Authorized-Only Execution** - Designed for engagements the operator is authorized to perform
- **ReAct Loop** - Thought → Action → Observation
- **Alternative Strategies** - Always tries different approaches
- **Adaptive Persistence** - Tries alternative strategies before reporting a block

### 🚀 Auto-Evasion
- **RAG-Based** - Learns from past evasion techniques
- **Heuristic** - Applies stealth flags automatically
- **Multi-Tool** - Switches tools when blocked
- **Smart Retry** - Maximum 2 attempts per block

### 🔍 Web Search & OSINT
- **CVE Discovery** - Searches for latest exploits
- **ExploitDB Integration** - Finds PoC code
- **OSINT Gathering** - Collects target intelligence
- **No API Required** - Uses DuckDuckGo

### 📊 Observability
- **Event System** - Real-time monitoring
- **WebSocket** - Live event streaming
- **Blackboard** - Shared findings board
- **Pheromones** - Decaying attention weights

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Interfaces                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │     CLI      │  │  REST API    │  │  Web Dashboard   │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                    Orchestrator                              │
│  - Campaign management                                       │
│  - Budget enforcement                                        │
│  - Agent coordination                                        │
└───────────────────────────┬─────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
┌───────▼────────┐  ┌──────▼──────┐  ┌────────▼────────┐
│ Agentic Core   │  │   Router    │  │  Memory Store   │
│ (Strategic)    │  │ (LLM-based) │  │  (RAG + Persist)│
└───────┬────────┘  └─────────────┘  └─────────────────┘
        │
   ┌────┴────┐
   │ Swarm   │
   │ Manager │
   └────┬────┘
        │
   ┌────┴────────────────┐
   │   Agents            │
   │  ┌──────────────┐   │
   │  │ Coordinator  │   │
   │  └──────────────┘   │
   │  ┌──────────────┐   │
   │  │ Recon Agent  │   │
   │  └──────────────┘   │
   │  ┌──────────────┐   │
   │  │ Scan Agent   │   │
   │  └──────────────┘   │
   │  ┌──────────────┐   │
   │  │Exploit Agent │   │
   │  └──────────────┘   │
   │  ┌──────────────┐   │
   │  │  C2 Agent    │   │
   │  └──────────────┘   │
   │  ┌──────────────┐   │
   │  │ MITM Agent   │   │
   │  └──────────────┘   │
   └─────────────────────┘
        │
   ┌────┴────────────────┐
   │  Blackboard         │
   │  - Findings         │
   │  - Pheromones       │
   │  - Predicates       │
   └─────────────────────┘
```

---

## 📦 Installation

### Prerequisites
- Python 3.9+
- pip package manager

### Install Dependencies

```bash
# Clone the repository
cd zahra

# Install dependencies
python -m pip install -r requirements.txt

# Or install manually
python -m pip install pyfiglet chromadb beautifulsoup4 fastapi uvicorn pydantic websockets requests openai
```

### Optional: Install Ollama (for local LLM)

```bash
# Windows
winget install Ollama.Ollama

# Or download from https://ollama.ai

# Pull a model
ollama pull llama3.1
```

---

## 🚀 Usage

### 1. Global Installation (Recommended)

After installing, the `zahra` command is available globally:

```bash
# Install in editable/development mode
pip install -e .

# Now use 'zahra' from any directory
zahra status
zahra full 10.2.20.31
zahra serve --port 8080
```

### 2. Command Line Interface (CLI)

```bash
# Show banner and status
python main.py status

# Full pentest
python main.py full 10.2.20.31

# Reconnaissance only
python main.py recon example.com

# Vulnerability scan
python main.py scan 192.168.1.1

# Exploitation
python main.py exploit https://target.com

# C2 (Command & Control)
python main.py c2 192.168.1.100

# MITM (Man-in-the-Middle)
python main.py mitm 192.168.1.100

# View memory
python main.py memory

# List campaigns
python main.py campaigns
```

### 3. API Server (Web Dashboard)

```bash
# Start the API server locally
python main.py serve --port 8000

# Access the dashboard locally
# Open browser: http://localhost:8000/

# Expose the dashboard to the internet (requires cloudflared or ngrok)
python main.py serve --port 8080 --tunnel

# Or use the dedicated tunnel command
python main.py tunnel --port 8080
```

**Dashboard Features:**
- Modern Bento Grid layout with Tailwind CSS
- Real-time WebSocket streaming of agent activity
- Target control panel with one-click attack modes
- Live terminal output
- Agent swarm status view
- Findings and blackboard table

### 4. With Real LLM (Ollama)

```powershell
# Set environment variables
$env:ZAHRA_LLM_BACKEND="ollama"
$env:ZAHRA_LLM_BASE_URL="http://localhost:11434/v1"
$env:ZAHRA_LLM_MODEL="llama3.1"
$env:ZAHRA_LLM_API_KEY="ollama"

# Run pentest
python main.py full 10.2.20.31
```

### 5. Remote Access with Tunneling

ZAHRA can expose its dashboard to the internet using **cloudflared** (recommended) or **ngrok**.

```bash
# Start the server with a tunnel in one command
python main.py serve --port 8080 --tunnel

# Or start tunnel separately (server must already be running)
python main.py tunnel --port 8080
```

**Setup Instructions:**

1. **cloudflared** (recommended - no account required):
   - Download: https://github.com/cloudflare/cloudflared/releases
   - Windows: `choco install cloudflared`
   - Mac: `brew install cloudflared`
   - Linux: `sudo apt install cloudflared` or download .deb

2. **ngrok** (requires free account):
   - Download: https://ngrok.com/download
   - Sign up at https://dashboard.ngrok.com/signup
   - Configure: `ngrok config add-authtoken <YOUR_TOKEN>`

When the tunnel starts, ZAHRA prints a public URL (e.g., `https://xxxx.trycloudflare.com`) that you can open from any device.

### 6. With OpenAI

```powershell
$env:ZAHRA_LLM_BACKEND="openai"
$env:ZAHRA_LLM_API_KEY="sk-..."
$env:ZAHRA_LLM_MODEL="gpt-4"

python main.py full 10.2.20.31
```

---

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ZAHRA_LLM_BACKEND` | LLM backend (ollama, openai, huggingface, offline) | `offline` |
| `ZAHRA_LLM_BASE_URL` | LLM API base URL | - |
| `ZAHRA_LLM_API_KEY` | LLM API key | - |
| `ZAHRA_LLM_MODEL` | Model name | - |
| `ZAHRA_MAX_TOKENS` | Max tokens per campaign | `500000` |
| `ZAHRA_MAX_AGENT_HOURS` | Max agent hours | `2.0` |
| `ZAHRA_CONTROLLER_CONFIG` | Path to config file | `~/.zahra_data/zahra_config.json` |

---

## 📊 Features Comparison

| Feature | ZAHRA | Strix | Pentest-Swarm-AI | OmniRoute |
|---------|-------|-------|------------------|-----------|
| Skills System | ✅ | ✅ | ❌ | ❌ |
| Stigmergic Blackboard | ✅ | ❌ | ✅ | ❌ |
| Pheromone Decay | ✅ | ❌ | ✅ | ❌ |
| Event System | ✅ | ❌ | ✅ | ❌ |
| Web Search | ✅ | ✅ | ✅ | ❌ |
| RAG Memory | ✅ | ❌ | ❌ | ❌ |
| Auto-Evasion | ✅ | ❌ | ❌ | ❌ |
| Async Swarm | ✅ | ✅ | ✅ | ❌ |
| MITM Proxy | 🔄 | ✅ | ❌ | ✅ |
| Budget Enforcement | ✅ | ❌ | ✅ | ❌ |
| Agentic Core | ✅ | ❌ | ❌ | ❌ |
| Coordinator Agent | ✅ | ✅ | ❌ | ❌ |
| Web Dashboard | ✅ | ❌ | ❌ | ❌ |
| REST API | ✅ | ❌ | ❌ | ❌ |

✅ = Implemented | 🔄 = Planned | ❌ = Not available

---

## 🧠 How It Works

### 1. Campaign Creation
```
User → CLI/API → Orchestrator → Router → Campaign Created
```

### 2. Agent Execution
```
Agentic Core → Swarm Manager → Agents (Recon/Scan/Exploit)
                                    ↓
                              Blackboard (Findings)
                                    ↓
                              RAG System (Learning)
```

### 3. Learning Loop
```
Campaign Complete → Store in RAG → Next Campaign Uses Experience
```

### 4. Auto-Evasion
```
Command Blocked → Detect → Query RAG → Apply Evasion → Retry
```

---

## 📁 Project Structure

```
zahra/
├── main.py                    # Entry point
├── requirements.txt           # Dependencies
├── README.md                  # This file
│
├── core/                      # Core systems
│   ├── agentic_core.py       # Strategic brain
│   ├── blackboard.py         # Stigmergic coordination
│   ├── events.py             # Event system
│   ├── orchestrator.py       # Main coordinator
│   ├── router.py             # Command routing
│   ├── memory.py             # Persistent memory
│   └── rag_system/           # Adaptive RAG
│       ├── __init__.py
│       └── chromadb_wrapper.py
│
├── agents/                    # AI Agents
│   ├── base_agent.py         # Base agent class
│   ├── coordinator_agent.py  # Strategic coordinator
│   ├── recon_agent.py        # Reconnaissance
│   ├── scan_agent.py         # Vulnerability scanning
│   ├── exploit_agent.py      # Exploitation
│   ├── c2_agent.py           # Command & Control
│   ├── mitm_agent.py         # Man-in-the-Middle
│   └── skills/               # Modular skills
│       ├── __init__.py
│       ├── base.py
│       ├── web_search.py
│       ├── reporting.py
│       └── proxy.py
│
├── ai_engine/                 # AI/LLM components
│   ├── llm_wrapper.py        # LLM abstraction
│   ├── prompt_engineer.py    # Prompt generation
│   └── decision_maker.py     # JSON decision parsing
│
├── interfaces/                # User interfaces
│   ├── cli.py                # Command-line interface
│   ├── api_server.py         # FastAPI backend
│   └── dashboard/            # Web dashboard
│       ├── index.html
│       ├── style.css
│       └── script.js
│
└── docs/                      # Documentation
    ├── FEATURES_INTEGRATION.md
    └── INTEGRATED_FEATURES.md
```

---

## 🎓 Inspiration

This project integrates concepts from:

- **Strix** - Campaign management, state persistence, agent coordination
- **Pentest-Swarm-AI** - Blackboard pattern, pheromone coordination, event system
- **OmniRoute** - Dynamic routing concepts, MITM proxy capabilities
- **Superpowers** - Advanced prompt engineering (ReAct, Chain-of-Thought)

---

## 🔒 Legal & Ethical

**IMPORTANT**: This tool is designed for:

- ✅ Authorized penetration testing
- ✅ Security research
- ✅ Educational purposes
- ✅ CTF competitions
- ✅ Bug bounty programs (with permission)

**DO NOT** use this tool for:
- ❌ Unauthorized access
- ❌ Illegal activities
- ❌ Malicious purposes

You are solely responsible for your actions. Use at your own risk.

---

## 📝 License

MIT License - see LICENSE file for details

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

---

## 📧 Contact

For questions and support, please open an issue on GitHub.

---

<div align="center">

**Built with ❤️ by the ZAHRA Team**

🐉 *"The dragon that learns from every battle"* 🐉

</div>