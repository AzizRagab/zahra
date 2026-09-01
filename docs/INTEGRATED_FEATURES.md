# Integrated Features Documentation

## Overview

Zahra has been enhanced with professional features from four leading open-source projects:
- **Strix** - Skills system, tools framework, web search
- **Pentest-Swarm-AI** - Stigmergic blackboard, pheromone coordination, event system
- **OmniRoute** - MITM proxy capabilities
- **Superpowers** - Multi-agent orchestration patterns

## Implemented Features

### 1. Skills System (from Strix)

**Location:** `agents/skills/`

Modular capabilities that agents can load and use during execution.

#### Available Skills:
- **WebSearchSkill** - Search the web for CVEs, OSINT data, and exploit techniques
- **ReportingSkill** - Generate vulnerability reports in multiple formats (Markdown, HTML, JSON, SARIF)
- **ProxySkill** - HTTP proxy for request/response manipulation and web app testing

#### Usage:
```python
from agents.skills import register_skill, get_skill
from agents.skills.web_search import WebSearchSkill

# Register a skill
register_skill(WebSearchSkill())

# Use in agent
skill = get_skill("web_search")
result = await skill.execute(context, query="Apache 2.4 CVE")
```

### 2. Stigmergic Blackboard (from Pentest-Swarm-AI)

**Location:** `core/blackboard.py`

Shared findings board with pheromone-based agent coordination.

#### Key Concepts:
- **Findings** - Structured data written by agents
- **Pheromones** - Decaying weights that bias agent attention
- **Predicates** - Filters for matching relevant findings
- **Budget** - Resource tracking per campaign

#### Finding Types:
- RECON, PORT_OPEN, HTTP_ENDPOINT, TECHNOLOGY
- CVE_MATCH, MISCONFIGURATION, EXPLOIT_CHAIN
- EXPLOIT_RESULT, CAMPAIGN_COMPLETE, AGENT_ERROR

#### Usage:
```python
from core.blackboard import Blackboard, Finding, FindingType, Predicate

# Write a finding
finding = Finding(
    type=FindingType.PORT_OPEN,
    target="example.com",
    data=b"Port 80 is open",
    pheromone_base=1.0,
    half_life_sec=3600
)
blackboard.write(finding)

# Query findings
predicate = Predicate(
    types=[FindingType.PORT_OPEN],
    min_pheromone=0.5
)
open_ports = blackboard.query(predicate)
```

### 3. Event System (from Pentest-Swarm-AI)

**Location:** `core/events.py`

Structured event emission for platform observability.

#### Event Types:
- AGENT_STARTED, AGENT_FINISHED, AGENT_ERROR
- AGENT_BUDGET_EXCEEDED, AGENT_BUDGET_WARN
- CAMPAIGN_STARTED, CAMPAIGN_COMPLETE, CAMPAIGN_ERROR
- BUDGET_EXCEEDED, FINDING_WRITTEN
- SKILL_EXECUTED, TOOL_USED

#### Usage:
```python
from core.events import EventEmitter, EventType, emit

# Global emitter
emit(Event(
    type=EventType.AGENT_STARTED,
    campaign_id="campaign-123",
    agent_name="recon_agent",
    detail="Starting reconnaissance"
))

# Custom emitter
emitter = EventEmitter()
emitter.on(EventType.AGENT_FINISHED, callback)
emitter.emit(Event(type=EventType.AGENT_FINISHED, ...))
```

### 4. Enhanced Base Agent (from Strix + Pentest-Swarm-AI)

**Location:** `agents/base_agent.py`

LLM-driven agents with integrated skills, events, and blackboard.

#### New Features:
- **Skills Integration** - Agents can execute skills via LLM decisions
- **Event Emission** - Automatic event emission for all agent actions
- **Blackboard Writing** - Automatic finding publication to blackboard
- **Trigger Predicates** - Define what findings an agent should process

#### Usage:
```python
from agents.base_agent import BaseAgent, AgentContext
from core.blackboard import Blackboard
from core.events import EventEmitter

# Create agent with enhancements
agent = BaseAgent(
    name="custom_agent",
    llm_wrapper=llm,
    skills=[web_search_skill, reporting_skill],
    blackboard=blackboard,
    event_emitter=event_emitter
)

# Define trigger predicate
def trigger(self):
    return Predicate(
        types=[FindingType.CVE_MATCH],
        min_pheromone=0.7
    )
```

### 5. Enhanced Orchestrator

**Location:** `core/orchestrator.py`

Top-level coordinator with blackboard and event integration.

#### New Features:
- **Blackboard Integration** - Automatic budget tracking on blackboard
- **Event Emission** - Structured events for all campaign lifecycle events
- **Budget Enforcement** - Partial reports on budget exhaustion

### 6. Enhanced Swarm Manager

**Location:** `agents/swarm_manager.py`

Async swarm coordinator with stigmergic coordination.

#### New Features:
- **Blackboard Writing** - All findings written to blackboard
- **Event Emission** - Real-time event streaming
- **Stigmergic Coordination** - Agents react to findings via queue

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        CLI / API                             │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                    Orchestrator                              │
│  - Campaign management                                       │
│  - Budget enforcement                                        │
│  - Event emission                                            │
│  - Blackboard integration                                    │
└───────────────────────────┬─────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
┌───────▼────────┐  ┌──────▼──────┐  ┌────────▼────────┐
│  Swarm Manager │  │    Router   │  │  Memory Store   │
│  - Async exec  │  │  - LLM      │  │  - Persistent   │
│  - Blackboard  │  │    routing  │  │  - RAG          │
│  - Events      │  │             │  │                 │
└───────┬────────┘  └─────────────┘  └─────────────────┘
        │
   ┌────┴────┐
   │ Agents  │
   │ - Recon │
   │ - Scan  │
   │ - Exploit│
   └────┬────┘
        │
   ┌────┴────────────────┐
   │  Blackboard         │
   │  - Findings         │
   │  - Pheromones       │
   │  - Predicates       │
   └─────────────────────┘
```

## Feature Comparison

| Feature | Zahra | Strix | Pentest-Swarm-AI | OmniRoute |
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

✅ = Implemented | 🔄 = Planned | ❌ = Not available

## Configuration

### Environment Variables

```bash
# LLM Configuration
ZAHRA_LLM_BACKEND=openai  # openai, ollama, huggingface, offline
ZAHRA_LLM_BASE_URL=https://api.openai.com/v1
ZAHRA_LLM_API_KEY=sk-...
ZAHRA_LLM_MODEL=gpt-4

# Platform Configuration
ZAHRA_MAX_TOKENS=500000
ZAHRA_MAX_AGENT_HOURS=2.0
```

### Skills Configuration

Skills are automatically registered in `main.py`. To add custom skills:

```python
from agents.skills import register_skill
from agents.skills.web_search import WebSearchSkill

# Register before building platform
register_skill(WebSearchSkill())
```

### Blackboard Configuration

```python
from core.blackboard import Blackboard

# Custom blackboard with settings
blackboard = Blackboard()

# Findings automatically decay based on half_life_sec
# Default: 3600 seconds (1 hour)
```

### Event System Configuration

```python
from core.events import EventEmitter, EventType

# Create custom emitter
emitter = EventEmitter()

# Subscribe to events
def on_agent_finished(event):
    print(f"Agent {event.agent_name} finished: {event.detail}")

emitter.on(EventType.AGENT_FINISHED, on_agent_finished)
```

## Testing

Run the platform to verify all features:

```bash
# Check platform status
python main.py status

# Run a campaign
python main.py scan example.com

# View memory
python main.py memory

# List campaigns
python main.py campaigns
```

## Next Steps

### Phase 2 Enhancements:
1. **MITM Proxy Integration** - Full HTTP/HTTPS interception
2. **Rate Limiting** - Per-agent rate limits (from Pentest-Swarm-AI)
3. **Fine-tuning Support** - Model fine-tuning for pentest-specific tasks
4. **Advanced Reporting** - SARIF, HTML reports with CVSS scoring

### Phase 3 Enhancements:
1. **Multi-Agent Graph** - Dynamic agent spawning (from Strix)
2. **Playbooks** - Pre-defined attack scenarios
3. **CI/CD Integration** - GitHub Actions, GitLab CI
4. **Dashboard** - Real-time web UI

## References

- [Strix](https://github.com/usestrix/strix) - AI pentesting agents
- [Pentest-Swarm-AI](https://github.com/Armur-Ai/Pentest-Swarm-AI) - Stigmergic swarm architecture
- [OmniRoute](https://github.com/omniroute/omniroute) - MITM proxy
- [Superpowers](https://github.com/obra/superpowers) - Agent methodology