# ZAHRA — Technical Audit Report (`PROJECT_REPORT.md`)

**Audit date:** 2026-08-31 · **Scope:** read-only pass over the ZAHRA Python platform (`c:\Users\Admin\Desktop\zahra`)
**Method:** every claim below is backed by a live run on this machine or a direct file read with `file:line` citation. Nothing is inferred from documentation alone.
**Honesty rule applied:** stubs are called stubs; simulated output is called simulated; verified behavior is labeled *verified*.

---

## 0. Executive summary

| Area | Verdict |
|---|---|
| Does it build/run? | **Yes** — `python main.py` CLI works; `scan 127.0.0.1` completed a real campaign (~16 s, real `nuclei` + real LLM calls, exit 0). Go sub-service builds (`go build ./...` exit 0). |
| Swarm coordination (blackboard + pheromones) | **Real and functional** — verified numerically (decay + pheromone-sorted queries). One stub inside it (see §4.2). |
| Multi-agent execution | **Real** — `full` launches 5 agents concurrently; each agent runs real external tools via subprocess. |
| RAG / adaptive learning | **Real** — ChromaDB store live with **1,285 findings**; recall verified. |
| Tests | **Effectively none runnable** — 1 test file exists, `pytest` is not installed in the venv (verified: `No module named pytest`). |
| Biggest demo risks | CORS `*` on the API, `tunnel` command exposes the dashboard publicly, offline LLM mode can hang, `full` can loop up to 1000 iterations, docstrings advertise broken CLI syntax. |

---

## 1. Project structure

The repository is a hybrid monorepo. The ZAHRA platform itself is the Python package set at the root (`core/`, `agents/`, `ai_engine/`, `ai_agent/`, `interfaces/` plus `zahra_agent.py`). Everything under `services/` (pentest-swarm in Go, omniroute in Next.js), `libs/agent-reach`, and `open-design/` is merged/vendored material, not part of the Python runtime.

### 1.1 `core/` — coordination kernel
- **`core/zahra_config.py`** — configuration schema and loader. `ZahraConfig.from_env()` (zahra_config.py:292–317) reads `ZAHRA_*` environment variables with sane defaults (Ollama at `http://localhost:11434/v1`), with an optional JSON config file via `ZAHRA_CONFIG` (line 292) and a legacy-key fallback. Execution mode defaults to **authorized** (`ZAHRA_UNRESTRICTED` default `"1"` maps to `UNRESTRICTED_DEFAULT`, zahra_agent.py:63).
- **`core/zahra_controller.py`** — the composition root. Builds and owns **every** subsystem: LLM wrapper, blackboard, event emitter, agentic core, skills, swarm manager, router, memory store (ChromaDB), SQLite database, orchestrator, and the ReAct AI agent (documented at main.py:49–74). `start()` (main.py:80) activates the agentic core. System prompt is authorized-engagement framed (zahra_controller.py:85–105).
- **`core/agentic_core.py`** — the strategic brain. Tracks per-campaign `CampaignState`, distributes `Task` objects, and decides phase transitions. `should_start_exploit()` (agentic_core.py:224–264) requires a completed scan phase plus exploitable blackboard findings (CVE/misconfiguration with pheromone ≥ 0.5); its "RAG guidance" is honestly self-labeled *"This is a simplified version - in production, use proper RAG query"* (agentic_core.py:254) — it counts past successes in the memory store (agentic_core.py:266–284), it is **not** a vector query.
- **`core/orchestrator.py`** — campaign lifecycle: create → run → track. Executes the recon→scan→exploit pipeline, emits events, and on failure produces a **placeholder finding** fallback (orchestrator.py:290–300) so the pipeline always yields output. This is real logic but the fallback path is clearly marked.
- **`core/blackboard.py`** — stigmergic coordination. `Finding` objects carry `pheromone_base` + timestamps; exponential half-life decay; `query(Predicate)` filters by type/severity/min-pheromone and **sorts by pheromone descending** — all verified live. ⚠️ `_notify()` is a **stub**: subscriber callbacks are logged, not dispatched, so "blackboard-triggered agent wake-up" does not fire; actual cross-agent signaling happens through the memory/event queue instead.
- **`core/memory.py`** — persistent memory: SQLite for structured history + ChromaDB vector store for semantic recall (`recall_relevant`). Live store holds 1,285 findings.
- **`core/router.py`** — LLM-assisted intent classification (maps a free-text goal to scan/recon/exploit/c2/mitm). Works, but quality depends on the small local model.
- **`core/events.py`** — typed `EventType` enum + `EventEmitter` singleton (`get_emitter`); the observability backbone feeding the dashboard WebSocket.
- **`core/tactical_intel.py`** — per-agent intel service: web OSINT + RAG recall fusion with TTL cache (tactical_intel.py:82–83) and a decision log written to `~/.gstack/projects/<slug>/decisions.jsonl` (tactical_intel.py:174–191). Lazy imports make it offline-tolerant.

### 1.2 `agents/` — the swarm
- **`agents/swarm_manager.py`** — creates and injects the five agents (recon, scan, exploit, c2, mitm), holds per-agent config (enabled flag, rate limit, max iterations — exposed via API routes `POST /api/agents/{name}/enabled|rate-limit|max-iterations`, api_server.py:530–546). `full` launches all five concurrently (verified live). Coordination is stigmergic: recon publishes, downstream agents subscribe and react via the async memory/event queue.
- **`agents/base_agent.py`** — shared agent machinery: subprocess tool execution, DuckDuckGo HTML search fallback (base_agent.py:503), target validation (base_agent.py:724–729), finding publication to the blackboard (⚠️ hardcoded to `FindingType.RECON` with `pheromone_base=1.0` — noted in a prior verification pass), and tactical-intel hooks.
- **`agents/recon_agent.py`** — real reconnaissance: nmap/masscan-style enumeration + LLM-planned commands. On Windows it can route commands through a WSL bridge (observed: an LLM-chosen `masscan -iL /dev/null` invoked the bridge and stalled) — see §9.
- **`agents/scan_agent.py`** — real scanning. Default template `nuclei -u http://{target} -silent` (scan_agent.py:56); the live `scan` command ran `nuclei -u http://127.0.0.1 -t cves` and produced 4 real findings in ~16 s.
- **`agents/exploit_agent.py`** — real tool invocation via sqlmap templates (`sqlmap -u http://{target} --batch --level=1`, exploit_agent.py:59) plus LLM-selected techniques. Effectiveness depends entirely on the target and the small local model's choices.
- **`agents/c2_agent.py`** — ⚠️ **partially simulated**: module docstring states "Performs data exfiltration (simulated)" (c2_agent.py:7) and the agent prompt repeats "(simulated)" (prompt_engineer.py:322). Infrastructure-listening logic exists; exfiltration is not a real implementation.
- **`agents/mitm_agent.py`** — runs async; depends on local network positioning (ARP/iptables-class tooling), effectively Linux-targeted; untested on Windows beyond "starts without crashing".

### 1.3 `ai_engine/` — LLM layer
- **`ai_engine/llm_wrapper.py`** — unified OpenAI-compatible client. Backends: `openai`, `anthropic`, `ollama` (via `http://localhost:11434/v1`, llm_wrapper.py:114), `openwebui`, `huggingface`, `offline`. Defaults when constructed directly: `backend="offline"`, `max_tokens=2048`, `timeout=60` (llm_wrapper.py:57–63). The **offline backend returns a simulated response**: *"This is a simulated response. Configure an LLM backend..."* (llm_wrapper.py:273) — honest labeling, but anything run in offline mode gets canned text, not reasoning.
- **`ai_engine/prompt_engineer.py`** — builds the per-agent system prompts (7 variants). Prompts use authorized-engagement framing; they explicitly forbid simulated/empty search results (prompt_engineer.py:56).
- **`ai_engine/decision_maker.py`** — heuristic + LLM hybrid command selection (e.g. nuclei template at decision_maker.py:347). Real logic, small-model quality-bound.

### 1.4 `ai_agent/` — the ReAct "brain" + training pipeline
- **`ai_agent/agent_core.py`** — ReAct loop (Thought→Action→Observation) with RAG + web search toggles (`AI_AGENT_*` env vars, agent_core.py:49–57). Calls the HF Inference router (`https://router.huggingface.co/hf-inference/models/...`, agent_core.py:116) or an OpenAI-compatible endpoint.
- **`ai_agent/adaptive_rag.py`** — hybrid embedding + TF-IDF recall against Ollama embeddings (`nomic-embed-text`, adaptive_rag.py:29–30). Backs the "1,285 findings" store.
- **`ai_agent/web_search.py`** — multi-engine search: Google CSE (needs API key, web_search.py:266), DuckDuckGo lite/html (285, 316), Bing (380, 408), Mojeek (437), DDG instant-answer API (542). Real HTTP scraping; no API key needed for DDG/Bing paths.
- **`ai_agent/hf_integration.py`, `train.py`, `zahra_dataset.py`, `zahra_finetune.py`, `zahra_learn.py`** — LoRA fine-tuning pipeline for the personal `zahra` model + auto-learning (`ZAHRA_LEARN_MIN_SAMPLES=600`, `ZAHRA_LEARN_AUTO=0`, zahra_learn.py:29–30). Trained artifacts live in `zahra_model/` (gitignored).

### 1.5 `interfaces/` — CLI, API, dashboard
- **`interfaces/cli.py`** — argparse CLI with ~30 subcommands (see §5). ANSI-colored output, pyfiglet banner. Two doc bugs: usage strings advertise `full pentest example.com` (cli.py:10, main.py:17) but argparse rejects that syntax (verified: exit 2 "unrecognized arguments"). `main()` inserts `parent.parent.parent` on `sys.path` (cli.py:59) which resolves to the *parent of the repo*, not the repo — works only because pip-installed packages put the root on the path anyway.
- **`interfaces/api_server.py`** — FastAPI app, **~50 routes** (full list in §5) + 3 WebSockets (`/ws`, `/ws/chat`, `/ws/attack`), campaign scheduler (defaults: 3600 s interval, command `full 127.0.0.1`, api_server.py:92–100), multi-turn chat memory capped at 24 turns (api_server.py:105), HTML/CSV report export (`/api/reports/export`, line 718). ⚠️ CORS is fully open: `allow_origins=["*"]` with `allow_credentials=True` (api_server.py:39–45).
- **`interfaces/dashboard/`** — vanilla JS command center (index.html + style.css + script.js, 1,410 lines). Three.js point-cloud background (script.js:39–92), vis.js attack graph (script.js:940–948), sparklines, SQLite explorer, AI chat (`POST /api/chat`, script.js:1014), WS-driven live agent view with reconnect. Every on-load fetch maps to a real API route (verified).

### 1.6 Root-level
- **`main.py`** — entry point; `build_platform()` (main.py:49–92) wires the controller and returns the CLI. Also implements `tunnel` (cloudflared `trycloudflare.com` parsing at main.py:254–265, ngrok API at main.py:269–308).
- **`launcher.py`** — interactive launcher: sets `ZAHRA_LLM_*` env from Ollama defaults (launcher.py:56–57, 188–190), sets `ZAHRA_UNRESTRICTED=1` and `PYTHONPATH` (launcher.py:204–205), spawns main.py.
- **`zahra_agent.py`** — 3,600-line monolith: the "safe brain" (human-in-the-loop autonomous agent), the **ATTACK_LIBRARY** of ~100+ curated curl/nmap/nuclei/sqlmap/gobuster command templates (zahra_agent.py:96–458), OSINT channel integration (Twitter/Reddit/GitHub via `libs/agent-reach`), and its own web search (Bing at 1302, DDG at 1327/1355). ⚠️ Contains an offline **simulated** OSINT backend used for pipeline testing (zahra_agent.py:1368–1399), exposed as CLI `osint simulate` (cli.py:289, 700–707).
- **`services/`, `libs/`, `open-design/`, `skills/`, `programming_agent/`, `hf_space/`, `reports/`, `docs/`** — merged/vendored material (Go swarm service, OmniRoute Next.js app, agent-reach lib with its own 36 test files, UI mockups). Not exercised by the Python runtime except `libs/agent-reach` (OSINT channels); `services/` sub-projects build/run independently.

---

## 2. Dependencies

Sources: `pyproject.toml:31–48` and `requirements.txt` (identical lists; `requirements.txt` additionally comments out optional `sentence-transformers`, `ollama`, `python-dotenv`).

| Library | Used for | Actually exercised? |
|---|---|---|
| `openai>=1.0.0` | OpenAI-compatible LLM client — this is how Ollama/OpenWebUI are called (llm_wrapper.py:114) | ✅ verified (live 200s from Ollama) |
| `anthropic>=0.8.0` | Anthropic backend option in llm_wrapper | imported; no key configured — untested path |
| `chromadb>=0.4.0` | Vector DB for RAG (`zahra_data/rag`, `zahra_data/ai_agent_chroma`) | ✅ verified (1,285 findings recalled) |
| `fastapi` / `uvicorn[standard]` / `pydantic` / `python-multipart` | REST API + dashboard server (api_server.py) | ✅ verified (`/api/info` 200, uvicorn clean start) |
| `websockets>=11.0` | WS event streaming (`/ws`, `/ws/chat`, `/ws/attack`) | ✅ route verified live |
| `requests` / `beautifulsoup4` | Web scraping for OSINT/search (web_search.py, base_agent.py) | ✅ used by agents |
| `numpy` | Embedding math in adaptive_rag | ✅ imported at startup |
| `transformers` / `torch` / `huggingface-hub` / `gradio` | LoRA fine-tuning + HF inference (`ai_agent/`) | ⚠️ heavy (~2 GB+); imported lazily; training pipeline **untested end-to-end in this audit** |
| `pyfiglet` | CLI banner (cli.py:45) | ✅ verified |

**Dev deps declared but not installed:** `pytest`, `black`, `mypy` are in `[project.optional-dependencies].dev` (pyproject.toml:51–55) — none installed in the active venv (verified: `No module named pytest`).

**Python version mismatch:** `requires-python = ">=3.9"` (pyproject.toml:29) but the code uses PEP 604 unions at runtime in dataclasses and the dev venv is Python 3.14 — 3.9/3.10 compatibility is **untested and unlikely** for `X | None` in non-annotation contexts.

---

## 3. Feature audit — README claims vs. reality

Legend: ✅ implemented & verified · 🟡 partial/stubbed · 🟠 simulated/hardcoded path · ❌ not implemented.

| README claim (README.md lines 44–78) | Verdict | Evidence |
|---|---|---|
| **Agentic Core — strategic brain coordinates swarm** | ✅ | `AgenticCore` real; tasks/phases tracked (agentic_core.py:94–103); controller wires it (main.py:80) |
| **Task distribution to specialized agents** | ✅ | swarm_manager injects 5 agents; concurrent launch verified live |
| **Phase management Recon→Scan→Exploit→Report** | 🟡 | recon→scan→exploit verified; "Report" phase is only the API export route (`/api/reports/export`, api_server.py:718) — no dedicated report agent |
| **RAG learning — learns from past campaigns** | ✅ (with caveat) | ChromaDB recall verified; but exploit-decision "RAG guidance" is a success-count heuristic, self-labeled simplified (agentic_core.py:254) |
| **Vector DB stores commands/payloads/techniques** | ✅ | `zahra_data/rag` + `ai_agent_chroma` live |
| **Experience reuse / evasion memory** | 🟡 | recall works; "remembers what bypassed WAFs" is implicit in stored findings, no dedicated evasion-index logic found |
| **Authorized-only execution framing** | ✅ | system prompts re-framed (zahra_controller.py:85–105, prompt_engineer.py:203–365) |
| **ReAct loop** | ✅ (two implementations) | `ai_agent/agent_core.py` (lib-driven) + `zahra_agent.py` brain; both real, small-model-bound |
| **Alternative strategies / adaptive persistence** | 🟡 | retry logic exists in decision_maker/base_agent; unrestricted controller allows `max_iterations=1000` — "persistence" is real but unbounded |
| **Auto-Evasion — RAG-based, heuristic, multi-tool, max 2 retries** | 🟡 | heuristic stealth-flag logic present; the "max 2 attempts" figure could not be confirmed as a hard invariant in code |
| **Web search / OSINT, CVE discovery, ExploitDB** | 🟡 | multi-engine search real (web_search.py:266–542); "ExploitDB integration" is just search queries, not an API client |
| **"No API required — uses DuckDuckGo"** | ✅ | DDG HTML scrape (base_agent.py:503, web_search.py:316) |
| **Event system + WebSocket + Blackboard + Pheromones** | ✅ (1 stub) | events/WS/blackboard/pheromones verified; blackboard `_notify()` is a **stub** (callbacks logged, not dispatched) |
| *Undocumented but real:* dashboard command center, scheduler, chat, DB explorer, report export, tunnel | ✅ | api_server.py routes; script.js |

### 3.1 Every TODO / stub / simulated / placeholder marker found (own code, exhaustive per `Select-String`)

| File:line | Marker | Meaning |
|---|---|---|
| `core/orchestrator.py:290` | `# Local fallback — produce a placeholder finding...` | pipeline failure fallback, intentional |
| `core/orchestrator.py:300` | `Placeholder finding for target...` | same |
| `core/agentic_core.py:254` | *"simplified version - in production, use proper RAG query"* | heuristic where RAG is claimed |
| `core/blackboard.py` (`_notify`) | stub | subscriber callbacks are logged, never dispatched |
| `agents/c2_agent.py:7` | "data exfiltration (simulated)" | exfiltration is not real |
| `ai_engine/llm_wrapper.py:273` | "This is a simulated response. Configure an LLM backend" | offline backend returns canned text |
| `ai_engine/prompt_engineer.py:322` | "Perform data exfiltration (simulated)" | prompt mirrors c2 limitation |
| `zahra_agent.py:1368–1399` | "Offline simulated search used for testing the pipeline end-to-end" + `[simulated github results...]` etc. | fake OSINT results generator |
| `zahra_agent.py:3305` / `interfaces/cli.py:289` | `osint simulate` subcommand | simulated path exposed as a CLI command |
| `zahra_agent.py:3561–3568` | `[SIMULATED OSINT] query=...` | its output |

No literal `TODO`/`FIXME`/`XXX` comments were found in `core/`, `agents/`, `ai_engine/`, or `interfaces/` — the code's gaps are expressed as the markers above, not TODOs.

## 4. Entry points & data flow

### 4.1 Ways to run the platform

| Entry point | Command | What it does |
|---|---|---|
| **Python CLI** | `python main.py <cmd>` | Main dispatcher (`main.py`). Subcommands registered at `interfaces/cli.py:145–312`: `scan`, `recon`, `exploit`, `c2`, `mitm`, `full`, `status`, `memory`, `campaigns`, `serve`, `tunnel`, `controller`, `think`, `decide`, `deploy`, `cmd`, plus a `brain` sub-suite (`think`, `run`, `assess`, `shell`, `recall`, `skills`, `osint …`, `attacks …`, `stats`) |
| **API server** | `python main.py serve --port 8090` or `python interfaces/api_server.py` | FastAPI + uvicorn; serves the dashboard, 50 REST routes and 3 WebSockets (list below) |
| **Web dashboard** | `http://localhost:8090` (static: `interfaces/dashboard/index.html`, `style.css`, `script.js` — 1,410 lines of JS) | Login screen → command center: KPIs, agent grid, findings, attack graph (vis.js), chat, scheduler, swarm control |
| **Launcher/setup** | `python launcher.py` | One-shot bootstrap: checks/starts Ollama (`launcher.py:56`), pulls `zahra:latest` (`:57`), sets `PYTHONPATH` (`:205`) |
| **Go reference CLI** | `services/pentest-swarm/cmd/pentestswarm` | Separate Go binary (builds clean); `serve` needs `services/pentest-swarm/config.yaml` — **missing** (only `config.example.yaml` exists) |
| **Training/ingest** | `ingest_rag_material.py`, `zahra_learn.py` | RAG corpus ingestion; fine-tune data prep (`zahra_learn.py:29–30`) |

### 4.2 REST API surface (`interfaces/api_server.py`, routes at cited lines)

- **Static:** `GET /` (`:53`), `/style.css` (`:61`), `/script.js` (`:70`)
- **Status/info:** `/api/info` (`:144`), `/api/status` (`:167`), `/health` (`:916`), `/status` (`:922`), `/memory` (`:900`), `/memory/findings` (`:908`)
- **Campaigns:** `POST /api/campaign` (`:186`), `POST /api/campaign/{id}/start` (`:205`), `GET /api/campaign/{id}` (`:221`), `GET /api/campaigns` (`:234`), `GET /api/blackboard` (`:254`), `GET /api/rag/stats` (`:279`)
- **DB explorer:** `GET /api/db/tables` (`:288`), `GET /api/db/table/{name}` (`:299`)
- **Agent/AI:** `GET /api/agent/status` (`:314`), `POST /api/agent/think` (`:325`), `/think/reset` (`:357`), `POST /api/agent/analyze` (`:365`), `POST /api/agent/run` (`:378`), `GET /api/agent/search` (`:394`), `GET /api/agent/rag/recent` (`:407`)
- **Controller:** `GET /api/controller` (`:418`), `POST /api/controller/think` (`:426`), `/decide` (`:440`), `/deploy` (`:454`), `/cmd` (`:472`), `GET /api/controller/campaigns` (`:487`), `/agents` (`:495`), `/blackboard` (`:562`), `/memory` (`:570`), `POST /api/controller/run-campaign` (`:578`)
- **Swarm control:** `GET /api/agents` (`:505`), `POST /api/agents/{name}/deploy` (`:513`), `/enabled` (`:530`), `/rate-limit` (`:538`), `/max-iterations` (`:546`), `GET /api/agents/{name}/logs` (`:554`)
- **Scheduler:** `GET|POST /api/scheduler/config` (`:635`, `:641`), `POST /api/scheduler/run-now` (`:659`)
- **Reports/chat:** `GET /api/reports/export` (`:718`), `POST /api/chat` (`:835`), `GET /api/chat/stats` (`:849`)
- **WebSockets:** `/ws` (`:930`), `/ws/chat` (`:864`), `/ws/attack` (`:958` — the dashboard's command channel)

### 4.3 End-to-end trace: `python main.py scan 127.0.0.1` (verified live, ~16 s)

1. `main.py` parses args → `ZahraConfig.from_env()` (`core/zahra_config.py:292–320`) → `ZahraController` (`core/zahra_controller.py`) → `SwarmManager` injected into `Orchestrator` (`core/orchestrator.py`).
2. `main.py` instantiates `CLI` and calls `cli.run()`; the dispatch table at `interfaces/cli.py:101–113` routes `scan` → `CLI._cmd_scan`.
3. `Orchestrator` starts the campaign; the router (`core/router.py`) selects the scan agent; `agents/scan_agent.py:56` builds `nuclei -u http://{target} -silent` (decision fallback: `ai_engine/decision_maker.py:347`).
4. `agents/base_agent.py:384–475` executes the command as a subprocess and parses output; `base_agent.py:503` can add DuckDuckGo HTML search for context.
5. Findings are written to the blackboard (`core/blackboard.py` — pheromone strength + decay) and `MemoryStore` (`core/memory.py` — SQLite + RAG upsert).
6. Events flow through `core/events.py` (`EventEmitter`) → `interfaces/api_server.py:1070–1102` subscribes to every `EventType` and broadcasts to WebSocket clients; `critical_alert` is synthesized for high/critical findings (`:1087–1098`).
7. CLI prints findings via `CLI._print_findings` (`interfaces/cli.py:771–798`); exit 0 on `campaign_complete`. ✔ Matches the verified live run: 4 findings, real nuclei execution, LLM HTTP 200s to Ollama.

**Parallel path (`full`):** `CLI._cmd_full` → `ZahraController`/`SwarmManager` (`agents/swarm_manager.py`) launches all five agents (recon, scan, exploit, c2, mitm) concurrently; coordination happens through the async `MemoryQueue` (stigmergy) — recon publishes, downstream agents subscribe. `Blackboard._notify` is a stub, so blackboard callbacks are *not* dispatched (see §3).


## 5. Config & environment

### 5.1 Config files

| File | Read by | Notes |
|---|---|---|
| `~/.zahra_data/zahra_config.json` (path overridable, `core/zahra_config.py:292`) | `ZahraConfig.from_env()` | Primary config; **two config systems exist** (see §7) |
| `zahra_data/zahra_config.json` | local instance copy | ⚠️ its `base_url` is `http://localhost:11434` (no `/v1`) — would 404 if loaded; it is **not** on the default load path |
| `.env` (`services/omniroute/`) | OmniRoute only | not read by the ZAHRA Python core |
| `services/pentest-swarm/config.yaml` | Go `serve` | **missing** (only `config.example.yaml`) |

### 5.2 Environment variables (defaults cited)

**ZAHRA core LLM** (`core/zahra_config.py:304–320`): `ZAHRA_LLM_BACKEND=ollama` · `ZAHRA_LLM_MODEL=zahra` · `ZAHRA_LLM_BASE_URL=http://localhost:11434/v1` · `ZAHRA_LLM_API_KEY=` (empty) · `ZAHRA_LLM_TEMPERATURE=0.7` · `ZAHRA_LLM_MAX_TOKENS=4096` · `ZAHRA_LLM_TIMEOUT=120` · `ZAHRA_USER_NAME=operator` · `ZAHRA_USE_GPU=true` (`core/zahra_controller.py:232`)

**Secondary LLM config** (`ai_engine/llm_wrapper.py:57–63`): same variable names but **conflicting defaults**: `ZAHRA_LLM_BACKEND=offline`, `ZAHRA_LLM_MAX_TOKENS=2048`, `ZAHRA_LLM_TIMEOUT=60`, empty base_url/model → any code path using this default silently runs the **simulated offline backend** ⚠️

**Agent/brain** (`zahra_agent.py`): `ZAHRA_UNRESTRICTED=1` (`:63` — default *on*) · `ZAHRA_MODEL=zahra-unrestricted` (`:2959`) · `ZAHRA_OLLAMA_URL=http://localhost:11434` (`:2960`; also `launcher.py:56–57`, model `zahra:latest`)

**Legacy `ai_agent` module** (`ai_agent/agent_core.py:49–57`, `hf_integration.py:25,68`): `AI_AGENT_BACKEND=huggingface` · `AI_AGENT_MODEL=mistralai/Mistral-7B-Instruct-v0.2` · `AI_AGENT_BASE_URL=` · `AI_AGENT_API_KEY=` falls back to `HF_TOKEN` · `AI_AGENT_TEMPERATURE=0.3` · `AI_AGENT_MAX_TOKENS=2048` · `AI_AGENT_MAX_ITERATIONS=10` · `AI_AGENT_RAG=true` · `AI_AGENT_WEB_SEARCH=true` · `HF_TOKEN=` (empty)

**RAG/embeddings** (`ai_agent/adaptive_rag.py:29–30`): `OLLAMA_BASE_URL=http://localhost:11434` · `ZAHRA_EMBED_MODEL=nomic-embed-text`

**Intel** (`core/tactical_intel.py:82–83,177–178`): `ZAHRA_INTEL_CACHE_TTL=180` · `ZAHRA_INTEL_CACHE_MAX=512` · `GSTACK_HOME=~/.gstack` · `ZAHRA_SLUG=zahra`

**Learning** (`zahra_learn.py:29–30`): `ZAHRA_LEARN_MIN_SAMPLES=600` · `ZAHRA_LEARN_AUTO=0`

**OSINT channels** (`zahra_agent.py:1410–1411`): `TWITTER_AUTH_TOKEN`, `TWITTER_CT0` (user-supplied session cookies; none committed)

**Misc:** `ZAHRA_CONFIG` (`core/zahra_config.py:292`) · `APPDATA`/`PATH` prepending for npm tools (`zahra_agent.py:544–550`)

## 6. External integrations (actually called, not just imported)

### 6.1 Services & APIs

| Integration | Where | How | Verified? |
|---|---|---|---|
| **Ollama (LLM)** | `ai_engine/llm_wrapper.py:114`, `core/zahra_controller.py`, `zahra_agent.py:2960` | OpenAI-compatible `POST /v1/chat/completions` to `ZAHRA_LLM_BASE_URL` (default `http://localhost:11434/v1`), model `zahra` / `zahra-unrestricted` | ✅ live: HTTP 200, real completions |
| **Ollama (embeddings)** | `ai_agent/adaptive_rag.py:29–30` | `nomic-embed-text` via `OLLAMA_BASE_URL` for hybrid RAG | present; recall verified via `/api/rag/stats` (1,285 findings) |
| **ChromaDB (local)** | `core/memory.py`, `zahra_data/ai_agent_chroma/`, `zahra_data/rag/` | Embedded vector store (SQLite-backed), fully local | ✅ live |
| **SQLite (local)** | `core/memory.py`, `zahra_data/zahra.db`, `zahra_brain.db` | Campaign/finding/skill persistence | ✅ live |
| **Bing search** | `zahra_agent.py:1302`, `ai_agent/web_search.py:6–7` | Bing RSS primary / Bing HTML — scraping, no API key | code present; not exercised in live run |
| **DuckDuckGo search** | `agents/base_agent.py:503`, `zahra_agent.py:1327,1355` | `https://html.duckduckgo.com/html/` scraping as fallback intel | code present |
| **Google CSE** | `ai_agent/web_search.py:40–42,111` | Only if `google_api_key`+`google_cx` set (none are) | optional, unconfigured |
| **Hugging Face** | `ai_agent/agent_core.py:49–52`, `ai_agent/hf_integration.py` | Inference API with `HF_TOKEN`, `Mistral-7B-Instruct-v0.2` (legacy `ai_agent` path only) | optional |
| **Twitter/X (OSINT)** | `zahra_agent.py:1410–1411` | User-provided `TWITTER_AUTH_TOKEN`/`TWITTER_CT0` session cookies | user-supplied; none set |

### 6.2 Third-party CLI tools the agents invoke as subprocesses

Executed on the host via `agents/base_agent.py:384–475` and the attack library (`zahra_agent.py:96–458`, 100+ command templates): `nmap`, `nuclei` (✅ verified live), `sqlmap`, `nikto`, `gobuster`, `ffuf`, `wpscan`, `xsstrike`, `zap-full-scan.py`, `masscan`, `davtest`, plus `curl`-based CVE probes (Log4Shell, Spring4Shell, Shellshock, Apache path-traversal, WebLogic, Jenkins, Elasticsearch). On Windows some run through the WSL bridge (`/dev/null`, `/tmp/...` paths in LLM-planned commands — known fragility, §8). Wordlists are expected at Kali paths (`/usr/share/wordlists/`) — missing on Windows.

### 6.3 Network exposure created by the app itself

- API server binds `0.0.0.0` by default (`interfaces/api_server.py:1118,1135`) with **CORS `allow_origins=["*"]` + `allow_credentials=True` (`:39–45`) and no authentication** on any route — including `/api/controller/cmd` (`:472`), which executes controller commands.
- `python main.py tunnel` (`interfaces/cli.py:191`; cloudflared parsing `main.py:254–265`, ngrok `:269–308`) deliberately exposes the dashboard to the public internet.
- WebSocket `/ws/attack` (`:958`) accepts `command` JSON from any connected client and can trigger campaigns.

## 7. Code health

### 7.1 Tests — effectively none

- Exactly **one test file exists**: `test_zahra_controller.py` (2.2 KB, repo root). No `tests/` package, no conftest, no fixtures.
- **`pytest` is not installed** in `.venv` (`No module named pytest`), so even that file isn't run by default. **No CI pipeline** exercises Python tests. Nothing in `core/`, `agents/`, `ai_engine/`, or `interfaces/` is under test. (The `*_test` files under `services/omniroute/tests/` belong to the vendored Node project, not ZAHRA.)

### 7.2 Type checking & linting

- Annotations are modern (`X | None`) but typing is inconsistent, with `# type: ignore` sprinkled in (`interfaces/cli.py:23,45–46`). A `.mypy_cache/` exists (mypy was run ad hoc) but mypy is not in `requirements.txt` and there is no clean full-repo mypy pass. **`requires-python = ">=3.9"` (`pyproject.toml:29`) is untested and unlikely** — the code uses PEP 604 unions at runtime; dev venv is Python 3.14. Go side is cleaner: `go vet` passes on `cli/...` and `cmd/...`.

### 7.3 Structural risks

- **God files:** `zahra_agent.py` ≈ 3,600 lines (brain + attack library + OSINT + memory + LLM glue in one module); `interfaces/api_server.py` 1,163 lines; `interfaces/cli.py` ≈ 800 lines.
- **Two parallel LLM config systems with conflicting defaults** (`core/zahra_config.py` defaults `ollama` vs `ai_engine/llm_wrapper.py:57` defaults `offline` — §5.2): a real foot-gun where one path silently runs the simulated backend.
- **Three overlapping orchestration layers:** `AgenticCore` (`core/agentic_core.py`), `Orchestrator`/`Router` (`core/orchestrator.py`, `core/router.py`), and `ZahraController`/`SwarmManager` (`core/zahra_controller.py`, `agents/swarm_manager.py`). `AgenticCore.should_start_exploit` (`core/agentic_core.py:224–264`) is **not wired into the live controller path** — a second brain nothing starts.
- **Service-locator globals:** `api_server.py:79–86` holds module-level `orchestrator/blackboard/controller/...` set by `setup_api` (`:1050–1068`) — fragile ordering, hard to test.
- **Circular-import defenses instead of fixes:** `core/tactical_intel.py:26–34` wraps `ai_agent` imports in `try/except` — works, but hides breakage silently.
- **Broad exception swallowing:** recurring `except Exception: # pragma: no cover` (`core/tactical_intel.py:87–93,148–149,190–191`) degrades silently instead of surfacing errors.

### 7.4 Error handling & duplication

- Subprocess execution has timeouts (`base_agent.py:384–475`), but the controller's autonomous loop defaults to **`max_iterations=1000` with no wall-clock budget** — a bad LLM plan can spin for a long time (observed live with a WSL `masscan` command).
- Duplicated logic: nuclei/sqlmap command construction in both `agents/scan_agent.py:56` / `agents/exploit_agent.py:59` and `ai_engine/decision_maker.py:347`; offline reply text duplicated between `ai_engine/llm_wrapper.py:273` and agent prompts.
- Frontend (`script.js`, 1,410 lines) is a single class, no build step, no tests — fine for a demo, fragile long-term.
- In-process state is lost on restart: campaign scheduler, AI conversation memory (`api_server.py:92–105`), and WebSocket connections are all module-level globals — no persistence layer behind the dashboard.

## 8. Risk flags

### 8.1 Will fail / embarrass in a live demo (verified on this machine)

| # | Risk | Evidence | Mitigation |
|---|---|---|---|
| 1 | **Documented `full pentest <target>` syntax does not work** — argparse exits 2 with "unrecognized arguments: <target>". Only `full <target>` is valid. | `interfaces/cli.py:10`, `main.py` docstring vs. live run | Fix docstrings before any demo/submission |
| 2 | **Offline mode hangs** — `ZAHRA_LLM_BACKEND=offline scan 127.0.0.1` never returned (killed at 90 s); offline scan agent runs full-template `nuclei -silent` against whatever is listening. | verified live | Never demo offline mode |
| 3 | **LLM-planned Linux-only commands on Windows** — the 1.5 B local model planned `masscan -iL /dev/null ... --excludefile /tmp/...`, executed via WSL bridge and stalled. | observed live in `full` run | Demo on Kali, or restrict to `scan` |
| 4 | **Autonomous loop has no wall-clock budget** — `max_iterations=1000` default, so a bad plan can spin indefinitely. | `core/zahra_config.py` (UnrestrictedSettings) | Set a low cap for demos |
| 5 | **First-run latency** — controller build + torch/transformers import takes ~10–30 s before any output; CLI banner does not mask it. | observed | Pre-warm before demo |
| 6 | **Port mismatch** — `main.py serve` defaults to 8080, README says 8090 (run.ps1 forces 8090). | `interfaces/cli.py` serve cmd | Align docs |
| 7 | **Go `pentestswarm serve` cannot start** — `services/pentest-swarm/config.yaml` missing (only `config.example.yaml`) and needs an API key. Go side builds/vets clean; CLI works. | earlier verification | Present as reference implementation or add config |
| 8 | **LLM quality** — `zahra:latest` is a ~1 GB Qwen-1.5B derivative; JSON output is workable for `scan` but occasionally nonsensical for recon/exploit planning. | observed | Use a larger model if demoing `full` |

### 8.2 Security posture of the app itself (important for judging)

- **Zero authentication on every API route** — including `/api/controller/cmd` (executes controller commands) and `/api/chat` — with **CORS `allow_origins=["*"]` + `allow_credentials=True`** (`interfaces/api_server.py:39–45`) and a default bind of `0.0.0.0` (`:1118,1135`). Anyone on the same network can drive the platform.
- **Dashboard "login" is cosmetic** — `attachAuthListeners` (`script.js`) performs no server-side auth check.
- **WebSocket `/ws/attack`** accepts command JSON from any connected client and can launch campaigns (`api_server.py:958`).
- **`python main.py tunnel`** publishes the unauthenticated dashboard to the public internet via cloudflared/ngrok (`main.py:254–308`).
- Minor: dashboard chat mixes Arabic strings into the English UI (`script.js:1013,1026` — "زهرة تفكر...", "خطأ:").

### 8.3 Authorized-use wording (residual, post-cleanup)

The Step-2 rewrite removed all "no ethical constraints / never refuses" phrasing from docs, prompts, and banners — final scan returned **CLEAN**. Intentionally retained *functional identifiers* (visible to code readers, but execution toggles rather than claims): env var `ZAHRA_UNRESTRICTED`, class `UnrestrictedSettings` (`core/zahra_config.py:141`), JSON key `"unrestricted"`, Ollama tag `zahra-unrestricted`, `self.unrestricted` flag (`zahra_agent.py:63`, default **on**). The attack library and C2/MITM agents are genuine offensive tooling — the README must carry a prominent **Legal & Ethical Use (authorized testing only)** section, currently drafted but not finalized.

### 8.4 Clearly unfinished / stubs (complete list)

| Item | Location | Status |
|---|---|---|
| Blackboard subscriber notification | `core/blackboard.py` `_notify()` | **Stub** — callbacks logged, never dispatched |
| Findings → blackboard typing | `core/blackboard.py` `_write_to_blackboard()` | **Hardcoded** `FindingType.RECON`, `pheromone_base=1.0` regardless of actual finding type |
| Second brain never started | `core/agentic_core.py:94–304` (`AgenticCore`) | **Fully written, never wired** into the live controller path; `should_start_exploit` (`:224–264`) is dead code in practice |
| Scheduler persistence | `api_server.py:92–101` | In-memory only; resets on restart |
| Tests | repo root | **1 file** (`test_zahra_controller.py`); pytest not installed; no CI |
| README media | `README.md` | Demo GIF / screenshots are placeholders |
| Root README rewrite | `README.md` | Polished draft exists, not yet saved (awaiting approval) |
| `zahra_data/zahra_config.json` | runtime config | Stale `base_url` (missing `/v1`); not loaded by default path, but a landmine if ever read |
| `requires-python >= 3.9` | `pyproject.toml:29` | Untested/unlikely (PEP 604 unions evaluated at runtime) |

## 9. Verdict

- **Works, verified live on this machine:** Go build + vet + CLI (`pentestswarm --help`); Python imports + `py_compile` across all packages; Ollama LLM round-trip (`zahra:latest`); `python main.py status` (exit 0, RAG loaded — 1,285 findings); a complete `scan` campaign end-to-end (real nuclei + real LLM, exit 0 in ~16 s, findings written); dashboard + REST + WebSocket with every frontend call mapped to a real route; pheromone decay + pheromone-sorted blackboard queries (verified numerically); multi-agent concurrent `full` run via the async MemoryQueue (all 5 agents launched).
- **Real but flaky:** `full <target>` on Windows (WSL bridge, unbounded loop, small model); offline mode (hangs); nuclei/sqlmap runtimes vary by target.
- **Stubbed / dead code:** blackboard `_notify()`, `AgenticCore`, scheduler persistence, tests/CI.
- **Biggest non-code risk:** the unauthenticated, CORS-wide-open API with a command-execution endpoint — acceptable on a lab machine, but a security-conscious judge will find it. Disclose it proactively.

*Method: read-only audit of the working tree; every claim cites file:line. Runtime claims were verified by executing the platform on this machine (Windows 11, Python 3.14.4 venv, Go 1.26.2, Node 24, Ollama 0.32.14 with `zahra:latest`). No code was modified during this audit.*

