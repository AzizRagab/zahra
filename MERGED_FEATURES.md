# Merged from Pentest-Swarm-AI

Logical merge only — Pentest-Swarm-AI (Go) stays a reference implementation
under `services/pentest-swarm/`; nothing there is executed by ZAHRA. The ideas
below were ported into ZAHRA's existing Python swarm (`core/`, `agents/`)
instead of vendoring Go code into a Python runtime.

## Already equivalent in ZAHRA
- Stigmergic blackboard with pheromone-weighted findings — ZAHRA's
  `ZahraController` blackboard already implements this; naming aligned with
  Pentest-Swarm-AI's finding types (`SUBDOMAIN`, `PORT_OPEN`, `CVE_MATCH`,
  `EXPLOIT_CHAIN`, `EXPLOIT_RESULT`) for anyone cross-referencing playbooks.
- Multi-backend LLM wrapper (Ollama / OpenAI-compatible / offline) —
  `ai_engine/llm_wrapper.py`, now defaulting to the local Ollama `zahra`
  model built from `Modelfile.zahra` (see Model wiring below).

## Ported as follow-up work (not yet implemented)
- **SARIF report export** — Pentest-Swarm-AI's report agent emits
  `md/html/json/sarif`. ZAHRA's `agents/skills/reporting.py` currently does
  markdown/JSON only; add a SARIF writer so findings drop straight into
  GitHub code scanning / CI.
- **Evidence dedup on the blackboard** — Pentest-Swarm-AI dedups findings
  before they trigger downstream agents. Worth adding to ZAHRA's blackboard
  write path to avoid duplicate agent wake-ups on noisy recon.
- **GitHub Action packaging** — `deploy/github-action/` in Pentest-Swarm-AI
  is a good template for a ZAHRA CI action once the Docker image is public.

## Model wiring (Ollama)
- `core/zahra_config.py` now defaults to `backend=ollama`, `model=zahra`,
  `base_url=http://localhost:11434/v1` when no env vars / config file
  override it.
- `install.sh` (Kali/Ubuntu) and `install.ps1` (Windows) both install Ollama
  if missing, pull the `llama3.1:8b` base model, and run
  `ollama create zahra -f Modelfile.zahra` to build the ZAHRA model.
- Override at any time with `ZAHRA_LLM_BACKEND` / `ZAHRA_LLM_MODEL` /
  `ZAHRA_LLM_BASE_URL` env vars, e.g. to point at Claude or OpenAI instead.
