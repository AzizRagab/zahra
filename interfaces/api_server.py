"""FastAPI Backend Server for Zahra Platform.

Provides REST API and WebSocket for:
- Campaign management
- Real-time event streaming
- Agent control
- RAG system queries
- Blackboard monitoring
- Dashboard frontend serving
- ZahraController (personal operator-directed controller)
"""

from __future__ import annotations

import asyncio
import html as _html
import json
import logging
import time
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, Response
from pydantic import BaseModel

logger = logging.getLogger("zahra.api")

# Create FastAPI app
app = FastAPI(
    title="Zahra - Agentic Pentest System",
    description="AI-Powered Penetration Testing Swarm Platform",
    version="2.0.0",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -- Serve Dashboard Frontend ----------------------------------------------

dashboard_dir = Path(__file__).resolve().parent / "dashboard"
index_file = dashboard_dir / "index.html"


@app.get("/", include_in_schema=False)
async def serve_dashboard() -> Any:
    """Serve the dashboard HTML page."""
    if index_file.exists():
        return FileResponse(index_file)
    raise HTTPException(status_code=404, detail="Dashboard not found")


@app.get("/style.css", include_in_schema=False)
async def serve_css() -> Any:
    """Serve the dashboard CSS."""
    css_file = dashboard_dir / "style.css"
    if css_file.exists():
        return FileResponse(css_file, media_type="text/css")
    raise HTTPException(status_code=404, detail="style.css not found")


@app.get("/script.js", include_in_schema=False)
async def serve_js() -> Any:
    """Serve the dashboard JavaScript."""
    js_file = dashboard_dir / "script.js"
    if js_file.exists():
        return FileResponse(js_file, media_type="application/javascript")
    raise HTTPException(status_code=404, detail="script.js not found")

# Global references (will be set by main.py)
orchestrator = None
agentic_core = None
blackboard = None
event_emitter = None
database = None
ai_agent = None
controller = None  # ZahraController instance (operator-directed)
brain = None  # ZahraAgent instance (autonomous brain)

# WebSocket connections
active_connections: list[WebSocket] = []

# ── Auto-schedule state (campaign scheduler) ──────────────────────────────
_scheduler = {
    "enabled": False,
    "interval_seconds": 3600,
    "command": "full 127.0.0.1",
    "last_run": None,
    "next_run": None,
    "runs": 0,
    "errors": 0,
}
_scheduler_task: asyncio.Task | None = None

# ── Multi-turn AI conversation memory (per session) ──────────────────────
_conversations: dict[str, list[dict[str, str]]] = {}
_MAX_CONVERSATION_TURNS = 24


def _conversation(session: str) -> list[dict[str, str]]:
    if session not in _conversations:
        _conversations[session] = []
    return _conversations[session]


def _prune_conversation(session: str) -> None:
    conv = _conversations.get(session, [])
    if len(conv) > _MAX_CONVERSATION_TURNS:
        _conversations[session] = conv[-_MAX_CONVERSATION_TURNS:]


# Pydantic models
class CampaignCreate(BaseModel):
    command: str


class CampaignResponse(BaseModel):
    id: str
    command: str
    target: str
    intent: str
    status: str
    findings_count: int


class StatusResponse(BaseModel):
    campaigns: int
    active: int
    completed: int
    budget: dict[str, Any]
    memory: dict[str, Any]
    agentic_core: dict[str, Any]


# Routes
@app.get("/api/info")
async def root() -> dict[str, Any]:
    """Root API endpoint."""
    return {
        "name": "Zahra - Agentic Pentest System",
        "version": "2.0.0",
        "controller": "zahra",
        "attribution": "Amshararou",
        "mode": "unrestricted",
        "status": "running",
        "features": [
            "ZahraController",
            "Agentic Core",
            "Swarm Coordination",
            "Adaptive RAG",
            "Auto-Evasion",
            "Web Search",
            "Event System",
            "No LLaMA (non-LLaMA enforced)",
        ],
    }


@app.get("/api/status")
async def get_status() -> dict[str, Any]:
    """Get platform status."""
    if not orchestrator:
        return {"error": "Platform not initialized"}

    status = orchestrator.status()

    # Add agentic core status
    if agentic_core:
        status["agentic_core"] = agentic_core.status()

    # Add controller status if available
    if controller:
        status["controller"] = controller.status()

    return status


@app.post("/api/campaign")
async def create_campaign(campaign: CampaignCreate) -> dict[str, Any]:
    """Create a new campaign."""
    if not orchestrator:
        return {"error": "Platform not initialized"}

    try:
        c = orchestrator.create_campaign(campaign.command)
        return {
            "id": c.id,
            "command": c.command,
            "target": c.target,
            "intent": c.intent.value,
            "status": c.status.value,
        }
    except Exception as exc:
        return {"error": str(exc)}


@app.post("/api/campaign/{campaign_id}/start")
async def start_campaign(campaign_id: str) -> dict[str, Any]:
    """Start a campaign."""
    if not orchestrator:
        return {"error": "Platform not initialized"}

    try:
        # Run in background thread
        import asyncio
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, orchestrator.run_campaign, campaign_id)
        return {"status": "started", "campaign_id": campaign_id}
    except Exception as exc:
        return {"error": str(exc)}


@app.get("/api/campaign/{campaign_id}")
async def get_campaign(campaign_id: str) -> dict[str, Any]:
    """Get campaign details."""
    if not orchestrator:
        return {"error": "Platform not initialized"}

    campaign = orchestrator.get_campaign(campaign_id)
    if not campaign:
        return {"error": "Campaign not found"}

    return campaign.to_dict()


@app.get("/api/campaigns")
async def list_campaigns() -> dict[str, Any]:
    """List all campaigns."""
    if not orchestrator:
        return {"error": "Platform not initialized"}

    campaigns = orchestrator.list_campaigns()
    return {
        "campaigns": [
            {
                "id": c.id,
                "target": c.target,
                "status": c.status.value,
                "findings_count": len(c.findings),
            }
            for c in campaigns
        ]
    }


@app.get("/api/blackboard")
async def get_blackboard() -> dict[str, Any]:
    """Get blackboard findings."""
    if not blackboard:
        return {"error": "Blackboard not initialized"}

    # Query all findings
    from core.blackboard import Predicate
    findings = blackboard.query(Predicate())

    return {
        "findings": [
            {
                "id": f.id,
                "type": f.type.value,
                "target": f.target,
                "agent": f.agent_name,
                "pheromone": f.pheromone,
                "created_at": f.created_at.isoformat(),
            }
            for f in findings[:100]  # Limit to 100
        ]
    }


@app.get("/api/rag/stats")
async def get_rag_stats() -> dict[str, Any]:
    """Get RAG system statistics."""
    if not orchestrator or not orchestrator.memory:
        return {"error": "Memory not initialized"}

    return orchestrator.memory.summary()


@app.get("/api/db/tables")
async def db_tables() -> dict[str, Any]:
    """List all tables in the database."""
    if not database:
        return {"error": "Database not initialized", "tables": []}
    try:
        return {"tables": database.list_tables()}
    except Exception as exc:
        return {"error": str(exc), "tables": []}


@app.get("/api/db/table/{table_name}")
async def db_table_data(table_name: str) -> dict[str, Any]:
    """Get data from a specific table."""
    if not database:
        return {"error": "Database not initialized"}
    try:
        return database.get_table_data(table_name)
    except ValueError as exc:
        return {"error": str(exc)}
    except Exception as exc:
        return {"error": str(exc)}


# -- AI Agent Endpoints -------------------------------------------------------

@app.get("/api/agent/status")
async def agent_status() -> dict[str, Any]:
    """Get AI Agent status."""
    if not ai_agent:
        return {"error": "AI Agent not initialized"}
    status = ai_agent.status()
    if ai_agent.rag:
        status["rag"] = ai_agent.rag.stats()
    return status


@app.post("/api/agent/think")
async def agent_think(request: dict[str, Any]) -> dict[str, Any]:
    """Make the AI Agent think about a task (multi-turn aware).

    Pass a ``session`` id to keep conversation context between calls.
    """
    if not ai_agent:
        return {"error": "AI Agent not initialized"}
    task = request.get("task", "")
    if not task:
        return {"error": "No task provided"}
    session = request.get("session", "default")
    try:
        conv = _conversation(session)
        context = dict(request.get("context") or {})
        # Feed the last turns as conversation context (multi-turn memory)
        if conv:
            context["conversation_history"] = [
                {"role": m["role"], "content": m["content"]} for m in conv[-10:]
            ]
        result = ai_agent.think(task, context)
        conv.append({"role": "user", "content": task})
        reply = result.get("analysis") or result.get("command") or result.get(
            "reasoning") or result.get("response") or "OK"
        conv.append({"role": "assistant", "content": str(reply)[:2000]})
        _prune_conversation(session)
        result["session"] = session
        return result
    except Exception as exc:
        return {"error": str(exc)}


@app.post("/api/agent/think/reset")
async def agent_think_reset(request: dict[str, Any]) -> dict[str, Any]:
    """Clear the multi-turn conversation memory for a session."""
    session = request.get("session", "default")
    _conversations.pop(session, None)
    return {"session": session, "cleared": True, "turns": 0}


@app.post("/api/agent/analyze")
async def agent_analyze(request: dict[str, Any]) -> dict[str, Any]:
    """Make the AI Agent analyze data."""
    if not ai_agent:
        return {"error": "AI Agent not initialized"}
    data = request.get("data", "")
    prompt = request.get("prompt", "Analyze this data for security issues")
    try:
        return ai_agent.analyze(data, prompt)
    except Exception as exc:
        return {"error": str(exc)}


@app.post("/api/agent/run")
async def agent_run(request: dict[str, Any]) -> dict[str, Any]:
    """Run the AI Agent on a task (full ReAct loop)."""
    if not ai_agent:
        return {"error": "AI Agent not initialized"}
    task = request.get("task", "")
    if not task:
        return {"error": "No task provided"}
    iterations = int(request.get("iterations", 5))
    ai_agent.config.max_iterations = iterations
    try:
        return await asyncio.to_thread(ai_agent.run, task)
    except Exception as exc:
        return {"error": str(exc)}


@app.get("/api/agent/search")
async def agent_search(q: str = "") -> dict[str, Any]:
    """Search the web using the AI Agent's search."""
    if not ai_agent or not ai_agent.web_search:
        return {"error": "Web search not available"}
    if not q:
        return {"error": "No query provided"}
    try:
        return {"results": await asyncio.to_thread(ai_agent.web_search.search, q)}
    except Exception as exc:
        return {"error": str(exc)}


@app.get("/api/agent/rag/recent")
async def rag_recent(category: str = "", limit: int = 20) -> dict[str, Any]:
    """Get recent RAG memory entries."""
    if not ai_agent or not ai_agent.rag:
        return {"error": "RAG not available"}
    entries = ai_agent.rag.recall(category or None, limit)
    return {"entries": entries}


# -- ZahraController Endpoints -----------------------------------------------

@app.get("/api/controller")
async def controller_status() -> dict[str, Any]:
    """Get ZahraController status (operator-directed controller)."""
    if not controller:
        return {"error": "ZahraController not initialized"}
    return controller.status()


@app.post("/api/controller/think")
async def controller_think(request: dict[str, Any]) -> dict[str, Any]:
    """Ask the ZahraController's AI agent to think about a task."""
    if not controller:
        return {"error": "ZahraController not initialized"}
    task = request.get("task", "")
    if not task:
        return {"error": "No task provided"}
    try:
        return await asyncio.to_thread(controller.think, task, request.get("context"))
    except Exception as exc:
        return {"error": str(exc)}


@app.post("/api/controller/decide")
async def controller_decide(request: dict[str, Any]) -> dict[str, Any]:
    """Ask the ZahraController to make a strategic decision."""
    if not controller:
        return {"error": "ZahraController not initialized"}
    command = request.get("command", "")
    if not command:
        return {"error": "No command provided"}
    try:
        return await asyncio.to_thread(controller.decide, command)
    except Exception as exc:
        return {"error": str(exc)}


@app.post("/api/controller/deploy")
async def controller_deploy(request: dict[str, Any]) -> dict[str, Any]:
    """Deploy a specific agent via the ZahraController."""
    if not controller:
        return {"error": "ZahraController not initialized"}
    agent_name = request.get("agent", "")
    target = request.get("target", "")
    if not agent_name or not target:
        return {"error": "Agent name and target are required"}
    try:
        finding = await asyncio.to_thread(
            controller.deploy_agent, agent_name, target, request.get("options")
        )
        return finding.to_dict()
    except Exception as exc:
        return {"error": str(exc)}


@app.post("/api/controller/cmd")
async def controller_cmd(request: dict[str, Any]) -> dict[str, Any]:
    """Execute a system command directly via the ZahraController (unrestricted)."""
    if not controller:
        return {"error": "ZahraController not initialized"}
    command = request.get("command", "")
    timeout = int(request.get("timeout", 300))
    if not command:
        return {"error": "No command provided"}
    try:
        return await asyncio.to_thread(controller.run_command, command, timeout)
    except Exception as exc:
        return {"error": str(exc)}


@app.get("/api/controller/campaigns")
async def controller_campaigns() -> dict[str, Any]:
    """List all campaigns managed by the ZahraController."""
    if not controller:
        return {"error": "ZahraController not initialized"}
    return {"campaigns": [c.to_dict() for c in controller.list_campaigns()]}


@app.get("/api/controller/agents")
async def controller_agents() -> dict[str, Any]:
    """List all agents in the ZahraController's swarm."""
    if not controller:
        return {"error": "ZahraController not initialized"}
    return {"agents": controller.list_agents()}


# -- Full Swarm Control ------------------------------------------------------

@app.get("/api/agents")
async def agents_full() -> dict[str, Any]:
    """Rich per-agent status (enablement, rate limit, iterations, logs count)."""
    if not controller:
        return {"error": "ZahraController not initialized"}
    return {"agents": controller.get_agents_full()}


@app.post("/api/agents/{agent_name}/deploy")
async def agents_deploy(agent_name: str, request: dict[str, Any]) -> dict[str, Any]:
    """Deploy a single agent against a target."""
    if not controller:
        return {"error": "ZahraController not initialized"}
    target = request.get("target", "")
    if not target:
        return {"error": "Target is required"}
    try:
        finding = await asyncio.to_thread(
            controller.deploy_agent, agent_name, target, request.get("options")
        )
        return finding.to_dict()
    except Exception as exc:
        return {"error": str(exc)}


@app.post("/api/agents/{agent_name}/enabled")
async def agents_enabled(agent_name: str, request: dict[str, Any]) -> dict[str, Any]:
    """Enable or disable an agent."""
    if not controller:
        return {"error": "ZahraController not initialized"}
    return controller.set_agent_enabled(agent_name, bool(request.get("enabled", True)))


@app.post("/api/agents/{agent_name}/rate-limit")
async def agents_rate_limit(agent_name: str, request: dict[str, Any]) -> dict[str, Any]:
    """Set max requests-per-second for an agent (0 = unlimited)."""
    if not controller:
        return {"error": "ZahraController not initialized"}
    return controller.set_agent_rate_limit(agent_name, float(request.get("rps", 0)))


@app.post("/api/agents/{agent_name}/max-iterations")
async def agents_max_iterations(agent_name: str, request: dict[str, Any]) -> dict[str, Any]:
    """Override max iterations for an agent."""
    if not controller:
        return {"error": "ZahraController not initialized"}
    return controller.set_agent_max_iterations(agent_name, int(request.get("iterations", 10)))


@app.get("/api/agents/{agent_name}/logs")
async def agents_logs(agent_name: str, limit: int = 100) -> dict[str, Any]:
    """Recent per-agent log lines."""
    if not controller:
        return {"error": "ZahraController not initialized"}
    return {"agent": agent_name, "logs": controller.get_agent_logs(agent_name, limit)}


@app.get("/api/controller/blackboard")
async def controller_blackboard() -> dict[str, Any]:
    """Get findings from the ZahraController's blackboard."""
    if not controller:
        return {"error": "ZahraController not initialized"}
    return {"findings": controller.get_blackboard_findings()}


@app.get("/api/controller/memory")
async def controller_memory() -> dict[str, Any]:
    """Get memory summary from the ZahraController."""
    if not controller:
        return {"error": "ZahraController not initialized"}
    return controller.get_memory_summary()


@app.post("/api/controller/run-campaign")
async def controller_run_campaign(request: dict[str, Any]) -> dict[str, Any]:
    """Create and run a campaign via the ZahraController."""
    if not controller:
        return {"error": "ZahraController not initialized"}
    command = request.get("command", "")
    if not command:
        return {"error": "No command provided"}
    try:
        campaign = await asyncio.to_thread(controller.run_campaign, command)
        return campaign.to_dict()
    except Exception as exc:
        return {"error": str(exc)}


# -- Auto-Schedule (scheduled campaigns) --------------------------------------

async def _scheduler_loop() -> None:
    """Background task: every interval, run the scheduled command."""
    global _scheduler
    while True:
        interval = max(5, float(_scheduler["interval_seconds"]))
        await asyncio.sleep(interval)
        if not _scheduler.get("enabled"):
            continue
        if not controller:
            continue
        command = _scheduler.get("command") or "full 127.0.0.1"
        _scheduler["last_run"] = time.time()
        _scheduler["next_run"] = time.time() + interval
        _scheduler["runs"] += 1
        try:
            campaign = await asyncio.to_thread(controller.run_campaign, command)
            broadcast_event({
                "type": "scheduled_run",
                "command": command,
                "campaign_id": campaign.id,
                "findings": len(campaign.findings),
                "status": campaign.status.value,
            })
        except Exception as exc:  # noqa: BLE001
            _scheduler["errors"] += 1
            logger.error("Scheduled campaign failed: %s", exc)


def _ensure_scheduler_task() -> None:
    global _scheduler_task
    if _scheduler_task is None:
        _scheduler_task = asyncio.create_task(_scheduler_loop())


@app.on_event("startup")
async def _start_scheduler_on_startup() -> None:
    """Start the auto-schedule loop once the event loop is running."""
    _ensure_scheduler_task()


@app.get("/api/scheduler/config")
async def scheduler_config() -> dict[str, Any]:
    """Get the auto-schedule configuration and state."""
    return dict(_scheduler)


@app.post("/api/scheduler/config")
async def scheduler_set_config(request: dict[str, Any]) -> dict[str, Any]:
    """Update the auto-schedule configuration."""
    global _scheduler
    if "enabled" in request:
        _scheduler["enabled"] = bool(request["enabled"])
    if "interval_seconds" in request:
        _scheduler["interval_seconds"] = max(5, int(request["interval_seconds"]))
    if "command" in request:
        _scheduler["command"] = str(request["command"]).strip()
    if _scheduler["enabled"]:
        _scheduler["next_run"] = time.time() + float(_scheduler["interval_seconds"])
    else:
        _scheduler["next_run"] = None
    _ensure_scheduler_task()
    return dict(_scheduler)


@app.post("/api/scheduler/run-now")
async def scheduler_run_now() -> dict[str, Any]:
    """Trigger the scheduled command immediately (fire-and-forget)."""
    if not controller:
        return {"error": "ZahraController not initialized"}
    command = _scheduler.get("command") or "full 127.0.0.1"
    try:
        # Run in the thread pool — endpoint returns instantly, campaign runs in background.
        loop = asyncio.get_running_loop()
        loop.run_in_executor(None, controller.run_campaign, command)
        _scheduler["last_run"] = time.time()
        _scheduler["runs"] += 1
        broadcast_event({
            "type": "scheduled_run",
            "command": command,
            "campaign_id": "triggered",
            "status": "running",
        })
        return {"started": True, "campaign_id": "triggered", "command": command}
    except Exception as exc:
        return {"started": False, "error": str(exc)}


# -- Report Export (HTML / JSON) ----------------------------------------------

def _report_context() -> dict[str, Any]:
    """Gather findings, campaigns and stats for the report."""
    findings: list[dict[str, Any]] = []
    if orchestrator and orchestrator.memory:
        findings = [f.to_dict() for f in orchestrator.memory.all_findings()]
    elif database:
        findings = database.get_findings(limit=500)

    campaigns: list[dict[str, Any]] = []
    if controller:
        campaigns = [c.to_dict() for c in controller.list_campaigns()]
    elif orchestrator:
        campaigns = [c.to_dict() for c in orchestrator.list_campaigns()]

    rag_stats = {}
    if ai_agent and ai_agent.rag:
        rag_stats = ai_agent.rag.stats()
    elif orchestrator and orchestrator.memory:
        rag_stats = orchestrator.memory.summary()

    return {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "findings": findings,
        "campaigns": campaigns,
        "rag_stats": rag_stats,
    }


def _severity_order(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
        str(sev).lower(), 5
    )


@app.get("/api/reports/export")
async def reports_export(format: str = "html") -> Any:
    """Export a full pentest report. ``format=html`` renders a printable
    standalone page (use the browser's Save-as-PDF), ``format=json`` dumps raw data.
    """
    ctx = _report_context()
    findings = sorted(ctx["findings"], key=lambda f: _severity_order(f.get("severity")))
    campaigns = ctx["campaigns"]
    rag = ctx["rag_stats"] or {}

    if format == "json":
        import json as _json

        content = _json.dumps(ctx, indent=2, ensure_ascii=False)
        return Response(content=content, media_type="application/json")

    sev_pill = lambda s: f"<span class='pill {s}'>{str(s).upper()}</span>"
    rows = "".join(
        f"<tr><td>{sev_pill(f.get('severity', 'info'))}</td>"
        f"<td>{_html.escape(str(f.get('type', f.get('finding_type', '')) or ''))}</td>"
        f"<td>{_html.escape(str(f.get('description', '')) or '')}</td>"
        f"<td>{_html.escape(str(f.get('target', '')) or '')}</td>"
        f"<td>{_html.escape(str(f.get('agent_name', '')) or '')}</td>"
        f"<td>{round(float(f.get('confidence', 0)) * 100)}%</td></tr>"
        for f in findings
    ) or "<tr><td colspan='6' class='empty'>No findings recorded.</td></tr>"

    crows = "".join(
        f"<tr><td>{_html.escape(str(c.get('id', ''))[:12])}</td>"
        f"<td>{_html.escape(str(c.get('target', '')) or '')}</td>"
        f"<td>{_html.escape(str(c.get('intent', '')) or '')}</td>"
        f"<td>{sev_pill(c.get('status', ''))}</td>"
        f"<td>{len(c.get('findings', []) or [])}</td></tr>"
        for c in campaigns
    ) or "<tr><td colspan='5' class='empty'>No campaigns recorded.</td></tr>"

    rag_rows = "".join(
        f"<tr><td>{_html.escape(str(k))}</td><td>{v}</td></tr>"
        for k, v in (rag.get("categories") or {}).items()
    ) or "<tr><td colspan='2' class='empty'>No RAG categories.</td></tr>"

    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>ZAHRA Pentest Report</title>
<style>
  :root {{ --bg:#05050d; --panel:#0a0f1e; --line:#1c2938; --neon:#c6ff00; --ice:#7ae2ff; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; padding:32px; font-family:'IBM Plex Mono',Consolas,monospace;
    background:var(--bg); color:#c7d4ea; }}
  .report {{ max-width:1100px; margin:0 auto; }}
  h1 {{ font-family:'Orbitron',sans-serif; letter-spacing:.2em; color:var(--neon); margin:0 0 4px; }}
  h2 {{ color:var(--ice); letter-spacing:.12em; border-bottom:1px solid var(--line); padding-bottom:8px; margin-top:36px; }}
  .meta {{ color:#6b7a99; font-size:.8rem; margin-bottom:24px; }}
  table {{ width:100%; border-collapse:collapse; font-size:.75rem; }}
  th {{ text-align:left; color:var(--ice); padding:10px; border-bottom:1px solid var(--line);
    text-transform:uppercase; letter-spacing:.14em; font-size:.62rem; }}
  td {{ padding:10px; border-bottom:1px solid rgba(28,41,56,.5); color:#b9c6dd; }}
  tr:hover td {{ background:rgba(122,226,255,.05); }}
  .pill {{ display:inline-block; padding:2px 10px; border-radius:999px; font-size:.6rem; letter-spacing:.1em; }}
  .pill.critical {{ background:rgba(255,45,85,.15); color:#ff6b8a; border:1px solid rgba(255,45,85,.4); }}
  .pill.high {{ background:rgba(255,92,46,.15); color:#ff8a5c; border:1px solid rgba(255,92,46,.4); }}
  .pill.medium {{ background:rgba(255,180,46,.15); color:#ffb42e; border:1px solid rgba(255,180,46,.4); }}
  .pill.low {{ background:rgba(122,226,255,.12); color:#7ae2ff; border:1px solid rgba(122,226,255,.35); }}
  .pill.info,.pill.completed {{ background:rgba(198,255,0,.1); color:#c6ff00; border:1px solid rgba(198,255,0,.3); }}
  .pill.running,.pill.queued,.pill.pending {{ background:rgba(255,180,46,.12); color:#ffb42e; border:1px solid rgba(255,180,46,.35); }}
  .pill.failed,.pill.blocked {{ background:rgba(255,45,85,.15); color:#ff6b8a; border:1px solid rgba(255,45,85,.4); }}
  .empty {{ text-align:center; color:#46536b; padding:16px; }}
  .stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; margin:16px 0; }}
  .stat {{ background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:14px; }}
  .stat b {{ display:block; font-size:1.6rem; color:var(--neon); }}
  .stat span {{ font-size:.62rem; color:#6b7a99; letter-spacing:.14em; text-transform:uppercase; }}
  @media print {{ body {{ background:#fff; color:#111; }} td {{ color:#222; }} }}
</style></head><body><div class="report">
  <h1>ZAHRA — PENTEST REPORT</h1>
  <div class="meta">Generated: {_html.escape(ctx['generated_at'])} &middot; AI-Powered Swarm &middot; Attribution: Amshararou</div>

  <div class="stats">
    <div class="stat"><b>{len(findings)}</b><span>Findings</span></div>
    <div class="stat"><b>{len(campaigns)}</b><span>Campaigns</span></div>
    <div class="stat"><b>{sum(1 for f in findings if str(f.get('severity','')).lower() in ('critical','high'))}</b><span>High+</span></div>
    <div class="stat"><b>{rag.get('total_entries', 0)}</b><span>RAG Entries</span></div>
  </div>

  <h2>1 &middot; Findings</h2>
  <table><thead><tr><th>Severity</th><th>Type</th><th>Description</th><th>Target</th><th>Agent</th><th>Confidence</th></tr></thead>
  <tbody>{rows}</tbody></table>

  <h2>2 &middot; Campaigns</h2>
  <table><thead><tr><th>ID</th><th>Target</th><th>Intent</th><th>Status</th><th>Findings</th></tr></thead>
  <tbody>{crows}</tbody></table>

  <h2>3 &middot; RAG Memory</h2>
  <table><thead><tr><th>Category</th><th>Entries</th></tr></thead>
  <tbody>{rag_rows}</tbody></table>
</div></body></html>"""
    return HTMLResponse(content=page)


# -- Zahra Agent Chat Endpoint ----------------------------------------------

_brain_singleton = None


def get_brain():
    """Lazily create the shared ZahraAgent brain (unrestricted by default)."""
    global _brain_singleton
    if _brain_singleton is None:
        from zahra_agent import ZahraAgent
        _brain_singleton = ZahraAgent()
    return _brain_singleton


class ChatRequest(BaseModel):
    message: str
    history: list[dict[str, str]] | None = None


@app.post("/api/chat")
async def chat_endpoint(request: ChatRequest) -> dict[str, Any]:
    """Conversational chat with the ZahraAgent brain (RAG + OSINT + execution)."""
    try:
        brain = get_brain()
        result = await asyncio.to_thread(
            brain.chat_respond, request.message, request.history)
        result["session"] = "shared-brain"
        return result
    except Exception as exc:
        return {"reply": f"خطأ في زهرة: {exc}", "intent": "error",
                "sources": [], "executed": False}


@app.get("/api/chat/stats")
async def chat_stats() -> dict[str, Any]:
    """Brain memory + RAG corpus stats for the chat UI."""
    try:
        brain = get_brain()
        stats = brain.memory.stats()
        stats["documents"] = len(brain.memory.get_documents(limit=100000))
        stats["channels"] = len(brain.ar.channels)
        return stats
    except Exception as exc:
        return {"error": str(exc)}


# -- WebSocket for live chat streaming ---------------------------------------

@app.websocket("/ws/chat")
async def ws_chat(websocket: WebSocket) -> None:
    """WebSocket chat: client sends {"message": "..."} and receives replies."""
    await websocket.accept()
    brain = get_brain()
    history: list[dict[str, str]] = []
    await websocket.send_json({"type": "meta",
                               "message": "زهرة متصلة. اكتب سؤالك أو اطلب أمرًا."})
    try:
        while True:
            raw = await websocket.receive_text()
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                data = {"message": raw}
            message = (data.get("message") or "").strip()
            if not message:
                await websocket.send_json({"type": "error", "message": "لا رسالة"})
                continue
            if message.lower() in ("exit", "quit"):
                await websocket.send_json({"type": "bye"})
                break
            reply = await asyncio.to_thread(
                brain.chat_respond, message, history)
            history.append({"role": "user", "content": message})
            history.append({"role": "assistant", "content": reply.get("reply", "")})
            history = history[-20:]
            await websocket.send_json({"type": "reply", "data": reply})
    except WebSocketDisconnect:
        pass
    except Exception as exc:  # noqa: BLE001
        logger.error("ws/chat error: %s", exc)


# -- Memory Endpoints --------------------------------------------------------

@app.get("/memory")
async def memory_summary() -> dict[str, Any]:
    """Get memory summary for dashboard."""
    if not orchestrator or not orchestrator.memory:
        return {"error": "Memory not initialized"}
    return orchestrator.memory.summary()


@app.get("/memory/findings")
async def all_findings() -> list[dict[str, Any]]:
    """Get all findings for dashboard (enriched with risk scores)."""
    if not orchestrator or not orchestrator.memory:
        return []
    items = [f.to_dict() for f in orchestrator.memory.all_findings()]
    try:
        from core.risk_engine import get_risk_engine

        engine = get_risk_engine()
        return [engine.enrich_dict(f) for f in items]
    except Exception as exc:
        logger.debug("risk enrichment failed: %s", exc)
        return items


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok", "version": "2.0.0"}


@app.get("/status")
async def platform_status() -> dict[str, Any]:
    """Platform status for dashboard stats bar."""
    if not orchestrator:
        return {"error": "Platform not initialized"}
    return orchestrator.status()


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """WebSocket for real-time events (legacy endpoint)."""
    await websocket.accept()
    active_connections.append(websocket)
    
    try:
        # Send initial status
        if orchestrator:
            status = orchestrator.status()
            await websocket.send_json({"type": "status", "data": status})
        
        # Keep connection alive and send events
        while True:
            # Wait for any message (ping/pong)
            await websocket.receive_text()
            
            # Send pong
            await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        if websocket in active_connections:
            active_connections.remove(websocket)
    except Exception as exc:
        logger.error("WebSocket error: %s", exc)
        if websocket in active_connections:
            active_connections.remove(websocket)


@app.websocket("/ws/attack")
async def ws_attack(websocket: WebSocket) -> None:
    """WebSocket endpoint for live attack streaming.

    Clients connect here to receive live logs from the swarm agents.
    The client can send a command to start a campaign:
        {"command": "recon example.com", "auto_run": true}
    """
    await websocket.accept()
    active_connections.append(websocket)
    logger.info("WebSocket client connected: %s", websocket.client)

    try:
        # Send welcome message
        await websocket.send_text(json.dumps({
            "type": "system",
            "message": "Connected to Zahra live attack stream. Send a command to start.",
        }))

        while True:
            raw = await websocket.receive_text()
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                data = {"command": raw}

            command = data.get("command", "")
            auto_run = data.get("auto_run", True)

            if not command:
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "message": "No command provided.",
                }))
                continue

            if not orchestrator:
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "message": "Platform not initialized",
                }))
                continue

            # Create campaign
            campaign = orchestrator.create_campaign(command)
            await websocket.send_text(json.dumps({
                "type": "campaign_created",
                "campaign_id": campaign.id,
                "target": campaign.target,
                "intent": campaign.intent.value,
            }))

            if auto_run:
                await websocket.send_text(json.dumps({
                    "type": "campaign_starting",
                    "campaign_id": campaign.id,
                }))
                # Run in background
                asyncio.create_task(orchestrator.run_campaign_async(campaign.id))

    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected")
    except Exception as exc:
        logger.error("WebSocket error: %s", exc)
    finally:
        if websocket in active_connections:
            active_connections.remove(websocket)


async def broadcast_event_async(event_data: dict[str, Any]) -> None:
    """Broadcast event to all WebSocket connections (async)."""
    dead: list[WebSocket] = []
    for connection in active_connections:
        try:
            await connection.send_text(json.dumps(event_data, default=str))
        except Exception as exc:
            logger.error("Failed to broadcast event: %s", exc)
            dead.append(connection)
    for conn in dead:
        if conn in active_connections:
            active_connections.remove(conn)


def broadcast_event(event_data: dict[str, Any]) -> None:
    """Broadcast event to all WebSocket connections."""
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(broadcast_event_async(event_data))
    except RuntimeError:
        pass


# ── Feature 1/4/5 endpoints: reports, risk scoring, notifications ─────────

_reports_dir = Path(__file__).resolve().parent.parent / "reports"


@app.get("/extras.js", include_in_schema=False)
async def serve_extras_js() -> Any:
    """Serve the dashboard extras JS (reports/risk/graph/alerts frontend)."""
    js_file = dashboard_dir / "extras.js"
    if js_file.exists():
        return FileResponse(js_file, media_type="application/javascript")
    raise HTTPException(status_code=404, detail="extras.js not found")


@app.get("/api/reports")
async def api_reports_list() -> Any:
    """List generated HTML reports (newest first)."""
    out: list[dict[str, Any]] = []
    if _reports_dir.exists():
        files = sorted(_reports_dir.glob("*.html"),
                       key=lambda p: p.stat().st_mtime, reverse=True)
        for p in files:
            st = p.stat()
            out.append({"name": p.name, "size": st.st_size, "modified": st.st_mtime})
    return {"reports": out, "dir": str(_reports_dir)}


@app.get("/api/reports/{report_name}")
async def api_reports_get(report_name: str) -> Any:
    """Serve one generated HTML report (name-validated, reports/ only)."""
    safe = Path(report_name).name
    if not safe.endswith(".html"):
        raise HTTPException(status_code=400, detail="only .html reports are served")
    path = _reports_dir / safe
    if not path.exists():
        raise HTTPException(status_code=404, detail="report not found")
    return FileResponse(path, media_type="text/html")


@app.post("/api/risk/score")
async def api_risk_score(payload: dict[str, Any]) -> Any:
    """Score a single finding dict with the risk engine (Feature 4)."""
    try:
        from core.risk_engine import get_risk_engine

        engine = get_risk_engine()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"risk engine unavailable: {exc}")
    try:
        if hasattr(engine, "enrich_dict"):
            return engine.enrich_dict(payload)
        if hasattr(engine, "score"):
            return engine.score(payload)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    raise HTTPException(status_code=500, detail="risk engine exposes no scoring method")


@app.get("/api/notifications/status")
async def api_notifications_status() -> Any:
    """Current notification-system status (Feature 5)."""
    try:
        from core.notifications import get_notification_manager

        return get_notification_manager().status()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"notifications unavailable: {exc}")


@app.post("/api/notifications/settings")
async def api_notifications_settings(payload: dict[str, Any]) -> Any:
    """Update notification settings (enabled flag / webhook URL)."""
    try:
        from core.notifications import get_notification_manager

        mgr = get_notification_manager()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"notifications unavailable: {exc}")
    if "enabled" in payload:
        try:
            if hasattr(mgr, "set_enabled"):
                mgr.set_enabled(bool(payload["enabled"]))
            else:
                mgr.enabled = bool(payload["enabled"])
        except Exception as exc:
            logger.debug("could not set enabled: %s", exc)
    if "webhook_url" in payload:
        try:
            if hasattr(mgr, "set_webhook_url"):
                mgr.set_webhook_url(str(payload["webhook_url"] or "") or None)
            else:
                mgr.webhook_url = str(payload["webhook_url"] or "") or None
        except Exception as exc:
            logger.debug("could not set webhook_url: %s", exc)
    try:
        return mgr.status()
    except Exception:
        return {"ok": True}


def setup_api(
    orchestrator_instance: Any,
    agentic_core_instance: Any,
    blackboard_instance: Any,
    event_emitter_instance: Any,
    database_instance: Any = None,
    ai_agent_instance: Any = None,
    controller_instance: Any = None,
) -> FastAPI:
    """Setup API with platform components."""
    global orchestrator, agentic_core, blackboard, event_emitter, database, ai_agent, controller

    orchestrator = orchestrator_instance
    agentic_core = agentic_core_instance
    blackboard = blackboard_instance
    event_emitter = event_emitter_instance
    database = database_instance
    ai_agent = ai_agent_instance
    controller = controller_instance

    # Feature 1 + 5 hooks: auto-report after each campaign and
    # notifications on critical/high findings.
    _campaign_findings: dict[str, list[dict[str, Any]]] = {}
    _campaign_events: dict[str, list[dict[str, Any]]] = {}

    def _feature_hooks(event: Any) -> None:
        try:
            ed = event.to_dict() if hasattr(event, "to_dict") else dict(event)
        except Exception:
            return
        etype = str(ed.get("type", ""))
        meta = ed.get("metadata") or {}
        cid = str(ed.get("campaign_id", "") or "unknown")
        if etype == "finding_written":
            _campaign_findings.setdefault(cid, []).append(dict(meta) or dict(ed))
            _campaign_events.setdefault(cid, []).append(ed)
            sev = str(meta.get("severity", "")).lower()
            if sev in ("critical", "high"):
                try:
                    from core.notifications import get_notification_manager

                    get_notification_manager().notify_finding({
                        "severity": sev,
                        "description": meta.get("description", ed.get("detail", "")),
                        "target": meta.get("target", ""),
                        "agent_name": ed.get("agent_name", ""),
                        "campaign_id": cid,
                    })
                except Exception as exc:
                    logger.debug("notification failed: %s", exc)
        elif etype == "campaign_complete":
            findings = _campaign_findings.pop(cid, [])
            events = _campaign_events.pop(cid, [])
            try:
                from agents.skills.reporting_skill import get_report_generator

                path = get_report_generator().generate(
                    campaign_id=cid,
                    findings=findings,
                    target=str(meta.get("target", "") or ""),
                    events=events,
                    meta={"target": meta.get("target", "")},
                )
                broadcast_event({
                    "type": "report_generated",
                    "campaign_id": cid,
                    "report": path.name,
                    "detail": f"Report generated: {path.name}",
                })
            except Exception as exc:
                logger.debug("auto-report failed: %s", exc)

    if event_emitter is not None:
        try:
            from core.events import EventType

            for _evt in EventType:
                event_emitter.on(_evt, _feature_hooks)
        except Exception as exc:
            logger.debug("feature hooks subscription failed: %s", exc)

    # Subscribe to events
    if event_emitter:
        def on_event(event: Any) -> None:
            # Map event types to dashboard-friendly format
            event_dict = event.to_dict()
            event_type_str = event_dict.get("type", "unknown")
            agent_name = event_dict.get("agent_name", "")
            detail = event_dict.get("detail", "")

            # Send raw event
            broadcast_event({
                "type": event_type_str,
                "agent": agent_name,
                "detail": detail,
                "data": event_dict,
            })

            # Critical-finding alert for high/critical findings
            meta = event_dict.get("metadata") or {}
            severity = str(meta.get("severity", "")).lower()
            if event_type_str == "finding_written" and severity in ("critical", "high"):
                broadcast_event({
                    "type": "critical_alert",
                    "severity": severity,
                    "agent": agent_name,
                    "target": str(meta.get("target", "") or ""),
                    "description": str(meta.get("description", detail))[:300],
                    "data": event_dict,
                })

        from core.events import EventType
        for event_type in EventType:
            event_emitter.on(event_type, on_event)

    # Also subscribe to orchestrator events
    if orchestrator:
        def on_orch_event(campaign_id: str, event_data: dict[str, Any]) -> None:
            broadcast_event({
                "type": event_data.get("type", "orchestrator"),
                "campaign_id": campaign_id,
                **event_data,
            })

        orchestrator.subscribe(on_orch_event)

    return app


def run_api_server(host: str = "0.0.0.0", port: int = 8000) -> None:
    """Run the API server."""
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    import os as _os
    import sys as _sys

    # Allow `python interfaces/api_server.py` from any working directory.
    _root = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
    if _root not in _sys.path:
        _sys.path.insert(0, _root)

    import argparse

    _parser = argparse.ArgumentParser(description="Zahra API server (dashboard + chat)")
    _parser.add_argument("--host", default="0.0.0.0")
    _parser.add_argument("--port", type=int, default=8000)
    _parser.add_argument("--no-platform", action="store_true",
                        help="Run with only the chat brain (skip full platform build)")
    _args = _parser.parse_args()

    if _args.no_platform:
        run_api_server(host=_args.host, port=_args.port)
        raise SystemExit(0)

    # Build the full platform (ZahraController + subsystems) exactly like
    # `python main.py serve`, so every dashboard tab works: campaigns,
    # agents, database, RAG, blackboard, AI brain, and chat.
    from main import build_platform

    print("[ZAHRA] building full platform (controller, swarm, RAG, brain)...")
    _cli = build_platform()

    setup_api(
        orchestrator_instance=_cli.orch,
        agentic_core_instance=_cli.controller.agentic_core,
        blackboard_instance=_cli.controller.blackboard,
        event_emitter_instance=_cli.controller.event_emitter,
        database_instance=_cli.controller.database,
        ai_agent_instance=_cli.controller.ai_agent,
        controller_instance=_cli.controller,
    )
    print(f"[ZAHRA] platform ready — serving dashboard on http://{_args.host}:{_args.port}")
    run_api_server(host=_args.host, port=_args.port)
