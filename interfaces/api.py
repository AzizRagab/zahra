"""FastAPI interface — REST + WebSocket API for the zahra platform.

Exposes the orchestrator's capabilities over HTTP so external tools,
dashboards, or automation pipelines can create and monitor campaigns.

Endpoints:
* ``POST /campaigns`` — create + optionally start a campaign
* ``GET /campaigns`` — list all campaigns
* ``GET /campaigns/{id}`` — get campaign details
* ``POST /campaigns/{id}/run`` — start a campaign
* ``GET /campaigns/{id}/findings`` — get campaign findings
* ``GET /status`` — platform status
* ``GET /health`` — health check
* ``WS /ws/attack`` — live streaming of swarm agent logs (WebSocket)
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

logger = logging.getLogger("zahra.interfaces.api")


def create_app(agent: Any = None) -> Any:
    """Create and configure the FastAPI application.

    Args:
        agent: The ZahraAgent instance to use. If ``None``, a
            new one is created with default settings.

    Returns:
        A configured FastAPI application instance.
    """
    try:
        from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
        from fastapi.responses import FileResponse
        from pydantic import BaseModel
        from starlette.routing import WebSocketRoute
    except ImportError:
        logger.error("fastapi and pydantic are required for the API interface")
        raise

    # Use ZahraAgent if provided, otherwise try to import and create one
    if agent is None:
        try:
            from zahra_agent import ZahraAgent
            agent = ZahraAgent()
        except Exception as exc:
            logger.warning("Could not load ZahraAgent: %s — falling back to offline mode", exc)
            agent = None

    # Keep backward-compatible alias so the rest of the file can still use
    # ``orch`` for orchestrator-like operations.
    orch = agent

    # Campaign storage for API compatibility (ZahraAgent doesn't have built-in campaign tracking)
    campaign_store: dict[str, dict[str, Any]] = {}

    app = FastAPI(
        title="Zahra — AI Pentest Platform",
        description="AI-driven penetration testing platform with autonomous agent capabilities.",
        version="1.0.0",
    )

    # -- ASGI middleware: allow WebSocket connections from any origin ------

    class _AllowAnyOrigin:
        """ASGI middleware that strips the Origin header from WebSocket
        handshakes so Starlette's default origin check does not reject
        dashboard connections served from a different host/port."""

        def __init__(self, inner: Any) -> None:
            self.inner = inner

        async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
            if scope["type"] == "websocket":
                scope["headers"] = [
                    (k, v)
                    for k, v in scope.get("headers", [])
                    if k.lower() != b"origin"
                ]
            await self.inner(scope, receive, send)

    app.add_middleware(_AllowAnyOrigin)

    # -- serve the dashboard frontend --------------------------------------

    from pathlib import Path

    dashboard_dir = Path(__file__).resolve().parent / "dashboard"
    index_file = dashboard_dir / "index.html"

    def _dashboard_available() -> bool:
        return index_file.exists()

    if _dashboard_available():
        @app.get("/", include_in_schema=False)
        async def dashboard_index() -> Any:
            return FileResponse(index_file)

        # Serve static assets (style.css, script.js) when requested directly.
        @app.get("/style.css", include_in_schema=False)
        async def dashboard_css() -> Any:
            css_file = dashboard_dir / "style.css"
            if css_file.exists():
                return FileResponse(css_file, media_type="text/css")
            raise HTTPException(status_code=404, detail="style.css not found")

        @app.get("/script.js", include_in_schema=False)
        async def dashboard_js() -> Any:
            js_file = dashboard_dir / "script.js"
            if js_file.exists():
                return FileResponse(js_file, media_type="application/javascript")
            raise HTTPException(status_code=404, detail="script.js not found")
    else:
        logger.warning("dashboard files not found at %s; / will return 404", dashboard_dir)

    # -- request/response models ------------------------------------------

    class CampaignRequest(BaseModel):
        command: str
        auto_run: bool = False

    class CampaignResponse(BaseModel):
        id: str
        command: str
        target: str
        intent: str
        status: str

    # -- WebSocket live-streaming -----------------------------------------

    # Connected WebSocket clients (for live agent logs).
    ws_clients: set[WebSocket] = set()

    async def broadcast(event: dict[str, Any]) -> None:
        """Send an event to all connected WebSocket clients."""
        if not ws_clients:
            return
        message = json.dumps(event, default=str)
        dead: list[WebSocket] = []
        for ws in list(ws_clients):
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            ws_clients.discard(ws)

    # Helper to broadcast agent activity to WebSocket clients.
    def broadcast_agent_event(event_type: str, data: dict[str, Any]) -> None:
        """Broadcast an agent event to all connected WebSocket clients."""
        payload = {"type": event_type, **data}
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(broadcast(payload))
        except RuntimeError:
            # No running loop — skip broadcast.
            pass

    # Wrap agent methods to broadcast events if the agent supports it.
    if agent is not None and hasattr(agent, "run_campaign"):
        _original_run_campaign = agent.run_campaign

        def _run_campaign_with_broadcast(goal: str, auto_approve: bool | None = None) -> dict[str, Any]:
            broadcast_agent_event("campaign_starting", {"goal": goal})
            try:
                result = _original_run_campaign(goal, auto_approve=auto_approve)
                broadcast_agent_event("campaign_completed", {
                    "goal": goal,
                    "status": result.get("status", "completed"),
                })
                return result
            except Exception as exc:
                broadcast_agent_event("campaign_error", {"goal": goal, "error": str(exc)})
                raise

        agent.run_campaign = _run_campaign_with_broadcast

    async def ws_attack(websocket: WebSocket) -> None:
        """WebSocket endpoint for live attack streaming.

        Clients connect here to receive live logs from the swarm agents
        (recon, scan, exploit) as they run. The client can also send a
        command to start a campaign:

            {"command": "recon example.com", "auto_run": true}

        The server streams back events like:
            {"type": "swarm", "agent": "recon_agent", "event": "agent_started", ...}
            {"type": "orchestrator", "campaign_id": "...", "type": "campaign_completed", ...}
        """
        await websocket.accept()
        ws_clients.add(websocket)
        logger.info("WebSocket client connected: %s", websocket.client)

        try:
            # Send a welcome message.
            await websocket.send_text(json.dumps({
                "type": "system",
                "message": "Connected to Zahra live attack stream. Send a command to start.",
            }))

            while True:
                # Wait for a command from the client.
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
                        "message": "No command provided. Send {\"command\": \"recon example.com\"}",
                    }))
                    continue

                # Create the campaign.
                campaign = orch.create_campaign(command)
                await websocket.send_text(json.dumps({
                    "type": "campaign_created",
                    "campaign_id": campaign.id,
                    "target": campaign.target,
                    "intent": campaign.intent.value,
                }))

                if auto_run:
                    # Run asynchronously so the WebSocket stays responsive.
                    await websocket.send_text(json.dumps({
                        "type": "campaign_starting",
                        "campaign_id": campaign.id,
                    }))
                    asyncio.create_task(orch.run_campaign_async(campaign.id))

        except WebSocketDisconnect:
            logger.info("WebSocket client disconnected: %s", websocket.client)
        except Exception as exc:
            logger.exception("WebSocket error")
            try:
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "message": str(exc),
                }))
            except Exception:
                pass
        finally:
            ws_clients.discard(websocket)

    # Register the WebSocket route via Starlette's WebSocketRoute so the
    # dashboard can connect from any origin (the _AllowAnyOrigin middleware
    # strips the Origin header before the origin check runs).
    app.router.routes.append(
        WebSocketRoute("/ws/attack", ws_attack)
    )

    # -- routes ------------------------------------------------------------

    @app.get("/health")
    async def health_check() -> dict[str, str]:
        return {"status": "ok", "version": "1.0.0"}

    @app.get("/status")
    async def status() -> dict[str, Any]:
        return orch.status()

    @app.post("/campaigns", response_model=CampaignResponse)
    async def create_campaign(req: CampaignRequest) -> CampaignResponse:
        campaign = orch.create_campaign(req.command)
        if req.auto_run:
            campaign = orch.run_campaign(campaign.id)
        return CampaignResponse(
            id=campaign.id,
            command=campaign.command,
            target=campaign.target,
            intent=campaign.intent.value,
            status=campaign.status.value,
        )

    @app.get("/campaigns")
    async def list_campaigns() -> list[dict[str, Any]]:
        return [c.to_dict() for c in orch.list_campaigns()]

    @app.get("/campaigns/{campaign_id}")
    async def get_campaign(campaign_id: str) -> dict[str, Any]:
        campaign = orch.get_campaign(campaign_id)
        if campaign is None:
            raise HTTPException(status_code=404, detail="campaign not found")
        return campaign.to_dict()

    @app.post("/campaigns/{campaign_id}/run")
    async def run_campaign(campaign_id: str) -> dict[str, Any]:
        campaign = orch.get_campaign(campaign_id)
        if campaign is None:
            raise HTTPException(status_code=404, detail="campaign not found")
        campaign = orch.run_campaign(campaign_id)
        return campaign.to_dict()

    @app.get("/campaigns/{campaign_id}/findings")
    async def get_findings(campaign_id: str) -> list[dict[str, Any]]:
        campaign = orch.get_campaign(campaign_id)
        if campaign is None:
            raise HTTPException(status_code=404, detail="campaign not found")
        return [f.to_dict() for f in campaign.findings]

    @app.get("/memory")
    async def memory_summary() -> dict[str, Any]:
        return orch.memory.summary()

    @app.get("/memory/findings")
    async def all_findings() -> list[dict[str, Any]]:
        return [f.to_dict() for f in orch.memory.all_findings()]

    @app.get("/memory/entries")
    async def all_entries() -> list[dict[str, Any]]:
        return [e.to_dict() for e in orch.memory.all_entries()]

    return app