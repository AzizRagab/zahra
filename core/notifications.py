"""Notification System for ZAHRA.

Fires alerts when Critical/High findings are written to the blackboard:
  * Webhook  (Discord / Slack / generic JSON) - optional, via env vars
  * Sound    (beep) in the Dashboard - driven by the WS broadcast payload
  * Visual   (red screen flash) in the Dashboard - same payload

The backend never raises on notification failure; alerts are best-effort
so a dead webhook can never stall a campaign.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from typing import Any

logger = logging.getLogger("zahra.notifications")

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class NotificationManager:
    """Best-effort alert dispatcher. Safe to call from any thread."""

    def __init__(self) -> None:
        self.enabled = os.environ.get("ZAHRA_NOTIFY_ENABLED", "1") not in ("0", "false", "no")
        self.min_severity = os.environ.get("ZAHRA_NOTIFY_MIN_SEVERITY", "high").lower()
        self.webhook_url = os.environ.get("ZAHRA_WEBHOOK_URL", "").strip()
        # auto-detect discord vs slack vs generic from the URL
        self.webhook_type = os.environ.get("ZAHRA_WEBHOOK_TYPE", "auto").lower()
        if self.webhook_type == "auto":
            if "discord" in self.webhook_url:
                self.webhook_type = "discord"
            elif "slack" in self.webhook_url:
                self.webhook_type = "slack"
            else:
                self.webhook_type = "generic"
        self._lock = threading.Lock()
        self.sent_count = 0
        self.failed_count = 0

    # -- threshold ---------------------------------------------------------

    def should_notify(self, finding: Any) -> bool:
        """True when the finding meets the minimum severity threshold."""
        if not self.enabled:
            return False
        if isinstance(finding, dict):
            severity = str(finding.get("severity", "")).lower()
        else:
            severity = str(getattr(finding, "severity", "")).lower()
        return _SEVERITY_ORDER.get(severity, 0) >= _SEVERITY_ORDER.get(self.min_severity, 3)

    # -- alert payload (also broadcast to dashboard over WS) ----------------

    def build_alert(self, finding: Any, risk: dict | None = None) -> dict:
        """Build the WS payload the dashboard uses for sound + visual alerts."""
        if isinstance(finding, dict):
            def get(k, d=""):
                return finding.get(k, d)
        else:
            def get(k, d=""):
                return getattr(finding, k, d)
        severity = str(get("severity", "unknown")).lower()
        return {
            "type": "notify_alert",
            "severity": severity,
            "agent": str(get("agent_name", "unknown")),
            "target": str(get("target", "")),
            "title": str(get("title", "") or get("description", "Finding")),
            "description": str(get("description", ""))[:300],
            "evidence": str(get("evidence", ""))[:200],
            "risk_score": (risk or {}).get("risk_score"),
            "risk_level": (risk or {}).get("risk_level"),
            "risk_color": (risk or {}).get("risk_color", "#ef4444"),
            "sound": True,
            "flash": True,
        }

    # -- webhook -------------------------------------------------------------

    def send_webhook(self, alert: dict) -> bool:
        """Post the alert to the configured webhook (background thread)."""
        if not self.webhook_url:
            return False

        def _post() -> None:
            try:
                import requests  # lazy - optional dependency

                if self.webhook_type == "discord":
                    payload = {
                        "username": "ZAHRA Swarm",
                        "embeds": [{
                            "title": "[" + alert["severity"].upper() + "] " + alert["title"],
                            "description": alert["description"],
                            "color": 0xEF4444 if alert["severity"] == "critical" else 0xF97316,
                            "fields": [
                                {"name": "Target", "value": alert["target"] or "-", "inline": True},
                                {"name": "Agent", "value": alert["agent"], "inline": True},
                                {"name": "Risk Score", "value": str(alert.get("risk_score", "-")), "inline": True},
                            ],
                        }],
                    }
                    body = json.dumps(payload)
                    headers = {"Content-Type": "application/json"}
                elif self.webhook_type == "slack":
                    body = json.dumps({
                        "text": ("[" + alert["severity"].upper() + "] " + alert["title"]
                                 + "\n" + alert["description"]
                                 + "\nTarget: " + alert["target"]
                                 + " | Agent: " + alert["agent"]
                                 + " | Risk: " + str(alert.get("risk_score", "-"))),
                    })
                    headers = {"Content-Type": "application/json"}
                else:
                    body = json.dumps(alert)
                    headers = {"Content-Type": "application/json"}

                resp = requests.post(self.webhook_url, data=body, headers=headers, timeout=5)
                with self._lock:
                    if resp.status_code < 300:
                        self.sent_count += 1
                    else:
                        self.failed_count += 1
                        logger.debug("webhook HTTP %s", resp.status_code)
            except Exception as exc:  # never alert-fail a campaign
                with self._lock:
                    self.failed_count += 1
                logger.debug("webhook failed: %s", exc)

        threading.Thread(target=_post, name="zahra-webhook", daemon=True).start()
        return True

    # -- one-call API used by the API server ----------------------------------

    def notify_finding(self, finding: Any, risk: dict | None = None):
        """Check a finding and dispatch alerts if it crosses the threshold.

        Returns the WS alert payload (so the caller can broadcast it), or None.
        """
        if not self.should_notify(finding):
            return None
        alert = self.build_alert(finding, risk)
        self.send_webhook(alert)  # no-op when no webhook configured
        logger.info("notification dispatched: [%s] %s", alert["severity"], alert["title"][:80])
        return alert

    def status(self) -> dict:
        return {
            "enabled": self.enabled,
            "min_severity": self.min_severity,
            "webhook_configured": bool(self.webhook_url),
            "webhook_type": self.webhook_type,
            "sent": self.sent_count,
            "failed": self.failed_count,
        }


_manager = None
_manager_lock = threading.Lock()


def get_notification_manager() -> NotificationManager:
    """Shared singleton (thread-safe)."""
    global _manager
    with _manager_lock:
        if _manager is None:
            _manager = NotificationManager()
        return _manager
