"""Auto-Report Generator skill for ZAHRA (Feature 1).

Generates a professional, self-contained HTML penetration-test report
after every campaign:

  * Executive Summary
  * Findings table (Severity / CVE / Description / Remediation)
  * Attack Timeline
  * Remediation Recommendations

Reports are written to ``reports/`` (override with ``ZAHRA_REPORTS_DIR``).
Optionally integrates with ``core.risk_engine`` (Feature 4) when available.

This module is deliberately standalone: it never raises on missing
integrations, so it can be called from any agent, API route, or script.
"""

from __future__ import annotations

import html
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPORTS_DIR = Path(
    os.environ.get(
        "ZAHRA_REPORTS_DIR",
        str(Path(__file__).resolve().parents[2] / "reports"),
    )
)

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_SEV_COLOR = {
    "critical": "#d93025",
    "high": "#e8710a",
    "medium": "#f9ab00",
    "low": "#1a73e8",
    "info": "#5f6368",
}

_REMEDIATION_BY_TYPE = {
    "cve": "Patch the affected software to the latest vendor release.",
    "cve_match": "Patch the affected software to the latest vendor release.",
    "misconfiguration": "Apply vendor hardening guidance and re-run configuration baselines.",
    "weak_credential": "Enforce a strong password policy, enable MFA, and rotate exposed credentials.",
    "default_credential": "Replace default credentials immediately and disable unused accounts.",
    "open_port": "Restrict exposure with firewall rules; close services that are not required.",
    "service": "Review the exposed service; restrict, update, or disable as appropriate.",
    "recon": "Limit information exposure (banners, DNS records, directory listings).",
    "lateral_movement": "Segment the network and enforce least-privilege between hosts.",
    "exfiltration": "Enable egress filtering and DLP monitoring on outbound channels.",
}


def _finding_to_dict(finding: Any) -> dict[str, Any]:
    """Normalise a Finding object or dict into a plain dict."""
    if isinstance(finding, dict):
        return dict(finding)
    out: dict[str, Any] = {}
    for attr in ("finding_type", "severity", "description", "evidence",
                 "agent_name", "confidence", "target", "cve", "ts"):
        try:
            out[attr] = getattr(finding, attr)
        except AttributeError:
            out[attr] = None
    if not out.get("description"):
        out["description"] = str(finding)
    return out


def _type_slug(value: Any) -> str:
    return str(value or "").strip().lower().replace(" ", "_")


class ReportGenerator:
    """Renders one campaign into a single self-contained HTML file."""

    def __init__(self, reports_dir: str | Path | None = None) -> None:
        self.reports_dir = Path(reports_dir) if reports_dir else REPORTS_DIR
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    # -- public API -----------------------------------------------------------

    def generate(
        self,
        campaign_id: str,
        findings: list[Any] | None = None,
        target: str = "",
        events: list[dict[str, Any]] | None = None,
        meta: dict[str, Any] | None = None,
    ) -> Path:
        """Write the HTML report for one campaign and return its path."""
        rows = [_finding_to_dict(f) for f in (findings or [])]
        rows.sort(key=lambda r: _SEV_ORDER.get(str(r.get("severity", "info")).lower(), 9))
        rows = self._apply_risk(rows)
        target = str(target or (meta or {}).get("target", "") or "")
        doc = self._render(
            campaign_id=str(campaign_id),
            target=target,
            rows=rows,
            events=list(events or []),
        )
        ts = time.strftime("%Y%m%d_%H%M%S")
        safe_id = "".join(c for c in str(campaign_id) if c.isalnum() or c in "-_")[:40] or "campaign"
        path = self.reports_dir / f"report_{safe_id}_{ts}.html"
        path.write_text(doc, encoding="utf-8")
        return path

    def _apply_risk(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Best-effort risk enrichment via the Feature-4 risk engine."""
        try:
            from core.risk_engine import get_risk_engine  # type: ignore

            engine = get_risk_engine()
            enriched: list[dict[str, Any]] = []
            for row in rows:
                try:
                    if hasattr(engine, "enrich_dict"):
                        row = dict(engine.enrich_dict(row))
                    elif hasattr(engine, "score"):
                        row = dict(engine.score(row))
                except Exception:
                    row.setdefault("risk_score", None)
                enriched.append(row)
            return enriched
        except Exception:
            for row in rows:
                row.setdefault("risk_score", None)
            return rows

    # -- rendering ------------------------------------------------------------

    def _render(
        self,
        *,
        campaign_id: str,
        target: str,
        rows: list[dict[str, Any]],
        events: list[dict[str, Any]],
    ) -> str:
        """Render the full self-contained HTML report document."""
        crit = sum(1 for r in rows if str(r.get("severity", "")).lower() == "critical")
        high = sum(1 for r in rows if str(r.get("severity", "")).lower() == "high")
        med = sum(1 for r in rows if str(r.get("severity", "")).lower() == "medium")
        low = len(rows) - crit - high - med

        findings_html = self._findings_table(rows)
        timeline_html = self._timeline(events)
        recs_html = self._recommendations(rows)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ZAHRA Report — {html.escape(campaign_id)}</title>
<style>
 body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117;
        color: #c9d1d9; margin: 0; padding: 32px; }}
 .wrap {{ max-width: 1080px; margin: 0 auto; }}
 h1 {{ color: #58a6ff; }} h2 {{ color: #7ee787; border-bottom: 1px solid #21262d;
        padding-bottom: 6px; margin-top: 36px; }}
 .badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px;
        font-size: 12px; font-weight: 700; color: #fff; }}
 .sum {{ display: flex; gap: 14px; margin: 18px 0; flex-wrap: wrap; }}
 .kpi {{ background: #161b22; border: 1px solid #21262d; border-radius: 10px;
        padding: 14px 22px; text-align: center; }}
 .kpi b {{ display: block; font-size: 26px; }}
 table {{ width: 100%; border-collapse: collapse; background: #161b22;
        border: 1px solid #21262d; }}
 th {{ background: #21262d; text-align: left; padding: 9px 10px; font-size: 13px; }}
 td {{ padding: 8px 10px; border-top: 1px solid #21262d; font-size: 13px; }}
 li {{ margin: 6px 0; }}
 .tl {{ border-left: 2px solid #30363d; margin: 12px 0 12px 8px; padding-left: 18px; }}
 .tl-item {{ margin: 10px 0; }}
 .tl-time {{ color: #8b949e; font-size: 12px; }}
 footer {{ margin-top: 40px; color: #8b949e; font-size: 12px; }}
</style>
</head>
<body><div class="wrap">
<h1>ZAHRA — Penetration Test Report</h1>
<p><b>Campaign:</b> {html.escape(campaign_id)} &nbsp;|&nbsp; <b>Target:</b>
 {html.escape(target or "N/A")} &nbsp;|&nbsp; <b>Generated:</b>
 {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}</p>

<h2>Executive Summary</h2>
<div class="sum">
 <div class="kpi" style="border-color:#d93025"><b style="color:#d93025">{crit}</b>Critical</div>
 <div class="kpi" style="border-color:#e8710a"><b style="color:#e8710a">{high}</b>High</div>
 <div class="kpi" style="border-color:#f9ab00"><b style="color:#f9ab00">{med}</b>Medium</div>
 <div class="kpi" style="border-color:#1a73e8"><b style="color:#1a73e8">{low}</b>Low/Info</div>
</div>
<p>{self._narrative(target, crit, high, len(rows))}</p>

<h2>Findings</h2>
{findings_html}

<h2>Attack Timeline</h2>
{timeline_html}

<h2>Remediation Recommendations</h2>
{recs_html}

<footer>Generated by ZAHRA — operator-directed platform for AUTHORIZED security
testing only. Handle this report according to the engagement's confidentiality
agreement.</footer>
</div></body></html>"""

    @staticmethod
    def _narrative(target: str, crit: int, high: int, total: int) -> str:
        if total == 0:
            return ("The assessment of <b>" + html.escape(target or "the target") +
                    "</b> completed without confirmed findings. This may indicate a "
                    "strong security posture or limited visibility — interpret with care.")
        tone = ("an URGENT remediation priority" if crit else
                "a HIGH remediation priority" if high else
                "a moderate remediation priority")
        return (f"The assessment of <b>{html.escape(target or 'the target')}</b> identified "
                f"<b>{total}</b> finding(s), including {crit} critical and {high} high-severity "
                f"issues — {tone}. Full details and remediation guidance follow below.")

# __PART3__

    @staticmethod
    def _sev_badge(severity: Any) -> str:
        sev = str(severity or "info").lower()
        color = _SEV_COLOR.get(sev, _SEV_COLOR["info"])
        return (f'<span class="badge" style="background:{color}">'
                f'{html.escape(sev.upper())}</span>')

    def _findings_table(self, rows: list[dict[str, Any]]) -> str:
        if not rows:
            return "<p><i>No findings recorded for this campaign.</i></p>"
        head = ("<tr><th>#</th><th>Severity</th><th>Risk Score</th><th>CVE</th>"
                "<th>Description</th><th>Agent</th><th>Evidence</th></tr>")
        body: list[str] = []
        for i, r in enumerate(rows, 1):
            sev = str(r.get("severity", "info")).lower()
            cve = html.escape(str(r.get("cve") or "—"))
            risk = r.get("risk_score")
            risk_cell = (f"<b style='color:{_SEV_COLOR.get(sev, '#5f6368')}'>"
                         f"{risk}</b>") if risk is not None else "—"
            desc = html.escape(str(r.get("description") or ""))
            agent = html.escape(str(r.get("agent_name") or "—"))
            ev = html.escape(str(r.get("evidence") or ""))[:220]
            body.append(f"<tr><td>{i}</td><td>{self._sev_badge(sev)}</td>"
                        f"<td>{risk_cell}</td><td>{cve}</td><td>{desc}</td>"
                        f"<td>{agent}</td><td>{ev}</td></tr>")
        return f"<table>{head}{''.join(body)}</table>"

    @staticmethod
    def _timeline(events: list[dict[str, Any]]) -> str:
        if not events:
            return "<p><i>No timeline events recorded.</i></p>"
        items: list[str] = []
        for e in events[:200]:
            ts = str(e.get("ts") or e.get("time") or "")
            if ts and ts.replace(".", "").isdigit():
                try:
                    ts = datetime.fromtimestamp(float(ts), timezone.utc).strftime("%H:%M:%S")
                except (ValueError, OSError):
                    pass
            kind = html.escape(str(e.get("event") or e.get("type") or "event"))
            msg = html.escape(str(e.get("message") or e.get("data") or ""))[:260]
            items.append(f'<div class="tl-item"><span class="tl-time">'
                         f'{html.escape(ts)}</span> — <b>{kind}</b> {msg}</div>')
        return f'<div class="tl">{"".join(items)}</div>'

    def _recommendations(self, rows: list[dict[str, Any]]) -> str:
        recs: list[str] = []
        seen: set[str] = set()
        for r in rows:
            sev = str(r.get("severity", "info")).lower()
            rec = str(r.get("remediation") or
                      _REMEDIATION_BY_TYPE.get(_type_slug(r.get("finding_type")),
                                               _REMEDIATION_BY_TYPE["misconfiguration"]))
            key = rec.lower()
            if key not in seen:
                seen.add(key)
                recs.append(f"<li>{self._sev_badge(sev)} {html.escape(rec)}</li>")
        if not recs:
            return "<p><i>No remediation actions required.</i></p>"
        return "<ul>" + "".join(recs) + "</ul>"
