"""HTTP Security Headers Scanner skill.

Scans HTTP security headers and provides A-F grading.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx

from .base import BaseSkill

logger = logging.getLogger("zahra.skills.http_headers_scanner")

SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "HSTS", "weight": 20,
        "check": lambda v: "max-age=" in v.lower() and int(re.search(r"max-age=(\d+)", v, re.I).group(1)) >= 31536000,
        "recommendation": "Set max-age >= 31536000"
    },
    "content-security-policy": {
        "name": "CSP", "weight": 20,
        "check": lambda v: len(v) > 0 and "unsafe-inline" not in v.lower() and "unsafe-eval" not in v.lower(),
        "recommendation": "Define restrictive CSP"
    },
    "x-frame-options": {
        "name": "X-Frame-Options", "weight": 15,
        "check": lambda v: v.upper() in ("DENY", "SAMEORIGIN"),
        "recommendation": "Set to DENY or SAMEORIGIN"
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options", "weight": 10,
        "check": lambda v: v.lower() == "nosniff",
        "recommendation": "Set to nosniff"
    },
    "referrer-policy": {
        "name": "Referrer-Policy", "weight": 10,
        "check": lambda v: v.lower() in ("no-referrer", "strict-origin-when-cross-origin"),
        "recommendation": "Set to no-referrer"
    },
    "permissions-policy": {
        "name": "Permissions-Policy", "weight": 10,
        "check": lambda v: len(v) > 0,
        "recommendation": "Define permissions policy"
    },
}

GRADE_THRESHOLDS = {"A+": 95, "A": 90, "B": 75, "C": 60, "D": 45, "F": 0}


class HTTPHeadersScannerSkill(BaseSkill):
    def __init__(self):
        super().__init__(name="http_headers_scanner", description="Scan HTTP security headers with A-F grading")
        self._client = None

    async def _get_client(self):
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=5.0), follow_redirects=True)
        return self._client

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None

    async def execute(self, context, **kwargs):
        target = kwargs.get("target") or context.get("target", "")
        if not target:
            return {"status": "error", "error": "Target URL required"}
        url = target if target.startswith("http") else f"https://{target}"
        try:
            client = await self._get_client()
            response = await client.get(url)
            headers = {k.lower(): v for k, v in response.headers.items()}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}
        analysis = self._analyze_headers(headers)
        return {
            "status": "success", "url": url,
            "grade": self._calculate_grade(analysis),
            "score": analysis["score"],
            "headers_found": analysis["found"],
            "headers_missing": analysis["missing"],
            "recommendations": analysis["recommendations"],
        }

    def _analyze_headers(self, headers):
        found, missing, recommendations = [], [], []
        score = 0
        for key, cfg in SECURITY_HEADERS.items():
            val = headers.get(key, "")
            if val:
                found.append(cfg["name"])
                if cfg["check"](val):
                    score += cfg["weight"]
            else:
                missing.append(cfg["name"])
                recommendations.append(f"{cfg['name']}: {cfg['recommendation']}")
        return {"score": score, "found": found, "missing": missing, "recommendations": recommendations}

    def _calculate_grade(self, analysis):
        pct = (analysis["score"] / 100) * 100
        for grade, threshold in GRADE_THRESHOLDS.items():
            if pct >= threshold:
                return grade
        return "F"

    def can_handle(self, task_type):
        return task_type in ["http_headers", "headers_scan", "security_headers"]


async def scan_http_headers(url, **kwargs):
    skill = HTTPHeadersScannerSkill()
    try:
        return await skill.execute({}, target=url, **kwargs)
    finally:
        await skill.close()
