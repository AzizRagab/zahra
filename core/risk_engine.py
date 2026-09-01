"""Risk Scoring Engine for ZAHRA.

Scores every finding on a 0-100 scale from four weighted factors:
  * CVSS score          (estimated from severity / CVE metadata when absent)
  * Business impact     (High / Medium / Low)
  * Exploitability      (Easy / Medium / Hard)
  * Network exposure    (External / Internal)

Read-only with respect to findings: `score()` never mutates the finding,
it returns a `RiskAssessment` the caller can attach to API responses.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any


# Weights (must sum to 1.0) - overridable via environment
_W_CVSS = float(os.environ.get("ZAHRA_RISK_W_CVSS", "0.40"))
_W_IMPACT = float(os.environ.get("ZAHRA_RISK_W_IMPACT", "0.25"))
_W_EXPLOIT = float(os.environ.get("ZAHRA_RISK_W_EXPLOIT", "0.20"))
_W_EXPOSURE = float(os.environ.get("ZAHRA_RISK_W_EXPOSURE", "0.15"))

_SEVERITY_BASE_CVSS = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.5,
    "low": 3.0,
    "info": 1.0,
    "unknown": 4.0,
}

# Keywords -> business impact
_IMPACT_KEYWORDS = [
    ("credential", "high"), ("password", "high"), ("admin", "high"),
    ("rce", "high"), ("remote code", "high"), ("injection", "high"),
    ("sql", "high"), ("auth", "high"), ("payment", "high"),
    ("pii", "high"), ("data leak", "high"), ("takeover", "high"),
    ("xss", "medium"), ("csrf", "medium"), ("redirect", "medium"),
    ("info disclosure", "medium"), ("misconfiguration", "medium"),
    ("banner", "low"), ("version", "low"), ("header", "low"),
]

# Keywords -> exploitability
_EXPLOIT_KEYWORDS = [
    ("metasploit", "easy"), ("public exploit", "easy"), ("default cred", "easy"),
    ("unauthenticated", "easy"), ("nuclei", "easy"), ("sqlmap", "easy"),
    ("cve-", "medium"), ("payload", "medium"), ("chained", "hard"),
    ("prerequisite", "hard"), ("requires", "hard"),
]

_EXPOSURE_KEYWORDS = [
    ("0.0.0.0", "external"), ("public", "external"), ("edge", "external"),
    ("dmz", "external"), ("wan", "external"),
    ("127.0.0.1", "internal"), ("localhost", "internal"),
    ("10.", "internal"), ("192.168.", "internal"), ("172.16", "internal"),
    ("internal", "internal"), ("lan", "internal"),
]


@dataclass
class RiskAssessment:
    """Result of scoring a single finding."""

    score: int = 0                    # 0-100
    level: str = "info"               # critical/high/medium/low/info
    color: str = "#22c55e"            # hex color for dashboard rows
    cvss: float = 0.0                 # estimated CVSS v3 base score
    business_impact: str = "low"      # high / medium / low
    exploitability: str = "medium"    # easy / medium / hard
    exposure: str = "internal"        # external / internal
    reasons: list = field(default_factory=list)

    def as_dict(self):
        return {
            "risk_score": self.score,
            "risk_level": self.level,
            "risk_color": self.color,
            "cvss": self.cvss,
            "business_impact": self.business_impact,
            "exploitability": self.exploitability,
            "exposure": self.exposure,
            "reasons": self.reasons,
        }


def _keyword_lookup(text, table, default):
    for kw, value in table:
        if kw in text:
            return value
    return default

class RiskEngine:
    """Stateless risk scorer - one instance can be shared app-wide."""

    # level thresholds on the 0-100 scale
    THRESHOLDS = {"critical": 85, "high": 65, "medium": 40, "low": 15}
    COLORS = {
        "critical": "#ef4444",  # red
        "high": "#f97316",      # orange
        "medium": "#eab308",    # yellow
        "low": "#22c55e",       # green
        "info": "#3b82f6",      # blue
    }

    def _estimate_cvss(self, severity: str, text: str) -> float:
        sev = (severity or "unknown").strip().lower()
        base = _SEVERITY_BASE_CVSS.get(sev, 4.0)
        if "cve-" in text:
            base = max(base, 7.0)
        if "critical" in text and base < 9.0:
            base = 9.0
        return round(min(base, 10.0), 1)

    def score(self, finding: Any) -> RiskAssessment:
        """Score a finding object or dict. Never mutates the input."""
        if isinstance(finding, dict):
            def get(k, d=""):
                return finding.get(k, d)
        else:
            def get(k, d=""):
                return getattr(finding, k, d)

        severity = str(get("severity", "info") or "info").lower()
        target = str(get("target", "") or "")
        evidence = str(get("evidence", "") or "")
        description = str(get("description", "") or "")
        text = " ".join((description, evidence, target)).lower()

        cvss = self._estimate_cvss(severity, text)
        impact = _keyword_lookup(text, _IMPACT_KEYWORDS,
                                 "high" if severity in ("critical", "high") else "low")
        exploit = _keyword_lookup(text, _EXPLOIT_KEYWORDS, "medium")
        exposure = _keyword_lookup(target + " " + text, _EXPOSURE_KEYWORDS, "internal")

        impact_map = {"high": 1.0, "medium": 0.6, "low": 0.3}
        exploit_map = {"easy": 1.0, "medium": 0.6, "hard": 0.3}
        exposure_map = {"external": 1.0, "internal": 0.5}

        s = (
            (cvss / 10.0) * _W_CVSS
            + impact_map[impact] * _W_IMPACT
            + exploit_map[exploit] * _W_EXPLOIT
            + exposure_map[exposure] * _W_EXPOSURE
        ) * 100.0
        score = int(round(min(max(s, 0.0), 100.0)))

        level = "info"
        for name, threshold in self.THRESHOLDS.items():
            if score >= threshold:
                level = name
                break

        reasons = [
            "CVSS~" + str(cvss) + " (severity: " + severity + ")",
            "business impact: " + impact,
            "exploitability: " + exploit,
            "exposure: " + exposure,
        ]
        return RiskAssessment(
            score=score, level=level,
            color=self.COLORS.get(level, self.COLORS["info"]),
            cvss=cvss, business_impact=impact,
            exploitability=exploit, exposure=exposure, reasons=reasons,
        )

    def enrich_dict(self, finding_dict: dict) -> dict:
        """Return a copy of a finding dict with risk_* fields added."""
        enriched = dict(finding_dict)
        assessment = self.score(enriched)
        enriched.update(assessment.as_dict())
        return enriched


_engine = None


def get_risk_engine() -> RiskEngine:
    """Shared singleton (lazy)."""
    global _engine
    if _engine is None:
        _engine = RiskEngine()
    return _engine
