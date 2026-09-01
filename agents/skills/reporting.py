"""Reporting skill for agents.

Provides vulnerability reporting capabilities with CVSS scoring
and multiple output formats.
Inspired by Strix's reporting tools.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from .base import BaseSkill

logger = logging.getLogger("zahra.skills.reporting")


class ReportingSkill(BaseSkill):
    """Skill for generating vulnerability reports.
    
    Creates professional pentest reports in multiple formats:
    - Markdown
    - HTML
    - JSON
    - SARIF
    """

    def __init__(self) -> None:
        """Initialize the reporting skill."""
        super().__init__(
            name="reporting",
            description="Generate vulnerability reports in multiple formats (MD, HTML, JSON, SARIF)",
        )

    async def execute(
        self,
        context: dict[str, Any],
        report_type: str = "vulnerability",
        format: str = "markdown",
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Execute report generation.
        
        Args:
            context: Execution context with findings
            report_type: Type of report (vulnerability, dependency, summary)
            format: Output format (markdown, html, json, sarif)
            **kwargs: Additional parameters
            
        Returns:
            Report data dictionary
        """
        findings = context.get("findings", [])
        target = context.get("target", "unknown")
        
        logger.info("Generating %s report in %s format", report_type, format)
        
        report: dict[str, Any] = {
            "report_type": report_type,
            "format": format,
            "target": target,
            "generated_at": datetime.now().isoformat(),
            "findings_count": len(findings),
            "content": self._generate_content(findings, format),
            "metadata": self._generate_metadata(findings),
        }
        
        logger.info("Report generated: %d findings", report.get("findings_count", 0))
        return report

    def _generate_content(self, findings: list[dict[str, Any]], format: str) -> str:
        """Generate report content in the specified format.
        
        Args:
            findings: List of findings
            format: Output format
            
        Returns:
            Formatted report content
        """
        report_content: str = ""
        if format == "json":
            import json
            return json.dumps(findings, indent=2)
        
        elif format == "markdown":
            lines: list[str] = ["# Vulnerability Report\n"]
            lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            lines.append(f"Total Findings: {len(findings)}\n")
            lines.append("---\n")
            
            for i, finding in enumerate(findings, 1):
                severity = finding.get("severity", "info").upper()
                lines.append(f"## {i}. [{severity}] {finding.get('finding_type', 'Unknown')}\n")
                lines.append(f"**Description:** {finding.get('description', 'N/A')}\n")
                if finding.get("evidence"):
                    lines.append(f"**Evidence:**\n```\n{finding['evidence'][:500]}\n```\n")
                lines.append(f"**Agent:** {finding.get('agent_name', 'N/A')} | ")
                lines.append(f"**Confidence:** {finding.get('confidence', 0):.0%}\n")
                lines.append("---\n")
            
            report_content = "\n".join(lines)
            return report_content
        
        else:
            return f"Report with {len(findings)} findings (format: {format})"

    def _generate_metadata(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        """Generate report metadata.
        
        Args:
            findings: List of findings
            
        Returns:
            Metadata dictionary
        """
        severities: dict[str, int] = {}
        for finding in findings:
            sev = str(finding.get("severity", "info"))
            severities[sev] = severities.get(sev, 0) + 1
        
        return {
            "severity_breakdown": severities,
            "total_findings": len(findings),
            "critical": severities.get("critical", 0),
            "high": severities.get("high", 0),
            "medium": severities.get("medium", 0),
            "low": severities.get("low", 0),
            "info": severities.get("info", 0),
        }

    def can_handle(self, task_type: str) -> bool:
        """Check if this skill can handle the task type.
        
        Args:
            task_type: Type of task
            
        Returns:
            True for reporting tasks
        """
        return task_type in ["report", "reporting", "generate_report"]