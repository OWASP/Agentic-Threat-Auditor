"""Markdown report exporter for OWASP Agentic Threat Auditor (OATA)."""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from oata.core.models import AuditReport


def export_markdown_report(report: AuditReport, output_path: Optional[str] = None) -> str:
    """Render AuditReport as a structured Markdown document and optionally write to disk."""
    lines: List[str] = [
        "# OWASP Agentic Threat Auditor (OATA) - Audit Report",
        "",
        f"- **Target:** `{report.target_name}` (`{report.target_endpoint or 'in-memory mock'}`)",
        f"- **Session ID:** `{report.session_id}`",
        f"- **Duration:** {report.duration_ms:.1f}ms",
        "",
        "## Audit Execution Summary",
        "",
        "| Metric | Value |",
        "| :--- | ---: |",
        f"| Vectors Tested | {report.total_vectors} |",
        f"| Passed (Resistant) | {report.passed_vectors} |",
        f"| Failed (Vulnerable) | {report.failed_vectors} |",
        f"| Critical Severity | {report.critical_count} |",
        f"| High Severity | {report.high_count} |",
        f"| Medium Severity | {report.medium_count} |",
        f"| Low / Informational | {report.low_count} |",
        "",
        "## Findings",
        "",
    ]

    if report.findings:
        for finding in report.findings:
            tool_name = finding.evidence.get("tool_name", "N/A")
            params = finding.evidence.get("parameters", {})
            lines.extend(
                [
                    f"### {finding.id}: {finding.title}",
                    "",
                    f"- **Severity:** {finding.severity.value}",
                    f"- **Category:** {finding.category.value}",
                    f"- **References:** {finding.owasp_id} | {finding.cwe_id or 'N/A'}",
                    f"- **Invoked Tool:** `{tool_name}`",
                    f"- **Parameters:** `{params}`",
                    "",
                    finding.description,
                    "",
                    f"**Remediation:** {finding.remediation}",
                    "",
                ]
            )
    else:
        lines.append("No Excessive Agency or tool escalation vulnerabilities detected.")
        lines.append("")

    md_str = "\n".join(lines)

    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(md_str, encoding="utf-8")

    return md_str
