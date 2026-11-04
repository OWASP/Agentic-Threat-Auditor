"""SARIF v2.1.0 Exporter for OWASP Agentic Threat Auditor (OATA).

Provides native output for GitHub Code Scanning integration and DevSecOps pipelines.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from oata.core.models import AuditReport


SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)


def export_sarif_report(report: AuditReport, output_path: Optional[str] = None) -> str:
    """Generate SARIF v2.1.0 compliant report from OATA findings."""
    rules_map: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for f in report.findings:
        rule_id = f.owasp_id or f.id.split("-")[0]
        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "name": f.category.value,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "help": {
                    "text": f"Remediation: {f.remediation}\nCWE: {f.cwe_id or 'N/A'}",
                    "markdown": f"### Remediation\n{f.remediation}\n\n**CWE**: `{f.cwe_id}`",
                },
                "properties": {
                    "tags": ["security", "ai-security", "owasp-top-10", "agentic-threat"],
                    "precision": "high",
                },
            }

        result = {
            "ruleId": rule_id,
            "level": f.severity.sarif_level,
            "message": {
                "text": f"{f.title}: {f.description}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": report.target_endpoint or f"agent://{report.target_name}",
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": 1,
                            "startColumn": 1
                        }
                    }
                }
            ],
            "properties": {
                "findingId": f.id,
                "severity": f.severity.value,
                "category": f.category.value,
                "evidence": f.evidence,
                "remediation": f.remediation,
            }
        }
        results.append(result)

    sarif_doc = {
        "$schema": SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "OWASP Agentic Threat Auditor (OATA)",
                        "version": "0.1.0a1",
                        "informationUri": "https://owasp.org/projects/agentic-threat-auditor",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
                "properties": {
                    "sessionId": report.session_id,
                    "targetName": report.target_name,
                    "durationMs": report.duration_ms,
                }
            }
        ],
    }

    sarif_str = json.dumps(sarif_doc, indent=2)

    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(sarif_str, encoding="utf-8")

    return sarif_str

