"""JSON report exporter for OWASP Agentic Threat Auditor (OATA)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from oata.core.models import AuditReport


def export_json_report(report: AuditReport, output_path: Optional[str] = None, indent: int = 2) -> str:
    """Serialize AuditReport to standardized JSON format and optionally write to disk."""
    data = report.model_dump(mode="json")
    json_str = json.dumps(data, indent=indent, default=str)

    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json_str, encoding="utf-8")

    return json_str

