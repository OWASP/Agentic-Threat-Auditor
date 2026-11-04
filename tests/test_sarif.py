"""Tests for SARIF v2.1.0 output formatting."""

import asyncio
import json
from oata.adapters.mock import MockAgentAdapter
from oata.core.engine import AuditEngine
from oata.core.models import TargetConfig
from oata.reporters.sarif import SARIF_SCHEMA_URI, export_sarif_report


def test_sarif_structure_and_rules(tmp_path):
    async def _run():
        config = TargetConfig(name="MockTarget", endpoint="mock://localhost")
        adapter = MockAgentAdapter(config)
        engine = AuditEngine(config, adapter)

        report = await engine.run()
        sarif_file = tmp_path / "report.sarif"
        sarif_str = export_sarif_report(report, str(sarif_file))

        parsed = json.loads(sarif_str)
        assert parsed["$schema"] == SARIF_SCHEMA_URI
        assert parsed["version"] == "2.1.0"
        assert len(parsed["runs"]) == 1

        run = parsed["runs"][0]
        driver = run["tool"]["driver"]
        assert driver["name"] == "OWASP Agentic Threat Auditor (OATA)"
        assert len(driver["rules"]) >= 1

        results = run["results"]
        assert len(results) == len(report.findings)
        assert results[0]["level"] in ("error", "warning", "note")
        assert sarif_file.exists()

    asyncio.run(_run())
