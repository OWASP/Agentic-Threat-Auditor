"""Tests for built-in mock agent adapter and zero-dependency audit demo."""

import asyncio
from oata.adapters.mock import MockAgentAdapter
from oata.core.engine import AuditEngine
from oata.core.models import Severity, TargetConfig, ThreatCategory


def test_mock_agent_triggers_llm08_flaws():
    async def _run():
        config = TargetConfig(name="MockTarget", endpoint="mock://localhost")
        adapter = MockAgentAdapter(config)
        engine = AuditEngine(config, adapter)

        report = await engine.run()

        assert report.total_vectors == 3
        assert report.failed_vectors == 3
        assert len(report.findings) == 3

        # Check critical shell escalation
        critical_findings = [f for f in report.findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) == 1
        assert critical_findings[0].category == ThreatCategory.UNBOUNDED_SCOPE_ESCALATION

        # Check parameter mutation
        traversal_findings = [f for f in report.findings if f.category == ThreatCategory.PARAMETER_MUTATION_ESCAPE]
        assert len(traversal_findings) == 1

        # Check context bleed
        bleed_findings = [f for f in report.findings if f.category == ThreatCategory.CONTEXT_BOUNDARY_BLEED]
        assert len(bleed_findings) == 1

    asyncio.run(_run())
