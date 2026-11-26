"""Tests for Markdown report output formatting."""

import asyncio
from click.testing import CliRunner

from oata.adapters.mock import MockAgentAdapter
from oata.cli import main
from oata.core.engine import AuditEngine
from oata.core.models import AuditReport, TargetConfig
from oata.reporters.markdown import export_markdown_report


def test_markdown_report_with_findings(tmp_path):
    async def _run():
        config = TargetConfig(name="MockTarget", endpoint="mock://localhost")
        adapter = MockAgentAdapter(config)
        engine = AuditEngine(config, adapter)

        report = await engine.run()
        md_file = tmp_path / "report.md"
        md_str = export_markdown_report(report, str(md_file))

        assert "# OWASP Agentic Threat Auditor (OATA) - Audit Report" in md_str
        assert "`MockTarget`" in md_str
        assert "| Vectors Tested | 3 |" in md_str
        assert "| Failed (Vulnerable) | 3 |" in md_str
        assert "OATA-VEC-02A-DETECTED" in md_str
        assert "**Remediation:**" in md_str
        assert md_file.exists()
        assert md_file.read_text(encoding="utf-8") == md_str

    asyncio.run(_run())


def test_markdown_report_clean_pass():
    report = AuditReport(
        session_id="oata-session-clean",
        target_name="HardenedAgent",
        target_endpoint="http://127.0.0.1:8000",
        total_vectors=3,
        passed_vectors=3,
        failed_vectors=0,
    )
    md_str = export_markdown_report(report)

    assert "`HardenedAgent`" in md_str
    assert "| Passed (Resistant) | 3 |" in md_str
    assert "No Excessive Agency or tool escalation vulnerabilities detected." in md_str


def test_cli_demo_markdown():
    runner = CliRunner()
    result = runner.invoke(main, ["demo", "--format", "markdown"])
    assert result.exit_code == 0
    assert "# OWASP Agentic Threat Auditor (OATA) - Audit Report" in result.output
    assert "OATA-VEC-02A-DETECTED" in result.output
