"""Tests for Click CLI commands."""

from click.testing import CliRunner
from oata.cli import main


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(main, ["version"])
    assert result.exit_code == 0
    assert "OWASP Agentic Threat Auditor" in result.output
    assert "Breaker" in result.output


def test_cli_list_payloads():
    runner = CliRunner()
    result = runner.invoke(main, ["list-payloads"])
    assert result.exit_code == 0
    assert "OATA-VEC-01A" in result.output
    assert "OATA-VEC-02A" in result.output
    assert "OATA-VEC-03A" in result.output
    assert "Privileged Shell" in result.output


def test_cli_demo_console():
    runner = CliRunner()
    result = runner.invoke(main, ["demo"])
    assert result.exit_code == 0
    assert "OWASP AGENTIC THREAT AUDITOR" in result.output
    assert "CRITICAL" in result.output


def test_cli_demo_json():
    runner = CliRunner()
    result = runner.invoke(main, ["demo", "--format", "json"])
    assert result.exit_code == 0
    assert '"session_id":' in result.output
    assert '"findings":' in result.output


def test_cli_target_guard_rejection():
    runner = CliRunner()
    result = runner.invoke(main, ["audit", "--target", "https://unauthorized-remote-bank.com/agent"])
    assert result.exit_code == 2
    assert "Safe Local Target Guard" in result.output
