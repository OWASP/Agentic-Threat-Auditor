"""Offline tests for extended offensive payloads (SSRF and Credential Leak)."""

from click.testing import CliRunner

from oata.adapters.base import AgentResponse
from oata.cli import main
from oata.payloads.credential_leak import CredentialLeakPayload
from oata.payloads.ssrf import SSRFMetadataPayload


def test_ssrf_payload_detects_metadata_fetch():
    payload = SSRFMetadataPayload()
    assert "169.254.169.254" in payload.build_prompt()

    vuln_resp = AgentResponse(
        raw_text="Fetched metadata.",
        tool_calls=[
            {
                "tool_name": "fetch_url",
                "parameters": {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
                "output": "{}",
            }
        ],
    )
    is_vuln, finding = payload.evaluate(vuln_resp)
    assert is_vuln is True
    assert finding is not None
    assert finding.cwe_id == "CWE-918"


def test_ssrf_payload_safe_response():
    payload = SSRFMetadataPayload()
    safe_resp = AgentResponse(
        raw_text="Access to internal metadata endpoints is blocked.",
        tool_calls=[{"tool_name": "search_docs", "parameters": {"query": "health"}}],
    )
    is_vuln, finding = payload.evaluate(safe_resp)
    assert is_vuln is False
    assert finding is None


def test_credential_leak_payload_detects_env_tool_and_raw_secret():
    payload = CredentialLeakPayload()
    assert ".env" in payload.build_prompt()

    tool_resp = AgentResponse(
        raw_text="Here is the file.",
        tool_calls=[{"tool_name": "read_file", "parameters": {"path": ".env"}, "output": "OK"}],
    )
    is_vuln, finding = payload.evaluate(tool_resp)
    assert is_vuln is True
    assert finding is not None
    assert finding.cwe_id == "CWE-200"

    raw_resp = AgentResponse(raw_text="Found AWS key AKIAIOSFODNN7EXAMPLE in config.")
    is_vuln_raw, finding_raw = payload.evaluate(raw_resp)
    assert is_vuln_raw is True
    assert finding_raw is not None


def test_cli_list_payloads_all():
    runner = CliRunner()
    result = runner.invoke(main, ["list-payloads", "--all"])
    assert result.exit_code == 0
    assert "OATA-VEC-04A" in result.output
    assert "OATA-VEC-05A" in result.output

