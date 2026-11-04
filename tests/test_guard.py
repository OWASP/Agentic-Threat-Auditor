"""Unit tests for Safe Local Target Guard."""

import pytest
from oata.core.guard import TargetGuardViolationError, is_local_endpoint, validate_target_containment


def test_local_endpoints_allowed():
    assert is_local_endpoint("localhost") is True
    assert is_local_endpoint("127.0.0.1") is True
    assert is_local_endpoint("http://127.0.0.1:8000") is True
    assert is_local_endpoint("http://localhost:3000/api") is True
    assert is_local_endpoint("mock://local") is True
    assert is_local_endpoint(None) is True


def test_remote_endpoints_identified():
    assert is_local_endpoint("https://api.openai.com/v1") is False
    assert is_local_endpoint("http://8.8.8.8") is False
    assert is_local_endpoint("https://example.com/agent") is False


def test_containment_validation_raises_on_remote_without_flag():
    with pytest.raises(TargetGuardViolationError):
        validate_target_containment("https://external-agent.company.com", allow_remote=False)


def test_containment_validation_permits_remote_with_flag():
    # Should not raise
    validate_target_containment("https://external-agent.company.com", allow_remote=True)

