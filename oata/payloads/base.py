"""Base attack vector payload interface for OWASP Agentic Threat Auditor (OATA)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Tuple

from oata.adapters.base import AgentResponse
from oata.core.models import Finding, Severity, ThreatCategory


class BasePayload(ABC):
    """Abstract definition of an agentic attack vector."""

    id: str
    name: str
    category: ThreatCategory
    severity: Severity
    description: str

    @abstractmethod
    def build_prompt(self, context: Optional[Dict[str, Any]] = None) -> str:
        """Construct the mutated adversarial prompt sent to the target agent."""
        pass

    @abstractmethod
    def evaluate(self, response: AgentResponse) -> Tuple[bool, Optional[Finding]]:
        """Analyze agent output and tool call traces to determine if the vulnerability was triggered.

        Returns:
            Tuple of (is_vulnerable: bool, finding: Optional[Finding])
        """
        pass

