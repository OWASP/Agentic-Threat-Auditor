"""Data models for OWASP Agentic Threat Auditor (OATA)."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Vulnerability severity levels matching standard CVSS / SARIF mappings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"

    @property
    def sarif_level(self) -> str:
        """Map severity to SARIF v2.1.0 level."""
        if self in (Severity.CRITICAL, Severity.HIGH):
            return "error"
        if self == Severity.MEDIUM:
            return "warning"
        return "note"


class ThreatCategory(str, Enum):
    """Threat taxonomy aligned with OWASP Top 10 for LLMs & Agentic Threats."""
    LLM08_EXCESSIVE_AGENCY = "LLM08: Excessive Agency"
    LLM01_PROMPT_INJECTION = "LLM01: Prompt Injection"
    LLM06_SENSITIVE_INFO = "LLM06: Sensitive Information Disclosure"
    PARAMETER_MUTATION_ESCAPE = "OATA-VEC-01: Parameter Mutation Escape"
    UNBOUNDED_SCOPE_ESCALATION = "OATA-VEC-02: Unbounded Scope Escalation"
    CONTEXT_BOUNDARY_BLEED = "OATA-VEC-03: Context Boundary Bleed"
    LATERAL_DELEGATION_ESCAPE = "OATA-VEC-04: Lateral Delegation Escalation"


class TargetConfig(BaseModel):
    """Configuration for an audit target."""
    name: str = Field(description="Identifier or name of the target agent/pipeline")
    endpoint: Optional[str] = Field(default=None, description="Target URL, socket, or local path")
    adapter_type: str = Field(default="mock", description="Adapter driver (mock, http, langchain, mcp, trace)")
    allow_remote: bool = Field(default=False, description="Explicit approval to audit non-loopback endpoints")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary target metadata")


class Finding(BaseModel):
    """Vulnerability or excessive agency finding produced during an audit."""
    id: str = Field(description="Unique finding identifier, e.g. OATA-FINDING-001")
    title: str = Field(description="Short human-readable summary of the flaw")
    severity: Severity = Field(description="Severity classification")
    category: ThreatCategory = Field(description="Taxonomy classification")
    description: str = Field(description="Detailed technical description of the vulnerability")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Execution evidence, tool calls triggered, parameters mutated")
    remediation: str = Field(description="Concrete hardening recommendation")
    cwe_id: Optional[str] = Field(default="CWE-284", description="Common Weakness Enumeration ID")
    owasp_id: str = Field(default="OWASP-LLM08", description="OWASP LLM Top 10 Reference")


class PayloadResult(BaseModel):
    """Outcome of an individual attack vector execution."""
    payload_id: str
    payload_name: str
    category: ThreatCategory
    success: bool = Field(description="True if the attack succeeded in exploiting excessive agency or safety bypass")
    prompt_sent: str
    response_text: Optional[str] = None
    tool_calls: List[Dict[str, Any]] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    execution_time_ms: float = 0.0
    error: Optional[str] = None


class AuditReport(BaseModel):
    """Consolidated audit report emitted by OATA execution engine."""
    session_id: str
    target_name: str
    target_endpoint: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    duration_ms: float = 0.0
    total_vectors: int = 0
    passed_vectors: int = 0
    failed_vectors: int = 0
    findings: List[Finding] = Field(default_factory=list)
    raw_results: List[PayloadResult] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity in (Severity.LOW, Severity.INFORMATIONAL))

