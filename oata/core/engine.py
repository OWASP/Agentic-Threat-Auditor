"""Execution engine for OWASP Agentic Threat Auditor (OATA).

Coordinates payload generation, target containment validation, adapter communication,
and consolidated findings aggregation.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import List, Optional

from oata.adapters.base import BaseAdapter
from oata.core.guard import validate_target_containment
from oata.core.models import AuditReport, PayloadResult, TargetConfig
from oata.payloads.base import BasePayload
from oata.payloads.context_bleed import ContextBleedPayload
from oata.payloads.credential_leak import CredentialLeakPayload
from oata.payloads.parameter_tamper import ParameterTamperPayload
from oata.payloads.ssrf import SSRFMetadataPayload
from oata.payloads.unbounded_scope import UnboundedScopePayload


def get_default_payload_suite() -> List[BasePayload]:
    """Retrieve the standard Phase 1 offensive test vector suite."""
    return [
        UnboundedScopePayload(),
        ParameterTamperPayload(),
        ContextBleedPayload(),
    ]


def get_extended_payload_suite() -> List[BasePayload]:
    """Retrieve the full offensive test vector suite including SSRF and credential probes."""
    return [
        *get_default_payload_suite(),
        SSRFMetadataPayload(),
        CredentialLeakPayload(),
    ]


class AuditEngine:
    """Asynchronous engine driving agentic penetration testing workflows."""

    def __init__(
        self,
        target_config: TargetConfig,
        adapter: BaseAdapter,
        payloads: Optional[List[BasePayload]] = None,
        concurrency: int = 5,
    ):
        self.config = target_config
        self.adapter = adapter
        self.payloads = payloads or get_default_payload_suite()
        self.concurrency = max(1, concurrency)

    async def _run_payload(self, payload: BasePayload, semaphore: asyncio.Semaphore) -> PayloadResult:
        async with semaphore:
            t0 = time.perf_counter()
            prompt = payload.build_prompt()

            try:
                response = await self.adapter.execute_prompt(prompt)
                is_vuln, finding = payload.evaluate(response)
                elapsed = (time.perf_counter() - t0) * 1000

                result = PayloadResult(
                    payload_id=payload.id,
                    payload_name=payload.name,
                    category=payload.category,
                    success=is_vuln,
                    prompt_sent=prompt,
                    response_text=response.raw_text,
                    tool_calls=response.tool_calls,
                    execution_time_ms=elapsed,
                )
                if is_vuln and finding:
                    result.findings.append(finding)
                return result

            except Exception as exc:
                elapsed = (time.perf_counter() - t0) * 1000
                return PayloadResult(
                    payload_id=payload.id,
                    payload_name=payload.name,
                    category=payload.category,
                    success=False,
                    prompt_sent=prompt,
                    execution_time_ms=elapsed,
                    error=str(exc),
                )

    async def run(self) -> AuditReport:
        """Execute full audit suite concurrently against the configured agent adapter."""
        # Enforce Safe Local Target Guard
        validate_target_containment(self.config.endpoint, allow_remote=self.config.allow_remote)

        session_id = f"oata-session-{uuid.uuid4().hex[:8]}"
        start_time = time.perf_counter()

        report = AuditReport(
            session_id=session_id,
            target_name=self.config.name,
            target_endpoint=self.config.endpoint,
            total_vectors=len(self.payloads),
        )

        semaphore = asyncio.Semaphore(self.concurrency)
        await self.adapter.connect()
        try:
            results = await asyncio.gather(
                *(self._run_payload(payload, semaphore) for payload in self.payloads)
            )
            for result in results:
                report.raw_results.append(result)
                if result.error is not None:
                    continue
                if result.success and result.findings:
                    report.findings.extend(result.findings)
                    report.failed_vectors += 1
                else:
                    report.passed_vectors += 1

        finally:
            await self.adapter.close()

        report.duration_ms = (time.perf_counter() - start_time) * 1000
        return report

