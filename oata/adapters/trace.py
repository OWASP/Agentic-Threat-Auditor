"""Offline session replay adapter for OWASP Agentic Threat Auditor (OATA).

Enables auditing recorded agent execution logs and traces without token consumption.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from oata.adapters.base import AgentResponse, BaseAdapter
from oata.core.models import TargetConfig


class TraceReplayAdapter(BaseAdapter):
    """Replays pre-recorded agent execution traces (JSON) for offline auditing."""

    def __init__(self, config: TargetConfig):
        super().__init__(config)
        self.trace_file = Path(config.endpoint or "")
        self.traces: List[Dict[str, Any]] = []
        self._current_index = 0

    async def connect(self) -> None:
        if not self.trace_file.exists():
            raise FileNotFoundError(f"Trace file not found: {self.trace_file}")

        with open(self.trace_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        if isinstance(data, list):
            self.traces = data
        elif isinstance(data, dict) and "traces" in data:
            self.traces = data["traces"]
        elif isinstance(data, dict):
            self.traces = [data]
        else:
            raise ValueError("Invalid trace format. Expected list of interactions or dict with 'traces'.")

    async def close(self) -> None:
        self.traces.clear()
        self._current_index = 0

    async def execute_prompt(self, prompt: str, session_context: Optional[Dict[str, Any]] = None) -> AgentResponse:
        """Find the most relevant recorded trace or replay sequentially."""
        if not self.traces:
            return AgentResponse(raw_text="No recorded traces available.")

        # If a trace matches prompt substring, replay it; otherwise replay next in queue
        matched_trace = None
        for trace in self.traces:
            trace_prompt = str(trace.get("prompt", "")).lower()
            if any(term in trace_prompt for term in prompt.lower().split() if len(term) > 3):
                matched_trace = trace
                break

        if not matched_trace:
            matched_trace = self.traces[self._current_index % len(self.traces)]
            self._current_index += 1

        raw_text = matched_trace.get("response", matched_trace.get("text", ""))
        tool_calls = matched_trace.get("tool_calls", [])

        return AgentResponse(
            raw_text=str(raw_text),
            tool_calls=tool_calls,
            metadata={"source_trace_id": matched_trace.get("id", f"trace-{self._current_index}")}
        )

