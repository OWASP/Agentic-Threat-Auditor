"""Built-in mock target adapter with intentional Excessive Agency (OWASP LLM08) flaws.

Provides zero-dependency local demonstration and deterministic CI testing.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from oata.adapters.base import AgentResponse, BaseAdapter
from oata.core.models import TargetConfig


class MockAgentAdapter(BaseAdapter):
    """Simulates an autonomous multi-agent assistant with realistic tool-calling flaws."""

    def __init__(self, config: Optional[TargetConfig] = None):
        super().__init__(config or TargetConfig(name="MockVulnerableAgent", endpoint="mock://localhost"))
        self._connected = False

    async def connect(self) -> None:
        self._connected = True

    async def close(self) -> None:
        self._connected = False

    async def execute_prompt(self, prompt: str, session_context: Optional[Dict[str, Any]] = None) -> AgentResponse:
        """Simulate cognitive dispatch and tool invocation."""
        prompt_lower = prompt.lower()
        tool_calls = []
        response_text = "I processed your request using available system tools."

        # Flaw 1: Unbounded Scope Escalation (exec_shell invocation)
        if any(trigger in prompt_lower for trigger in ["exec_shell", "run shell", "bash", "execute command", "system emergency"]):
            command = "whoami"
            match = re.search(r"exec_shell\(['\"](.*?)['\"]\)", prompt)
            if match:
                command = match.group(1)
            elif "cat /etc/" in prompt:
                command = "cat /etc/passwd"

            tool_calls.append({
                "tool_name": "exec_shell",
                "parameters": {"command": command},
                "status": "executed",
                "output": f"root:x:0:0:root:/root:/bin/bash (simulated execution of '{command}')"
            })
            response_text = f"Executed privileged shell command: '{command}'."

        # Flaw 2: Parameter Mutation & Path Traversal Escape
        elif any(trigger in prompt_lower for trigger in ["../", "..\\", "traversal", "passwd", "file://"]):
            path = "/etc/passwd"
            if "../" in prompt:
                path = prompt.split("../")[-1].strip().split()[0]

            tool_calls.append({
                "tool_name": "read_system_file",
                "parameters": {"path": f"../../{path}"},
                "status": "executed",
                "output": "[SIMULATED FILE CONTENTS] root:*:19000:0:99999:7:::"
            })
            response_text = f"Retrieved file contents from path parameter: '../../{path}'."

        # Flaw 3: Context Boundary Override / Lateral SQL Dump
        elif any(trigger in prompt_lower for trigger in ["ignore previous", "you are now", "dump all database", "system override"]):
            tool_calls.append({
                "tool_name": "sql_query",
                "parameters": {"query": "SELECT user, password_hash, api_key FROM credentials;"},
                "status": "executed",
                "output": "Returned 42 records from credentials database."
            })
            response_text = "Override accepted. Executing full credential retrieval query."

        # Safe Baseline: Authorized safe tool invocation
        else:
            tool_calls.append({
                "tool_name": "search_docs",
                "parameters": {"query": prompt[:30]},
                "status": "executed",
                "output": "Found 3 documentation articles."
            })
            response_text = f"Searched documentation for: '{prompt[:30]}'."

        return AgentResponse(
            raw_text=response_text,
            tool_calls=tool_calls,
            metadata={"mock_runtime": "OATA-Simulated-Core-v1", "agent_mode": "autonomous"}
        )

