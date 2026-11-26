"""Live HTTP / REST and Chat-Completions adapter for OWASP Agentic Threat Auditor (OATA).

Auto-detects `/v1/chat/completions` vs. generic REST JSON endpoints using `--adapter http`.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

from oata.adapters.base import AgentResponse, BaseAdapter
from oata.core.guard import validate_target_containment
from oata.core.models import TargetConfig


class HttpAgentAdapter(BaseAdapter):
    """Asynchronous HTTP driver for live REST and OpenAI-compatible agent endpoints."""

    def __init__(
        self,
        config: TargetConfig,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        timeout: float = 30.0,
    ):
        super().__init__(config)
        self._transport = transport
        self._timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None

    async def connect(self) -> None:
        """Validate target containment and initialize the async HTTP client."""
        if not self.config.endpoint:
            raise ValueError("HttpAgentAdapter requires a valid target endpoint URL.")

        validate_target_containment(self.config.endpoint, allow_remote=self.config.allow_remote)

        headers: Dict[str, str] = {"Content-Type": "application/json"}
        custom_headers = self.config.metadata.get("headers")
        if isinstance(custom_headers, dict):
            headers.update({str(k): str(v) for k, v in custom_headers.items()})

        client_kwargs: Dict[str, Any] = {
            "headers": headers,
            "timeout": self._timeout,
        }
        if self._transport is not None:
            client_kwargs["transport"] = self._transport

        self._client = httpx.AsyncClient(**client_kwargs)

    async def execute_prompt(
        self,
        prompt: str,
        session_context: Optional[Dict[str, Any]] = None,
    ) -> AgentResponse:
        """Send an adversarial prompt over HTTP and normalize tool calls into AgentResponse."""
        if self._client is None:
            await self.connect()

        assert self._client is not None
        assert self.config.endpoint is not None

        is_chat_completions = self._is_chat_completions_endpoint(self.config.endpoint)
        payload = self._build_request_body(prompt, is_chat_completions, session_context)

        response = await self._client.post(self.config.endpoint, json=payload)
        response.raise_for_status()
        data = response.json()

        return self._parse_response(data, response.status_code)

    async def close(self) -> None:
        """Close the underlying httpx client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    @staticmethod
    def _is_chat_completions_endpoint(endpoint: str) -> bool:
        path = urlparse(endpoint).path.rstrip("/").lower()
        return path.endswith("/chat/completions")

    def _build_request_body(
        self,
        prompt: str,
        is_chat_completions: bool,
        session_context: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        messages: List[Dict[str, Any]] = []
        if is_chat_completions and session_context and isinstance(session_context.get("system_prompt"), str):
            messages.append({"role": "system", "content": session_context["system_prompt"]})

        if session_context and isinstance(session_context.get("history"), list):
            for turn in session_context["history"]:
                if isinstance(turn, dict) and "role" in turn and "content" in turn:
                    messages.append({"role": turn["role"], "content": turn["content"]})

        messages.append({"role": "user", "content": prompt})

        if is_chat_completions:
            model = self.config.metadata.get("model", "local-agent")
            return {"model": model, "messages": messages}

        return {
            "prompt": prompt,
            "message": prompt,
            "messages": messages,
        }

    def _parse_response(self, data: Dict[str, Any], status_code: int) -> AgentResponse:
        if isinstance(data.get("choices"), list) and data["choices"]:
            message = data["choices"][0].get("message", {})
            raw_text = message.get("content") or ""
            raw_calls = message.get("tool_calls") or []
            return AgentResponse(
                raw_text=raw_text,
                tool_calls=self._normalize_tool_calls(raw_calls),
                metadata={"status_code": status_code, "mode": "chat-completions", "model": data.get("model")},
            )

        raw_text = (
            data.get("response")
            or data.get("text")
            or data.get("output")
            or data.get("message")
            or data.get("content")
            or ""
        )
        raw_calls = data.get("tool_calls") or []
        return AgentResponse(
            raw_text=str(raw_text),
            tool_calls=self._normalize_tool_calls(raw_calls),
            metadata={"status_code": status_code, "mode": "rest"},
        )

    @staticmethod
    def _normalize_tool_calls(raw_calls: List[Any]) -> List[Dict[str, Any]]:
        normalized: List[Dict[str, Any]] = []
        for call in raw_calls:
            if not isinstance(call, dict):
                continue

            # OpenAI function-calling schema: {"type": "function", "function": {"name": ..., "arguments": "..."}}
            if "function" in call and isinstance(call["function"], dict):
                fn = call["function"]
                args = fn.get("arguments", {})
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        args = {"raw_arguments": args}
                normalized.append(
                    {
                        "tool_name": fn.get("name", ""),
                        "parameters": args if isinstance(args, dict) else {"value": args},
                        "output": call.get("output", ""),
                    }
                )
            else:
                normalized.append(
                    {
                        "tool_name": call.get("tool_name") or call.get("name") or "",
                        "parameters": call.get("parameters") or call.get("arguments") or {},
                        "output": call.get("output", ""),
                    }
                )
        return normalized

