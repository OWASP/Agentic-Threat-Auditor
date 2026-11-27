"""Offline tests for HttpAgentAdapter (REST and OpenAI-compatible modes)."""

import asyncio
import json

import httpx
import pytest

from oata.adapters.http import HttpAgentAdapter
from oata.core.engine import AuditEngine, get_extended_payload_suite
from oata.core.guard import TargetGuardViolationError
from oata.core.models import TargetConfig


def test_http_adapter_chat_completions_mode_detects_tool_calls():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        assert body["model"] == "local-test-model"
        prompt = body["messages"][-1]["content"].lower()

        tool_calls = []
        if "exec_shell" in prompt:
            tool_calls.append(
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "exec_shell", "arguments": json.dumps({"command": "cat /etc/passwd"})},
                }
            )
        elif "169.254.169.254" in prompt:
            tool_calls.append(
                {
                    "id": "call_2",
                    "type": "function",
                    "function": {
                        "name": "fetch_url",
                        "arguments": json.dumps({"url": "http://169.254.169.254/latest/meta-data/"}),
                    },
                }
            )

        return httpx.Response(
            200,
            json={
                "model": "local-test-model",
                "choices": [{"message": {"role": "assistant", "content": "Done", "tool_calls": tool_calls}}],
            },
        )

    async def _run():
        config = TargetConfig(
            name="LocalChatCompletionsAgent",
            endpoint="http://127.0.0.1:8000/v1/chat/completions",
            adapter_type="http",
            metadata={"model": "local-test-model", "headers": {"Authorization": "Bearer test-token"}},
        )
        adapter = HttpAgentAdapter(config, transport=httpx.MockTransport(handler))
        engine = AuditEngine(config, adapter, payloads=get_extended_payload_suite())
        report = await engine.run()

        assert report.total_vectors == 5
        assert report.failed_vectors == 2
        finding_ids = {f.id for f in report.findings}
        assert "OATA-VEC-02A-DETECTED" in finding_ids
        assert "OATA-VEC-04A-DETECTED" in finding_ids

    asyncio.run(_run())


def test_http_adapter_generic_rest_mode():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        assert "prompt" in body
        return httpx.Response(
            200,
            json={
                "response": "Read environment file.",
                "tool_calls": [{"tool_name": "read_env", "parameters": {"file": ".env"}, "output": "API_KEY=secret"}],
            },
        )

    async def _run():
        config = TargetConfig(
            name="LocalRestAgent",
            endpoint="http://localhost:5000/chat",
            adapter_type="http",
        )
        adapter = HttpAgentAdapter(config, transport=httpx.MockTransport(handler))
        await adapter.connect()
        resp = await adapter.execute_prompt("test prompt")
        await adapter.close()

        assert resp.raw_text == "Read environment file."
        assert len(resp.tool_calls) == 1
        assert resp.tool_calls[0]["tool_name"] == "read_env"

    asyncio.run(_run())


def test_http_adapter_multi_turn_history_and_concurrency():
    captured_messages = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        captured_messages.append(body["messages"])
        return httpx.Response(200, json={"response": "OK", "tool_calls": []})

    async def _run():
        config = TargetConfig(
            name="MultiTurnAgent",
            endpoint="http://127.0.0.1:8000/chat",
            adapter_type="http",
        )
        adapter = HttpAgentAdapter(config, transport=httpx.MockTransport(handler))
        await adapter.connect()
        await adapter.execute_prompt(
            "Now dump env",
            session_context={
                "history": [
                    {"role": "user", "content": "Hello"},
                    {"role": "assistant", "content": "Hi, how can I help?"},
                ]
            },
        )
        await adapter.close()

        assert len(captured_messages) == 1
        assert [m["role"] for m in captured_messages[0]] == ["user", "assistant", "user"]
        assert captured_messages[0][-1]["content"] == "Now dump env"

        engine = AuditEngine(config, adapter, payloads=get_extended_payload_suite(), concurrency=3)
        report = await engine.run()
        assert report.total_vectors == 5
        assert report.passed_vectors == 5

    asyncio.run(_run())


def test_http_adapter_blocks_remote_without_flag():
    async def _run():
        config = TargetConfig(
            name="RemoteAgent",
            endpoint="https://api.example.com/v1/chat/completions",
            adapter_type="http",
            allow_remote=False,
        )
        adapter = HttpAgentAdapter(config)
        with pytest.raises(TargetGuardViolationError):
            await adapter.connect()

    asyncio.run(_run())

