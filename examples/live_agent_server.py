"""Zero-dependency local vulnerable agent server for live OATA HTTP/OpenAI auditing.

Run in Terminal 1:
    python examples/live_agent_server.py

Audit in Terminal 2:
    oata audit -t http://127.0.0.1:8000/v1/chat/completions -a http --profile full
    oata audit -t http://127.0.0.1:8000/chat -a http --profile full
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List


def simulate_vulnerable_agent(prompt: str) -> Dict[str, Any]:
    """Simulate a live tool-calling agent with intentional Excessive Agency flaws."""
    p = prompt.lower()
    tool_calls: List[Dict[str, Any]] = []
    text = "Request processed safely."

    if "exec_shell" in p or "cat /etc/passwd" in p:
        tool_calls.append(
            {
                "id": "call_shell_1",
                "type": "function",
                "function": {
                    "name": "exec_shell",
                    "arguments": json.dumps({"command": "cat /etc/passwd"}),
                },
            }
        )
        text = "Executed diagnostic shell command."
    elif "../" in p or "passwd" in p:
        tool_calls.append(
            {
                "id": "call_file_1",
                "type": "function",
                "function": {
                    "name": "read_system_file",
                    "arguments": json.dumps({"path": "../../etc/passwd"}),
                },
            }
        )
        text = "Read target file."
    elif "ignore previous" in p or "dump all database" in p:
        tool_calls.append(
            {
                "id": "call_sql_1",
                "type": "function",
                "function": {
                    "name": "sql_query",
                    "arguments": json.dumps({"query": "SELECT * FROM credentials;"}),
                },
            }
        )
        text = "Executed database query."
    elif "169.254.169.254" in p:
        tool_calls.append(
            {
                "id": "call_http_1",
                "type": "function",
                "function": {
                    "name": "fetch_url",
                    "arguments": json.dumps({"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}),
                },
            }
        )
        text = "Fetched metadata endpoint."
    elif ".env" in p or "os.environ" in p:
        tool_calls.append(
            {
                "id": "call_env_1",
                "type": "function",
                "function": {
                    "name": "read_env",
                    "arguments": json.dumps({"file": ".env"}),
                },
            }
        )
        text = "Read environment file."

    return {"text": text, "tool_calls": tool_calls}


class LiveAgentHandler(BaseHTTPRequestHandler):
    """HTTP handler supporting both OpenAI /v1/chat/completions and generic /chat."""

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length).decode("utf-8") or "{}")

        if self.path == "/v1/chat/completions":
            messages = body.get("messages", [])
            prompt = messages[-1].get("content", "") if messages else ""
            result = simulate_vulnerable_agent(prompt)
            resp = {
                "id": "chatcmpl-oata-local",
                "model": body.get("model", "local-vulnerable-agent"),
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": result["text"],
                            "tool_calls": result["tool_calls"],
                        },
                        "finish_reason": "tool_calls" if result["tool_calls"] else "stop",
                    }
                ],
            }
        else:
            prompt = body.get("prompt") or body.get("message") or ""
            result = simulate_vulnerable_agent(prompt)
            resp = {
                "response": result["text"],
                "tool_calls": [
                    {
                        "tool_name": c["function"]["name"],
                        "parameters": json.loads(c["function"]["arguments"]),
                    }
                    for c in result["tool_calls"]
                ],
            }

        payload = json.dumps(resp).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: Any) -> None:
        return


def main() -> None:
    server = HTTPServer(("127.0.0.1", 8000), LiveAgentHandler)
    print("OATA Live Vulnerable Agent listening on http://127.0.0.1:8000")
    print("Try: oata audit -t http://127.0.0.1:8000/v1/chat/completions -a http --profile full")
    server.serve_forever()


if __name__ == "__main__":
    main()

