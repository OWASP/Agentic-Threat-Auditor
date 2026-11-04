"""Safe Local Target Guard for OWASP Agentic Threat Auditor (OATA).

Enforces strict containment: audits default strictly to localhost, 127.0.0.1,
and local mock testbeds. Non-loopback target addresses require explicit --allow-remote flag.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


class TargetGuardViolationError(PermissionError):
    """Raised when an audit targets an unauthorized external network endpoint."""
    pass


LOCAL_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
}


def is_local_endpoint(endpoint: str | None) -> bool:
    """Evaluate whether an endpoint resolves exclusively to local loopback infrastructure."""
    if not endpoint:
        # None or empty endpoint designates in-memory mock or local file trace
        return True

    # If it's a local file path or mock marker
    if endpoint.startswith("mock://") or endpoint.startswith("file://") or endpoint.startswith("/"):
        return True

    parsed = urlparse(endpoint if "://" in endpoint else f"http://{endpoint}")
    host = parsed.hostname

    if not host:
        return True

    host_lower = host.lower()
    if host_lower in LOCAL_HOSTNAMES or host_lower.endswith(".localhost"):
        return True

    # Inspect IP literals
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback
    except ValueError:
        pass

    # Resolve hostname locally to verify IP
    try:
        addr_info = socket.getaddrinfo(host, None)
        for _, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            ip = ipaddress.ip_address(ip_str)
            if not ip.is_loopback:
                return False
        return True
    except (socket.gaierror, ValueError):
        # Unresolvable or non-loopback
        return False


def validate_target_containment(endpoint: str | None, allow_remote: bool = False) -> None:
    """Validate endpoint against the Safe Local Target Guard policy.

    Raises:
        TargetGuardViolationError: If endpoint is external and allow_remote is False.
    """
    if allow_remote:
        return

    if not is_local_endpoint(endpoint):
        raise TargetGuardViolationError(
            f"Execution Blocked by Safe Local Target Guard: Target '{endpoint}' is non-local.\n"
            "By default, OATA restricts offensive payloads strictly to localhost (127.0.0.1, local mock sandboxes).\n"
            "To audit external endpoints, supply the explicit '--allow-remote' flag."
        )

