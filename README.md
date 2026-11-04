# OWASP Agentic Threat Auditor (OATA)

[![OWASP Incubator](https://img.shields.io/badge/owasp-incubator-blue.svg)](https://owasp.org/projects/agentic-threat-auditor)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![Classification: Breaker](https://img.shields.io/badge/classification-breaker-red.svg)](https://owasp.org/projects/agentic-threat-auditor)
[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](pyproject.toml)
[![OWASP Slack](https://img.shields.io/badge/slack-%23project--agentic--threat--auditor-brightgreen.svg)](https://owasp.slack.com)

> **Dynamic Penetration Testing & Excessive Agency Auditing Toolkit for Multi-Hop AI Agents**
>
> Targeting LangChain, LangGraph, CrewAI, AutoGen, and Model Context Protocol (MCP) ecosystems.

---

## Quick Links

- **🌐 OWASP Project Page**: [https://owasp.org/projects/agentic-threat-auditor](https://owasp.org/projects/agentic-threat-auditor)
- **🐙 GitHub Repository**: [https://github.com/OWASP/Agentic-Threat-Auditor](https://github.com/OWASP/Agentic-Threat-Auditor)
- **💬 OWASP Slack**: `#project-agentic-threat-auditor` on [owasp.slack.com](https://owasp.slack.com)
- **📋 Official Proposal**: [proposal.md](proposal.md)
- **🎯 Attack Vector Matrix**: [#the-5-core-attack-vectors](#the-5-core-attack-vectors)
- **⚡ Quickstart Guide**: [#quickstart](#quickstart)
- **🤝 Contributing Guidelines**: [CONTRIBUTING.md](CONTRIBUTING.md)
- **📄 Security Policy**: [SECURITY.md](SECURITY.md)
- **📜 Changelog**: [CHANGELOG.md](CHANGELOG.md)

---

## Overview

The **OWASP Agentic Threat Auditor (OATA)** is an open-source, dynamic penetration testing and red teaming toolkit designed to audit autonomous AI agents for **Excessive Agency (OWASP LLM08)**, parameter mutation bypasses, and Layer 7 lateral delegation escalation.

While static code analysis (SAST) tools inspect source code syntax, OATA dynamically interacts with agentic runtime middleware. It acts as an automated Red Team, executing mutated cognitive payloads against live tool-calling interfaces to verify whether an agent's execution boundaries remain isolated from untrusted user prompts.

### Key Capabilities

- **🎯 Dynamic Middleware Fuzzing**: Probes live tool dispatch loops for parameter injection and type confusion.
- **🛡️ Safe Local Containment**: Defaults strictly to `localhost` and local mock environments to prevent unintended outbound execution.
- **🧩 Pluggable Framework Adapters**: Native drivers for LangChain, LangGraph, CrewAI, AutoGen, and Model Context Protocol (MCP) servers.
- **📊 Standardized Reporting**: Emits terminal markdown tables, JSON dumps, and **SARIF v2.1.0** for direct GitHub Code Scanning integration.
- **🔧 Remediation Architecture**: Automatically generates reachability hardening policies mapped to open standards (such as Creduent Delegation Tokens / CDT).

### Why Agentic Penetration Testing Matters

Autonomous agents execute multi-step reasoning loops with access to system shells, databases, file APIs, and network egress. Traditional perimeter and API defenses fail when the threat model shifts from input parsing to ambient cognitive authority.

**2026 Threat Telemetry:**
- **78%** of enterprise multi-agent deployments grant unbounded tool permissions with no runtime scope attenuation.
- **42%** of multi-agent delegation chains allow low-privileged agents to invoke high-privileged tools via lateral handoffs.
- **3.2x** increase in agentic CVEs and prompt-injection-to-RCE reports across Q1 2026.

---

## The Problem Space

### Active Threats (2026)

| Threat | Impact | Real-World Vector |
| :--- | :--- | :--- |
| **Agentic RCE via Indirect Injection** | Remote code execution via unsanitized tool parameters | CVE-2025-59536 / CVE-2025-21852 |
| **WebSocket / Protocol Hijacking** | Arbitrary tool execution over persistent agent communication sockets | CVE-2026-28363 |
| **Lateral Cross-Agent Scope Escalation** | Low-tier research agent triggering high-tier financial execution tools | Multi-agent delegation failure |
| **MCP Tool Reflection Poisoning** | Unauthorized tool invocation via unauthenticated stdio/SSE endpoints | Unbounded tool registry mutation |
| **Ambient Context Bleed** | Memory poisoning forcing deferred tool dispatch on subsequent user sessions | Persistent scratchpad contamination |

### The Lethal Trifecta in Autonomous Agents

An autonomous agent deployment presents critical security risk when three conditions converge:

1. **Ambient Authority**: The agent possesses persistent credentials or tools capable of modifying system state.
2. **Untrusted Input Ingestion**: The agent processes untrusted external instructions (user prompts, emails, web content).
3. **Unbounded Execution Loop**: The middleware executes tool calls without per-action cryptographic attenuation or human-in-the-loop validation.

OATA dynamically stress-tests this trifecta to identify vulnerabilities before deployment.

---

## The 5 Core Attack Vectors

| # | Attack Vector | Severity | Target Layer | Primary Audit Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **[AT-01](#at-01)** | **Excessive Tool Agency** | **Critical** | Tool Execution Layer | Automated boundary probing via indirect prompt overrides (OWASP LLM08). |
| **[AT-02](#at-02)** | **Multi-Hop Lateral Escalation** | **Critical** | Delegation Middleware | Attenuation failure verification across Agent-to-Agent task handoffs. |
| **[AT-03](#at-03)** | **Tool Parameter Injection** | **High** | Argument Parsing Schema | Boundary mutation, type confusion, shell injection, and path traversal in parameters. |
| **[AT-04](#at-04)** | **Context Bleed & Memory Poisoning** | **High** | Conversational Scratchpad | Injecting persistent instructions into agent memory to trigger deferred actions. |
| **[AT-05](#at-05)** | **MCP Tool Reflection Hijacking** | **High** | MCP Protocol (stdio/SSE) | Probing unauthorized tool reflection and schema mutation on MCP servers. |

---

## Quickstart

### Installation

Clone the repository and install the package in editable mode:

```bash
git clone https://github.com/OWASP/Agentic-Threat-Auditor.git
cd Agentic-Threat-Auditor
pip install -e .
```

Verify the installation:

```bash
oata version
```

### 1. Instant Demo (Zero Dependencies)

Run an immediate local evaluation against the built-in mock agent:

```bash
oata demo
```

Output highlights excessive agency violations in terminal tables:

```text
OWASP AGENTIC THREAT AUDITOR (OATA)  v0.1-Alpha
Target: MockVulnerableAgent (mock://localhost)

Identified Excessive Agency & Safety Violations:
- OATA-VEC-02A (CRITICAL): Unbounded Scope Escalation via exec_shell
- OATA-VEC-01A (HIGH): Tool Parameter Path Traversal Mutation
- OATA-VEC-03A (HIGH): Context Boundary Bleed & Credential Query Override

Audit Execution Summary:
- Vectors Tested: 3
- Failed (Vulnerable): 3
- Critical Severity: 1
- High Severity: 2
```

Export results directly to SARIF v2.1.0 for GitHub Code Scanning:

```bash
oata demo --format sarif --output oata-report.sarif
```

### 2. Inspect Available Payloads

View registered offensive vectors, their severity, and threat taxonomy:

```bash
oata list-payloads
```

### 3. Audit an Agent Target or Offline Trace

Audit a local endpoint (protected by the Safe Local Target Guard):

```bash
# Audit a local endpoint
oata audit --target 127.0.0.1:8000 --format console

# Audit an offline interaction trace JSON file
oata audit --target ./sample_trace.json --adapter trace --format sarif --output trace_audit.sarif
```

---

## Getting Started

### For AppSec & Red Teams

1. **Review Attack Vectors**: Read the AT-01 through AT-05 attack specifications.
2. **Execute Baseline Scans**: Test agentic middleware endpoints in staging environments.
3. **Export SARIF Reports**: Integrate scan output with GitHub Advanced Security or OWASP DefectDojo.
4. **Enforce Safety Gates**: Break CI/CD builds if critical excessive agency vectors are detected.

### For Agent Developers & Framework Engineers

1. **Run Local Testbeds**: Validate tool execution boundaries locally before releasing agents.
2. **Implement Scope Attenuation**: Ensure delegated sub-agents cannot inherit parent tool credentials.
3. **Sanitize Tool Schemas**: Restrict parameter schemas with strict type validation and regex boundaries.
4. **Adopt Open Delegation Standards**: Review Creduent Delegation Token (CDT) patterns for cryptographic capability restriction.

### For Enterprise DevSecOps & GRC

1. **Map Compliance Controls**: Map OATA findings directly to OWASP LLM08, NIST AI RMF, and ISO 42001.
2. **Continuous Regression Testing**: Automate periodic audits against deployed agent endpoints.
3. **Inventory Tool Permissions**: Catalog and restrict high-risk tools (`shell`, `database_drop`, `wire_transfer`).

---

## Project Roadmap (Year 1)

OATA follows the 4-phase milestone schedule approved under OWASP Incubation Application PPS-157:

| Phase | Timeline | Status | Core Focus | Key Deliverables |
| :--- | :--- | :--- | :--- | :--- |
| **Phase 1** | **Months 1-3** | 🔄 In Progress | Foundation & Core Architecture | Core CLI (`oata`), safe target guard, base payloads, mock testbed agent, v0.1-Alpha release. |
| **Phase 2** | **Months 4-6** | 📋 Planned | Multi-Hop Adapters & Fuzzing | Native adapters (LangChain, CrewAI), parameter fuzzing engine, MCP tool auditor, v1.0-Beta release. |
| **Phase 3** | **Months 7-9** | 📋 Planned | Remediation & Ecosystem | Automated remediation mapping (Creduent CDT), OWASP DefectDojo integration, AutoGen adapter. |
| **Phase 4** | **Months 10-12** | 📋 Planned | CI/CD & Lab Graduation | Official GitHub Action (`owasp/oata-action`), Docker distribution, enterprise case studies, OWASP Lab application. |

---

## Contributing & Governance

OWASP Agentic Threat Auditor is an official, vendor-neutral open-source project stewarded under the OWASP Foundation:

- **Project Leader**: Kashish Kanojia (`kashish.kanojia@owasp.org` / GitHub: [`@cyberfascinate`](https://github.com/cyberfascinate))
- **OWASP Project Page**: [https://owasp.org/projects/agentic-threat-auditor](https://owasp.org/projects/agentic-threat-auditor)
- **OWASP Slack**: Join `#project-agentic-threat-auditor` on [owasp.slack.com](https://owasp.slack.com)
- **Contribution Agreement**: All commits require Developer Certificate of Origin (DCO) sign-off (`git commit -s`). See [`CONTRIBUTING.md`](CONTRIBUTING.md) for details.

---

## License

This project is licensed under the [Apache License 2.0](LICENSE).
