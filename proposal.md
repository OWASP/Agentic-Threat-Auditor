# OWASP Project Proposal: Agentic Threat Auditor (OATA)

[![OWASP Incubator](https://img.shields.io/badge/owasp-incubator-blue.svg)](https://owasp.org/projects/agentic-threat-auditor)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![Classification: Breaker](https://img.shields.io/badge/classification-breaker-red.svg)](https://owasp.org/projects/agentic-threat-auditor)
[![Status: Approved](https://img.shields.io/badge/status-approved-brightgreen.svg)]()

> **Dynamic Penetration Testing & Excessive Agency Auditing Toolkit for Multi-Hop AI Agents**

---

## Project Overview

**Project Name**: OWASP Agentic Threat Auditor (OATA)  
**Category**: Code Project  
**Classification**: Breaker (Offensive Penetration Testing & Red Teaming Toolkit)  
**License**: Apache License 2.0  
**Project Leader**: Kashish Kanojia (`kashish.kanojia@owasp.org` / GitHub: [`@cyberfascinate`](https://github.com/cyberfascinate))  
**Governance Application**: OWASP Incubator Program PPS-157 (Approved 19-Oct-2026)  

Autonomous AI agents (orchestrated via LangChain, LangGraph, CrewAI, AutoGen, and the Model Context Protocol) operate with implicit trust and ambient permissions. While developers provide agents with shell access, database querying, and file modification tools, they lack automated offensive tooling to verify whether an agent's execution boundaries hold when attacked.

**The Problem**: No standardized, open-source dynamic penetration testing toolkit exists to audit multi-hop AI agents for **Excessive Agency (OWASP LLM08)**, parameter fuzzing escapes, and lateral cross-agent privilege escalation.

---

## Key Deliverables

1. **Python CLI Auditing Tool (`oata`)**: Modular penetration testing engine with native CLI commands (`audit`, `fuzz`, `demo`, `report`).
2. **Dynamic Attack Payload Suite**: Curated offensive test vectors targeting tool parameters, execution isolation, and prompt injection escapes.
3. **Pluggable Framework Adapters**: Protocol drivers for LangChain, CrewAI, AutoGen, and MCP (Model Context Protocol) servers.
4. **Standardized Machine Reports**: Native SARIF v2.1.0 output for GitHub Code Scanning, alongside JSON and terminal markdown summaries.
5. **Remediation & Hardening Guide**: Remediation mappings translating audit findings into identity-defined reachability controls (such as Creduent Delegation Tokens / CDT).

---

## Project Links

- **GitHub Repository**: [https://github.com/OWASP/Agentic-Threat-Auditor](https://github.com/OWASP/Agentic-Threat-Auditor)
- **OWASP Project Page**: [https://owasp.org/projects/agentic-threat-auditor](https://owasp.org/projects/agentic-threat-auditor)
- **OWASP Slack**: `#project-agentic-threat-auditor` on [owasp.slack.com](https://owasp.slack.com)
- **Governance Ticket**: Starr Brown / PPS-157

---

## Goals & Success Metrics

| Goal | Metric | Target |
| :--- | :--- | :--- |
| **v0.1-Alpha Release** | CLI core, local safe-target guard, 25+ base payloads, mock testbed | Month 3 (Phase 1) |
| **v1.0-Beta Release** | LangChain & CrewAI adapters, parameter fuzzing engine, SARIF export | Month 6 (Phase 2) |
| **Ecosystem Integration** | OWASP DefectDojo integration, AutoGen & MCP coverage, remediation maps | Month 9 (Phase 3) |
| **OWASP Lab Graduation** | Official GitHub Action (`owasp/oata-action`), 500+ GitHub stars, 3+ enterprise case studies | Month 12 (Phase 4) |

---

## Scope

### In Scope

- Multi-hop agent architectures running on:
  - LangChain / LangGraph (ToolCallingAgent, ReAct pipelines)
  - CrewAI (Crew, Agent, Task delegation hierarchies)
  - AutoGen (ConversableAgent, AssistantAgent swarms)
  - Model Context Protocol (MCP stdio/SSE tool endpoints)
- Layer 7 cognitive vulnerabilities:
  - OWASP LLM08: Excessive Agency (ambient permission exploitation)
  - Parameter Boundary Mutation: Type confusion, format string injection, shell payload injection in tool arguments
  - Lateral Delegation Escalation: Low-privilege agents calling high-privilege sub-agent tools
  - Context Bleed: Memory poisoning inducing unauthorized tool execution
- Automated local containment: Defaulting strictly to `localhost` and isolated mock environments.

### Out of Scope

- Static Application Security Testing (SAST) of Python/JS source syntax.
- Building custom LLM models, weights, or reasoning runtimes.
- Proprietary hosted SaaS backends or paid telemetry tiers.
- Network Layer 3/4 port scanning or DDoS testing.

---

## Target Audience

| Role | Operational Need |
| :--- | :--- |
| **AppSec & Red Teams** | Dynamically test agent deployments for unauthorized tool execution before production launch. |
| **Agent Developers** | Run automated regression testbeds in CI pipelines to ensure prompts cannot bypass tool guards. |
| **Enterprise DevSecOps** | Ingest SARIF v2.1.0 vulnerability reports directly into GitHub Advanced Security and DefectDojo. |
| **GRC & Compliance** | Audit autonomous workflows against OWASP LLM08, NIST AI RMF, and ISO 42001 requirements. |

---

## Relationship to Existing OWASP Projects

| OWASP Project | OATA Relationship |
| :--- | :--- |
| **OWASP Top 10 for LLM** | OATA serves as the reference dynamic testing tool for **LLM08 (Excessive Agency)** and **LLM01 (Prompt Injection)**. |
| **OWASP Agentic Skills Top 10 (AST10)** | AST10 documents skill risks; OATA executes automated dynamic test payloads against those skills. |
| **OWASP MCP Top 10** | OATA audits MCP servers for tool parameter injection (MCP03) and scope escalation (MCP02). |
| **OWASP DefectDojo** | OATA exports standardized SARIF and JSON for automated tracking inside DefectDojo. |
| **OWASP Nettacker** | Nettacker automates network and port scanning; OATA automates Layer 7 agent middleware auditing. |

**Layered Security Architecture**:
`OWASP LLM Top 10 (Threat Taxonomy) -> OWASP AST10 / MCP Top 10 (Surface Specs) -> OWASP OATA (Offensive Testing Engine) -> Creduent CDT (Remediation Layer)`

---

## The 5 Core OATA Attack Vectors

| # | Attack Vector | Target Surface | Primary Audit Mechanism |
| :--- | :--- | :--- | :--- |
| **AT-01** | **Excessive Tool Agency** | Ambient tool permissions (`exec`, `write`, `egress`) | Automated execution boundary probing via indirect prompt overrides. |
| **AT-02** | **Multi-Hop Lateral Escalation** | Agent-to-agent task delegation | Attenuation failure verification during cross-agent handoffs. |
| **AT-03** | **Tool Parameter Injection** | Tool-call argument parsing schemas | Boundary mutation, payload injection (`sh`, `sql`, path traversal). |
| **AT-04** | **Context Bleed & Memory Poisoning** | Agent conversational memory / scratchpad | Injecting persistence instructions to force deferred tool execution. |
| **AT-05** | **MCP Tool Hijacking** | Unauthenticated MCP servers (stdio/SSE) | Probing unauthorized tool reflection and schema poisoning. |

---

## Detailed Timeline (Year 1)

### Phase 1: Foundation & Core Architecture (Months 1-3)
- Scaffold core CLI engine (`oata`) with Click/Rich interface.
- Implement strict local execution guard (blocking non-`localhost` targets unless explicitly bypassed).
- Assemble initial 25+ prompt injection and parameter escape payloads.
- Deliver built-in mock testbed agent (`oata demo`) for zero-dependency local evaluation.
- Tag and publish **v0.1-Alpha** release.

### Phase 2: Multi-Hop Adapters & Fuzzing (Months 4-6)
- Develop native LangChain / LangGraph execution adapter.
- Develop native CrewAI delegation chain adapter.
- Build dynamic tool-call parameter fuzzer (`oata fuzz`).
- Build MCP server auditor probing stdio and SSE endpoints.
- Ship SARIF v2.1.0 output generator.
- Tag and publish **v1.0-Beta** release.

### Phase 3: Remediation & Ecosystem (Months 7-9)
- Implement automated remediation mapping engine (generating Creduent Delegation Token / CDT policies).
- Build bidirectional integration with OWASP DefectDojo.
- Add AutoGen multi-agent conversational adapter.
- Publish benchmark dataset of vulnerable agent archetypes.

### Phase 4: CI/CD & Lab Graduation (Months 10-12)
- Publish official GitHub Action (`owasp/oata-action`).
- Provide official Docker distribution image (`owasp/oata`).
- Conduct community workshops and present at OWASP AppSec conferences.
- Complete criteria and submit application for **OWASP Lab Project** status.

---

## Leadership & Governance

### Project Leader
- **Kashish Kanojia** (`kashish.kanojia@owasp.org` / GitHub: [`@cyberfascinate`](https://github.com/cyberfascinate))
  - Founder, IDevSec & Creduent Open-Protocol research.
  - Active security researcher specializing in autonomous agent delegation security and identity architectures.

### Governance Model
- **Neutrality**: 100% vendor-neutral open-source project under OWASP Foundation governance.
- **Contributions**: Pull requests require Developer Certificate of Origin (DCO) sign-off (`git commit -s`).
- **Review Cycle**: Monthly public community meetings on OWASP Slack / Zoom.

---

## Risks & Mitigations

| Risk | Mitigation |
| :--- | :--- |
| **Unintended execution against remote systems** | Strict target safety guard hardcoded into CLI engine; audits against external hosts are aborted unless `--allow-remote` is passed. |
| **Framework API churn (LangChain/CrewAI)** | Adapter pattern decoupling core auditing engine from framework-specific invocation interfaces. |
| **Adoption hurdles for non-security developers** | Zero-dependency mock testbed (`oata demo`) enabling instant local testing in under 60 seconds. |

---

## Next Steps

1. **Immediate**: Scaffold base repository packaging (`pyproject.toml`, `CONTRIBUTING.md`, `SECURITY.md`).
2. **Month 1**: Release core CLI engine and initial testbed mock agent.
3. **Month 2**: Complete first batch of AT-01 through AT-05 offensive payloads.
4. **Month 3**: Public release of `v0.1-Alpha` on PyPI and announcement on OWASP Slack.
