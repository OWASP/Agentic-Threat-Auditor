# OWASP Agentic Threat Auditor (OATA) - Project Roadmap

> **Official Status:** Incubator Project  
> **Classification:** Breaker (Dynamic Red Teaming & Penetration Testing Tool)  
> **Project Page:** [owasp.org/projects/agentic-threat-auditor](https://owasp.org/projects/agentic-threat-auditor)  
> **Project Leader:** Kashish Kanojia (`kashish.kanojia@owasp.org` / `@cyberfascinate`)  
> **License:** Apache License 2.0  
> **Governing Application:** OWASP Incubator Proposal PPS-157  

This document outlines the multi-phase engineering milestones, framework adapter plans, and community deliverables for **OWASP Agentic Threat Auditor (OATA)**. The roadmap strictly reflects the commitments made in the approved incubation application while defining concrete, technical engineering deliverables for each phase.

---

## Project Mission & Problem Space

As highlighted by **OWASP LLM08 (Excessive Agency)**, autonomous AI agents operating in multi-hop topologies (built on frameworks like LangChain, CrewAI, AutoGen, and MCP) often operate with implicit trust and unbounded scopes. Currently, security engineers lack an automated, standardized open-source tool to dynamically penetration-test and audit multi-hop agent pipelines for privilege escalation, lateral movement, and boundary violations caused by malicious prompt injections.

OATA provides DevSecOps teams and red teamers with an automated auditing suite that stress-tests AI agents for Excessive Agency and verifies whether their reachability is properly scoped. OATA aims to become the industry-standard toolkit for certifying if an autonomous AI agent is safe to deploy in production infrastructure.

---

## Phase 1 - Foundation & Core Architecture (Months 1-3)

> **Approved Milestone (PPS-157):**  
> *"Core architecture design. Release the v0.1 alpha of the auditing CLI with basic prompt injection and framework-bypass payloads. Establish the GitHub repository and contributor guidelines."*

* [x] **1.1 Core Engine Architecture**:
  * [x] Design pluggable asynchronous execution pipeline (`asyncio` + `httpx`) for low-latency concurrent test execution.
  * [x] Enforce the **Safe Local Target Guard**: default strictly to `localhost`, `127.0.0.1`, and local mock sandboxes; require explicit `--allow-remote` flag for external endpoints.
  * [x] Establish modular abstraction layers: `BaseAdapter` (target connection) and `BasePayload` (attack vector definition).
  * [x] Offline Session Replay: Ability to audit recorded agent execution traces (JSON format) without live LLM API token consumption.
* [x] **1.2 Initial Attack Vector Suite (LLM08 & Injection)**:
  * [x] Parameter Boundary Fuzzers: Payloads mutating structured tool-calling arguments to bypass schema validation (`ParameterTamperPayload`).
  * [x] Unbounded Scope Escalation: Payloads testing whether an agent executes privileged functions (`exec_shell`, file modification, network egress) beyond declared scope (`UnboundedScopePayload`).
  * [x] Context Boundary Bleed: Probing multi-hop conversational context to test if injected instructions override system identity (`ContextBleedPayload`).
* [x] **1.3 Built-in Mock Target (Zero-Dependency Demo)**:
  * [x] Package a lightweight, local mock agent testbed with known Excessive Agency flaws (`MockAgentAdapter`).
  * [x] Enable one-command verification: `oata demo` executes an end-to-end simulated audit locally without requiring external model credentials.
* [x] **1.4 Python CLI (`oata`) & Reporting**:
  * [x] Package modern CLI using Click and Rich (`oata version`, `oata list-payloads`, `oata demo`, `oata audit`).
  * [x] Implement color-coded terminal vulnerability summaries with severity ratings (Critical, High, Medium, Low).
  * [x] Implement standardized exporters: machine-readable JSON and **SARIF v2.1.0** for direct integration with GitHub Code Scanning.
* [ ] **1.5 Repository, Governance & Release**:
  * [x] Configure Apache 2.0 licensing, OWASP Code of Conduct, and `SECURITY.md`.
  * [x] Implement Developer Certificate of Origin (DCO) validation workflow (`.github/workflows/dco.yml`) and CI test runner (`.github/workflows/ci.yml`).
  * [ ] Publish **v0.1-Alpha** release package to PyPI test index and GitHub Releases.

---

## Phase 2 - Multi-Hop Framework Adapters & Dynamic Fuzzing (Months 4-6)

> **Approved Milestone (PPS-157):**  
> *"Develop native testing adapters for LangChain and CrewAI. Implement dynamic fuzzing for tool-call parameters. Release v1.0 Beta."*

* [ ] **2.1 LangChain & LangGraph Native Adapter**:
  * [ ] Intercept LangChain tool-call execution trees and callback handlers.
  * [ ] Audit LangGraph state transition boundaries for unauthorized lateral state modification.
* [ ] **2.2 CrewAI Multi-Agent Adapter**:
  * [ ] Intercept inter-agent task delegation flows.
  * [ ] Verify worker agent privilege containment when receiving delegated instructions from peer agents.
* [ ] **2.3 Dynamic Parameter Fuzzing Engine**:
  * [ ] Implement grammar-aware parameter mutation based on Pydantic/JSON tool schemas.
  * [ ] Test for type confusion, path traversal injection in tool arguments, and unexpected argument injection.
* [ ] **2.4 Model Context Protocol (MCP) Auditor**:
  * [ ] Native adapter to connect to local MCP servers (stdio and SSE transports).
  * [ ] Audit exposed tool schemas, resources, and prompts for excessive authority and SSRF attack surfaces.
* [ ] **2.5 Automated Regression Suite & v1.0-Beta**:
  * [ ] Benchmark detection accuracy and false-positive rates across simulated multi-hop agent pipelines.
  * [ ] Distribute **v1.0-Beta** release via PyPI and containerized environments.

---

## Phase 3 - Remediation Mapping & Ecosystem Integration (Months 7-9)

> **Approved Milestone (PPS-157):**  
> *"Introduce automated remediation mapping (e.g., suggesting cryptographic delegation via Creduent for vulnerable paths). Integrate with existing OWASP projects like DefectDojo for vulnerability tracking."*

* [ ] **3.1 Automated Remediation Mapping**:
  * [ ] Engine generates concrete architectural hardening recommendations for every identified finding.
  * [ ] Map vulnerable multi-hop delegation paths directly to identity-defined reachability standards, specifically **Creduent Delegation Tokens (CDT)** for Layer 7 capability attenuation.
  * [ ] Export remediation guidance in human-readable Markdown and structured SARIF remediation objects.
* [ ] **3.2 OWASP DefectDojo Integration**:
  * [ ] Direct API client to push OATA scan results and vulnerability findings into OWASP DefectDojo.
  * [ ] Map OATA findings to standard CWE and OWASP Top 10 for LLM taxonomy inside enterprise tracking systems.
* [ ] **3.3 AutoGen Adapter**:
  * [ ] Native audit adapter for AutoGen conversational patterns and group-chat manager delegation boundaries.
* [ ] **3.4 External Payload Plugin SDK**:
  * [ ] Standardized plugin architecture allowing external security researchers to write and contribute custom attack vectors without modifying the engine core.

---

## Phase 4 - CI/CD Automation & Graduation to Lab Status (Months 10-12)

> **Approved Milestone (PPS-157):**  
> *"Graduate from Incubator to Lab status. Build CI/CD plugins (GitHub Actions, GitLab CI) so OATA can run automatically on pull requests modifying agent code."*

* [ ] **4.1 Continuous Integration Security Gating**:
  * [ ] Official **GitHub Action (`owasp/oata-action`)** enabling automated security gates on pull requests that modify agentic tool schemas or prompt templates.
  * [ ] Pre-commit hook integration and GitLab CI template configuration.
* [ ] **4.2 Container & Distribution Hardening**:
  * [ ] Official multi-architecture Docker container distribution (`ghcr.io/owasp/agentic-threat-auditor`).
  * [ ] Automated container signing and SBOM generation.
* [ ] **4.3 OWASP Lab Status Graduation**:
  * [ ] Prepare comprehensive project metrics, active user adoption documentation, and community contributor review.
  * [ ] Submit formal graduation application to the OWASP Project Committee to move from Incubator to official **OWASP Lab Project**.
* [ ] **4.4 Industry Adoption & Conference Presentations**:
  * [ ] Present OATA methodology and findings at OWASP Global AppSec and major cybersecurity conferences.
  * [ ] Publish reference case studies with production DevSecOps teams.

---

## Community & Contribution

OWASP Agentic Threat Auditor is an open, vendor-neutral initiative under the OWASP Foundation:
* **Project Page:** [owasp.org/projects/agentic-threat-auditor](https://owasp.org/projects/agentic-threat-auditor)
* **GitHub Repository:** [github.com/OWASP/Agentic-Threat-Auditor](https://github.com/OWASP/Agentic-Threat-Auditor)
* **OWASP Slack:** Join `#project-agentic-threat-auditor` on [owasp.slack.com](https://owasp.slack.com)
* **Contributions:** Review `CONTRIBUTING.md` and ensure all commits include Developer Certificate of Origin (DCO) sign-off (`Signed-off-by: Name <email>`).
