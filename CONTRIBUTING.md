# Contributing to OWASP Agentic Threat Auditor (OATA)

Thank you for your interest in contributing to the **OWASP Agentic Threat Auditor (OATA)**. As an official OWASP open-source project, OATA relies on community contributions from security researchers, penetration testers, red teamers, and software engineers.

---

## 1. Developer Certificate of Origin (DCO) Mandate

All commits contributed to this repository must include a **Developer Certificate of Origin (DCO)** sign-off line. This certifies that you have the right to submit the code under the project's [Apache License 2.0](LICENSE).

### How to Sign Commits

Add the `-s` or `--signoff` flag when committing:

```bash
git commit -s -m "feat(payloads): add indirect injection vector for tool parameter fuzzing"
```

This automatically appends the required sign-off trailer:

```text
Signed-off-by: Your Real Name <your.email@example.com>
```

> Commits submitted without a valid DCO signature will be blocked automatically by our GitHub Actions verification workflow.

---

## 2. Safe Local Testing Policy (Target Guard)

OATA is an offensive security auditing engine. It generates dynamic payloads designed to probe runtime execution boundaries and induce unauthorized tool calls.

To prevent accidental scanning or disruption of third-party systems:

1. **Localhost Default**: All test suites, mock agents, and fuzzing payloads must default strictly to `localhost`, `127.0.0.1`, or isolated local container sandboxes.
2. **Explicit Flag Requirement**: Any CLI invocation or adapter capable of reaching external network endpoints must require an explicit flag (`--allow-remote`) and user confirmation.
3. **No Unsanitized Remote Execution**: Automated unit tests and integration tests submitted in pull requests must execute locally and require zero live third-party cloud services or API keys.

---

## 3. Technical Contribution & Anti-Slop Standards

We maintain a high technical bar. Documentation, code comments, and payload descriptions must be written for professional security practitioners:

- **Plain, Direct Language**: Use active voice and plain engineering terminology. Avoid synthetic filler, overused transition words (*moreover*, *furthermore*), and corporate jargon.
- **Zero Marketing Buzzwords**: Do not use marketing adjectives (*cutting-edge*, *robust*, *groundbreaking*, *seamless*, *revolutionize*, *leverage*, *delve*). Focus on technical mechanics, attack vectors, and observable system behavior.
- **No Em-Dashes**: Use standard punctuation (colons, hyphens, periods).
- **Evidence-Based References**: When introducing a new attack vector or payload, reference the corresponding CWE, OWASP LLM category, or public CVE.

---

## 4. Contributing New Attack Payloads

OATA classifies attack vectors under five core categories (AT-01 through AT-05). When proposing a new test payload, include the following metadata:

1. **Vector Category**: AT-01 (Excessive Agency), AT-02 (Multi-Hop Escalation), AT-03 (Parameter Injection), AT-04 (Context Bleed), or AT-05 (MCP Server Hijacking).
2. **Payload Structure**: Plaintext prompt injection, mutated JSON parameter, or MCP method invocation.
3. **Target Frameworks**: Specify supported frameworks (LangChain, CrewAI, AutoGen, or MCP).
4. **Expected Signal**: The exact heuristic or response indicating whether the target agent is vulnerable or isolated.

---

## 5. Development Workflow

1. **Fork and Clone**:
   ```bash
   git clone https://github.com/<your-username>/Agentic-Threat-Auditor.git
   cd Agentic-Threat-Auditor
   ```

2. **Create a Feature Branch**:
   ```bash
   git checkout -b feat/add-crewai-adapter
   ```

3. **Install Dependencies & Pre-commit Tools**:
   ```bash
   pip install -e ".[dev]"
   ```

4. **Run Tests Locally**:
   ```bash
   pytest tests/
   ```

5. **Commit with DCO Sign-off**:
   ```bash
   git commit -s -m "feat(adapters): implement crewai task delegation auditor"
   ```

6. **Submit a Pull Request**:
   - Open a pull request against the `main` branch.
   - Fill out the provided pull request template completely.
   - Verify that all CI checks (DCO verification, linting, unit tests) pass.

---

## 6. Community & Communication

- **OWASP Project Page**: [https://owasp.org/projects/agentic-threat-auditor](https://owasp.org/projects/agentic-threat-auditor)
- **OWASP Slack**: Join `#project-agentic-threat-auditor` on [owasp.slack.com](https://owasp.slack.com)
- **Project Leader**: Kashish Kanojia (`kashish.kanojia@owasp.org`)
