# Changelog

All notable changes to the OWASP Agentic Threat Auditor (OATA) project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0a1] - 2026-11-04

### Added
- **Core CLI (`oata`)**: Command-line interface built on Click and Rich providing `version`, `list-payloads`, `demo`, and `audit` commands.
- **Safe Local Target Guard**: Localhost and loopback address containment filter in `oata/core/guard.py`. Audits reject remote targets unless the explicit `--allow-remote` flag is passed.
- **Async Execution Engine**: Asynchronous execution coordinator in `oata/core/engine.py` managing adapter dispatch and finding consolidation.
- **Phase 1 Attack Vector Suite**:
  - `ParameterTamperPayload` (`OATA-VEC-01A`): Probes tool parameter schemas for path traversal and unvalidated argument mutations.
  - `UnboundedScopePayload` (`OATA-VEC-02A`): Probes agents for privileged command execution escapes (`exec_shell`).
  - `ContextBleedPayload` (`OATA-VEC-03A`): Probes multi-turn context boundaries for prompt injection overrides and unauthorized credential extraction queries.
- **Mock Target Adapter (`oata/adapters/mock.py`)**: Zero-dependency local agent simulator containing intentional OWASP LLM08 excessive agency flaws for instant verification (`oata demo`).
- **Offline Session Replay Adapter (`oata/adapters/trace.py`)**: Replay driver that audits recorded JSON interaction traces without live model token consumption.
- **Multi-Format Reporting**:
  - Rich terminal console reporter with color-coded severity tables (`oata/reporters/console.py`).
  - Machine-readable JSON exporter (`oata/reporters/json_reporter.py`).
  - Native SARIF v2.1.0 exporter (`oata/reporters/sarif.py`) for GitHub Code Scanning integration.
- **Continuous Integration & Governance**:
  - GitHub Actions test matrix across Python 3.10, 3.11, 3.12, and 3.13 (`.github/workflows/ci.yml`).
  - Developer Certificate of Origin (DCO) commit sign-off validator (`.github/workflows/dco.yml`).
  - Unit test suite in `tests/` with 11 passing tests.
  - Project governance documents: `README.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `LICENSE`, `ROADMAP.md`, and `proposal.md`.
  - GitHub Community Issue Templates (`bug_report.yml`, `new_vector.yml`) and Pull Request Template with DCO checklist.
  - CI workflow status badge in `README.md`.
- **Examples & Trace Fixtures**:
  - Sample agent interaction trace (`examples/sample_trace.json`) for offline trace replay testing.
  - Enhanced `guard.py` path resolution to support local file paths and Windows drive roots.

