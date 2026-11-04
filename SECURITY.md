# Security Policy

The **OWASP Agentic Threat Auditor (OATA)** project takes the security of its code, toolchain, and community seriously. We appreciate responsible disclosure of any vulnerabilities found within this software.

---

## Supported Versions

Only the latest active development versions of OATA receive security updates and bug fixes:

| Version | Supported |
| :--- | :--- |
| `0.1.x` (Alpha) | :white_check_mark: Yes |
| `< 0.1.0` | :x: No |

---

## Reporting a Vulnerability

If you discover a security vulnerability within the OATA codebase, execution engine, or built-in testbed, **please do not open a public GitHub issue**.

### How to Report Privately

1. **Email the Project Leader**:
   Send an encrypted or direct email detailing the vulnerability to:
   - **Primary**: Kashish Kanojia (`kashish.kanojia@owasp.org`)
   - **CC**: OWASP Security Team (`security@owasp.org`)

2. **Include Key Details in Your Report**:
   - A descriptive summary of the vulnerability.
   - Exact steps or minimal proof-of-concept (PoC) to reproduce the issue.
   - Affected CLI commands, adapters, or payload modules.
   - Potential impact (e.g., unintended code execution on the auditor host, arbitrary remote scanning, privilege escalation).
   - Any suggested mitigations or patches.

---

## Response Timeline & Service Level Agreement (SLA)

As an official OWASP project leader, the team adheres strictly to the **OWASP Foundation 9-business-day response SLA**:

- **Initial Acknowledgment**: Within **48 hours** of receiving the report.
- **Triage & Assessment**: Within **9 business days**, detailing validity, severity classification, and planned remediation steps.
- **Fix & Public Advisory**: Coordinated disclosure after a patch has been merged and verified, typically within 30 to 60 days depending on complexity.

---

## Safe Harbor & Research Guidelines

We consider security research conducted under the following terms to be authorized:

- **Local Scope**: Research is performed against local instances, isolated testbeds, or explicitly authorized environments.
- **No Disruption**: You make a good-faith effort to avoid service disruption, privacy violations, or data destruction.
- **Responsible Coordination**: You give the project team reasonable time to remediate the vulnerability before public disclosure.

Thank you for helping keep the OWASP open-source ecosystem secure.
