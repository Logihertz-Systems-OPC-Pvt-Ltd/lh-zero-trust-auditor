# lh-zero-trust-auditor

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-zero-trust-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-zero-trust-auditor/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise zero-trust network & service mesh auditor developed by **Logihertz Systems (OPC) Private Limited**.

Audits Istio/Envoy service mesh policies, Tailscale/WireGuard ACLs, BeyondCorp access proxies, and mTLS configurations for permissive PERMISSIVE mTLS modes, missing device posture checks, and lateral movement paths.

---

## Key Features

- **Multi-Mesh & Proxy Ingestion**: Parses Istio PeerAuthentication, Envoy mTLS filters, Cloudflare Access policies, and Google BeyondCorp manifests.
- **Mutual TLS (mTLS) Enforcement Auditing**: Detects service-to-service links running in `PERMISSIVE` or disabled mTLS mode.
- **Implicit Network Trust Elimination**: Flags blanket CIDR allowlists (`0.0.0.0/0`, internal subnets) that grant access without user/workload identity.
- **Device Posture & MFA Step-Up Verification**: Verifies that protected resources require continuous device compliance and MFA validation.
- **Micro-Segmentation Analysis**: Flags overly broad service-to-service communication paths violating least-privilege principles.
- **Multi-Format Reporting**: Outputs rich terminal tables, machine-readable JSON, and OASIS SARIF v2.1.0.

---

## Core Detection Rules

| Rule ID | Severity | Description |
|:---|:---:|:---|
| `LH-ZTNA-001` | `CRITICAL` | Missing or Bypassed Identity Assertion on Protected Route |
| `LH-ZTNA-002` | `CRITICAL` | Mutual TLS (mTLS) Disabled or Permissive in service-to-service communication |
| `LH-ZTNA-003` | `HIGH` | Missing Device Posture or Endpoint Compliance Check in ZTNA policy |
| `LH-ZTNA-004` | `CRITICAL` | Implicit Network Trust or Broad CIDR Allowlist granting unauthenticated access |
| `LH-ZTNA-005` | `HIGH` | Missing Multi-Factor Authentication (MFA) Step-Up on sensitive routes |
| `LH-ZTNA-006` | `HIGH` | Overly Permissive Micro-Segmentation or Lateral Movement Path allowed in mesh |
| `LH-ZTNA-007` | `HIGH` | Anomalous Context, Impossible Travel, or Untrusted Geo/ASN Access |
| `LH-ZTNA-008` | `MEDIUM` | Excessive ZTNA Session TTL or Disabled Continuous Re-Evaluation |
| `LH-ZTNA-009` | `HIGH` | Unverified Identity Header Forwarding (header spoofing vector) |
| `LH-ZTNA-010` | `LOW` | Missing Zero-Trust Policy Decision Audit Telemetry |

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-zero-trust-auditor.git
cd lh-zero-trust-auditor

# Create virtual environment and install in editable mode with development tools
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## CLI Usage

The primary executable entrypoint is `lh-ztna` (also accessible via `lh-ztna`, `lh-zero-trust-auditor`).

```bash
# Scan a ZTNA policy manifest or Istio mTLS configuration
lh-ztna scan ztna-policy.yaml

# Audit service mesh definitions with structured JSON output
lh-ztna scan ./mesh-configs/ --format json

# Export findings to OASIS SARIF v2.1.0
lh-ztna scan ./policies/ --format sarif --output ztna-results.sarif

# List all Zero-Trust detection rules
lh-ztna rules
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All audits and security checks passed; no policy violations detected. |
| `1` | One or more security findings, policy violations, or compliance failures detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed syntax). |

---

## Documentation

Comprehensive enterprise documentation is available in the [`docs/`](docs/) directory and repository root:

- **[Architecture & Design](docs/ARCHITECTURE.md)**: Zero-daemon clean-room architecture, module responsibilities, domain models, and 0–100 risk score calculation formula.
- **[Security Rules Reference](docs/RULES.md)**: Exhaustive catalog of all 10 detection rules with threat models, severities, and remediation guides.
- **[CLI Usage Guide](docs/USAGE.md)**: Complete command-line manual, flags, exit codes, CI/CD SARIF upload workflows, and JSON pipelines.
- **[Test & Verification Declaration](docs/TESTING.md)**: Audited test inventory, AST security verification, SAST audit results, and per-module code coverage metrics.
- **[Changelog](CHANGELOG.md)**: Semantic release history and detailed changelog entries.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, coding standards, line length, typing, and PR requirements.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure procedure, reporting email, and 48-hour response SLA.
- **[Legal Notice & Attributions](NOTICE)**: Apache-2.0 Section 4 legal notice, trademark reservations, and third-party software attributions.

## Development & Testing

Run all project linters, security audits, and test suites:

```bash
# Run code style and lint checks
uv run ruff check src/ tests/

# Run static application security testing (SAST)
uv run bandit -r src/

# Run unit and integration tests with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.

Developed with precision by **Logihertz Systems (OPC) Private Limited** (`logihertzsystems`).  
Created, architected, and engineered by **Sameer Tawade** (Creator, Founder, Director & Whole and Sole Developer — `ops@logihertz.com`).
