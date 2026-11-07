# Security Rules Reference: lh-zero-trust-auditor

An enterprise zero-trust network access & mtls posture auditor developed by **Logihertz Systems (OPC) Private Limited**.

This reference manual documents the complete 10-rule security detection registry enforced by `lh-zero-trust-auditor`.

---

## Detection Catalog Overview

| Rule ID | Severity | Category | Title |
|:---|:---:|:---|:---|
| `LH-ZTNA-001` | `CRITICAL` | Identity Governance | Missing or Bypassed Identity Assertion on Protected Route |
| `LH-ZTNA-002` | `CRITICAL` | Transport Security | Mutual TLS (mTLS) Disabled or Permissive in Service Mesh |
| `LH-ZTNA-003` | `HIGH` | Device Posture | Missing Device Posture or Endpoint Compliance Check |
| `LH-ZTNA-004` | `CRITICAL` | Network Segmentation | Implicit Network Trust or Broad CIDR Allowlist |
| `LH-ZTNA-005` | `HIGH` | Authentication | Missing Multi-Factor Authentication (MFA) Step-Up |
| `LH-ZTNA-006` | `HIGH` | Micro-Segmentation | Overly Permissive Micro-Segmentation in Service Mesh |
| `LH-ZTNA-007` | `HIGH` | Contextual Access | Anomalous Context, Impossible Travel, or Untrusted Geo/ASN |
| `LH-ZTNA-008` | `MEDIUM` | Session Lifecycle | Excessive ZTNA Session TTL or Disabled Re-Evaluation |
| `LH-ZTNA-009` | `HIGH` | Header Spoofing | Unverified Identity Header Forwarding |
| `LH-ZTNA-010` | `LOW` | Audit Logging | Missing Zero-Trust Policy Decision Audit Telemetry |

---

## Granular Rule Specifications

### `LH-ZTNA-001`: Missing or Bypassed Identity Assertion on Protected Route

- **Severity**: `CRITICAL`
- **Category**: `Identity Governance`
- **Description**: Protected route allows anonymous access or bypasses identity provider assertion.
- **Remediation**: Enforce mandatory OIDC/OAuth2 identity token verification on all protected endpoints.

---

### `LH-ZTNA-002`: Mutual TLS (mTLS) Disabled or Permissive in Service Mesh

- **Severity**: `CRITICAL`
- **Category**: `Transport Security`
- **Description**: Service mesh link running with mTLS mode: PERMISSIVE or disabled.
- **Remediation**: Enforce strict mutual TLS (mode: STRICT) across all service-to-service communication paths.

---

### `LH-ZTNA-003`: Missing Device Posture or Endpoint Compliance Check

- **Severity**: `HIGH`
- **Category**: `Device Posture`
- **Description**: ZTNA access policy grants access without validating device health, disk encryption, or EDR.
- **Remediation**: Configure continuous device posture checks verifying compliant OS, disk encryption, and active EDR.

---

### `LH-ZTNA-004`: Implicit Network Trust or Broad CIDR Allowlist

- **Severity**: `CRITICAL`
- **Category**: `Network Segmentation`
- **Description**: Policy grants automatic authorization based on network location or broad CIDR ranges.
- **Remediation**: Eliminate network-based trust; require authenticated identity for every request regardless of origin.

---

### `LH-ZTNA-005`: Missing Multi-Factor Authentication (MFA) Step-Up

- **Severity**: `HIGH`
- **Category**: `Authentication`
- **Description**: Access to high-risk administrative route permitted with single-factor credentials.
- **Remediation**: Enforce step-up FIDO2/WebAuthn MFA verification for high-risk and administrative operations.

---

### `LH-ZTNA-006`: Overly Permissive Micro-Segmentation in Service Mesh

- **Severity**: `HIGH`
- **Category**: `Micro-Segmentation`
- **Description**: Service mesh AuthorizationPolicy permits wildcard service-to-service communication.
- **Remediation**: Restrict service-to-service communication strictly to required consumer service accounts.

---

### `LH-ZTNA-007`: Anomalous Context, Impossible Travel, or Untrusted Geo/ASN

- **Severity**: `HIGH`
- **Category**: `Contextual Access`
- **Description**: Access granted despite anomalous geographic origin or impossible travel velocity.
- **Remediation**: Implement adaptive risk-based access policies that challenge or block anomalous contextual requests.

---

### `LH-ZTNA-008`: Excessive ZTNA Session TTL or Disabled Re-Evaluation

- **Severity**: `MEDIUM`
- **Category**: `Session Lifecycle`
- **Description**: ZTNA session lifetime exceeds 8 hours without continuous posture re-evaluation.
- **Remediation**: Limit ZTNA session lifetimes to <= 4 hours and enforce continuous policy re-evaluation.

---

### `LH-ZTNA-009`: Unverified Identity Header Forwarding

- **Severity**: `HIGH`
- **Category**: `Header Spoofing`
- **Description**: Upstream proxy trusts incoming X-Remote-User headers without cryptographic signature.
- **Remediation**: Strip untrusted identity headers at perimeter and authenticate forwarded identity via signed JWT.

---

### `LH-ZTNA-010`: Missing Zero-Trust Policy Decision Audit Telemetry

- **Severity**: `LOW`
- **Category**: `Audit Logging`
- **Description**: ZTNA gateway does not log policy allow/deny decisions with user and device context.
- **Remediation**: Enable structured JSON logging recording user, device, action, and policy decision for every request.

---
