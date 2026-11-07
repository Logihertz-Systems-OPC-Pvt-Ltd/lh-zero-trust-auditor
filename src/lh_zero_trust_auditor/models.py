# ==============================================================================
# Product:       lh-zero-trust-auditor (lh-zero-trust)
# Module:        src.lh_zero_trust_auditor.models
# Role:          Data Models & Rule Definitions
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Data models and rule definitions for lh-zero-trust-auditor."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class FindingSeverity(StrEnum):
    # --- Severity Rank & Weighting Structure ---
    # Defines discrete security tiers for findings and threshold gating.
    # Higher ordinal rankings enforce stricter build break / fail-on gates.
    """Severity ratings for Zero-Trust posture audit findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def level(self) -> int:
        """Numeric rank for threshold comparison."""
        ranks = {
            FindingSeverity.CRITICAL: 4,
            FindingSeverity.HIGH: 3,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 1,
        }
        return ranks.get(self, 0)

    @classmethod
    def from_string(cls, val: str) -> FindingSeverity:
        """Convert string to FindingSeverity case-insensitively."""
        normalized = val.strip().upper()
        for member in cls:
            if member.value == normalized:
                return member
        return cls.LOW

    def meets_threshold(self, threshold: FindingSeverity) -> bool:
        """Return True if this severity meets or exceeds threshold."""
        return self.level >= threshold.level


@dataclass
class ZTNAPolicy:
    """Extracted Zero-Trust gateway or reverse proxy policy specification."""

    policy_id: str = ""
    name: str = ""
    target_route: str = ""
    auth_required: bool | None = None
    bypass_auth: bool | None = None
    identity_provider: str = ""
    mtls_mode: str = ""
    ssl_verify_client: str = ""
    client_ca_file: str = ""
    require_managed_device: bool | None = None
    device_posture_check: bool | None = None
    disk_encryption_required: bool | None = None
    edr_active_required: bool | None = None
    trust_internal_network: bool | None = None
    allowed_cidrs: list[str] = field(default_factory=list)
    require_mfa: bool | None = None
    step_up_mfa: bool | None = None
    allowed_sources: list[str] = field(default_factory=list)
    allowed_destinations: list[str] = field(default_factory=list)
    allowed_services: list[str] = field(default_factory=list)
    session_ttl_minutes: int | None = None
    continuous_evaluation: bool | None = None
    strip_identity_headers: bool | None = None
    decision_logging: bool | None = None
    geo_restriction_enabled: bool | None = None
    block_untrusted_locations: bool | None = None
    source_file: str = ""
    line_number: int = 0


@dataclass
class AccessTelemetryEvent:
    """Captured access telemetry record or policy decision event."""

    event_id: str = ""
    timestamp: str = ""
    user_id: str = ""
    device_id: str = ""
    client_ip: str = ""
    location: str = ""
    resource: str = ""
    action: str = ""
    posture_status: str = ""
    source_file: str = ""
    line_number: int = 0


@dataclass
class AuditFinding:
    """Security finding or zero-trust posture violation."""

    rule_id: str
    severity: FindingSeverity
    category: str
    target_resource: str
    title: str
    description: str
    remediation: str
    evidence: str = ""


@dataclass
class AuditReport:
    """Consolidated Zero-Trust posture audit report."""

    target: str
    files_scanned: int = 0
    policies_analyzed: int = 0
    telemetry_events_analyzed: int = 0
    findings_count: int = 0
    findings: list[AuditFinding] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    risk_score: int = 0


@dataclass(frozen=True)
class AuditRuleDefinition:
    """Static metadata for Zero-Trust audit rules."""

    rule_id: str
    title: str
    severity: FindingSeverity
    category: str
    description: str
    remediation: str


RULES_REGISTRY: dict[str, AuditRuleDefinition] = {
    "LH-ZTNA-001": AuditRuleDefinition(
        rule_id="LH-ZTNA-001",
        title="Missing or Bypassed Identity Assertion on Protected Route",
        severity=FindingSeverity.CRITICAL,
        category="Identity",
        description=(
            "Internal, admin, or API routes are accessible without mandatory identity provider "
            "(OIDC/SAML/JWT) authentication."
        ),
        remediation=(
            "Enforce mandatory identity verification for all protected routes and remove "
            "unauthenticated bypass rules."
        ),
    ),
    "LH-ZTNA-002": AuditRuleDefinition(
        rule_id="LH-ZTNA-002",
        title="Mutual TLS (mTLS) Disabled or Permissive",
        severity=FindingSeverity.CRITICAL,
        category="Cryptography",
        description=(
            "Service-to-service or edge proxy channels operate with mTLS disabled, permissive, "
            "or without client certificate verification."
        ),
        remediation=(
            "Configure strict mTLS mode (ssl_verify_client on) with trusted internal certificate "
            "authority (CA) validation."
        ),
    ),
    "LH-ZTNA-003": AuditRuleDefinition(
        rule_id="LH-ZTNA-003",
        title="Missing Device Posture or Endpoint Compliance Check",
        severity=FindingSeverity.HIGH,
        category="Device Posture",
        description=(
            "Access policies allow unmanaged or non-compliant devices without verifying disk "
            "encryption, EDR status, or MDM enrollment."
        ),
        remediation=(
            "Enforce continuous device posture evaluation requiring active EDR, disk encryption, "
            "and managed enterprise device status."
        ),
    ),
    "LH-ZTNA-004": AuditRuleDefinition(
        rule_id="LH-ZTNA-004",
        title="Implicit Network Trust or Broad CIDR Allowlist Violation",
        severity=FindingSeverity.CRITICAL,
        category="Segmentation",
        description=(
            "Policy grants implicit network trust based on IP subnet ranges (0.0.0.0/0, "
            "10.0.0.0/8) bypassing per-request identity verification."
        ),
        remediation=(
            "Eliminate implicit IP-based trust; require per-request identity and context "
            "evaluation regardless of network origin."
        ),
    ),
    "LH-ZTNA-005": AuditRuleDefinition(
        rule_id="LH-ZTNA-005",
        title="Missing Multi-Factor Authentication (MFA) Step-Up",
        severity=FindingSeverity.HIGH,
        category="Authentication",
        description=(
            "Privileged or sensitive resource policies lack mandatory multi-factor authentication "
            "or FIDO2/hardware token step-up."
        ),
        remediation=(
            "Require phishing-resistant MFA (FIDO2/WebAuthn) step-up authentication for access to "
            "privileged administrative endpoints."
        ),
    ),
    "LH-ZTNA-006": AuditRuleDefinition(
        rule_id="LH-ZTNA-006",
        title="Overly Permissive Micro-Segmentation or Lateral Movement Path",
        severity=FindingSeverity.HIGH,
        category="Micro-Segmentation",
        description=(
            "Service mesh or routing policies include wildcard east-west communication rules (*), "
            "enabling unconstrained lateral movement."
        ),
        remediation=(
            "Enforce strict least-privilege micro-segmentation by defining explicit source, "
            "destination, and service access lists."
        ),
    ),
    "LH-ZTNA-007": AuditRuleDefinition(
        rule_id="LH-ZTNA-007",
        title="Anomalous Context, Impossible Travel, or Untrusted Geo/ASN Access",
        severity=FindingSeverity.HIGH,
        category="Context Analysis",
        description=(
            "Access events or policy rules allow impossible travel velocities, anonymized proxies, "
            "or lack geographic/ASN restrictions."
        ),
        remediation=(
            "Block access from anonymized proxies/Tor exit nodes and enforce velocity and "
            "geographic context checks."
        ),
    ),
    "LH-ZTNA-008": AuditRuleDefinition(
        rule_id="LH-ZTNA-008",
        title="Excessive ZTNA Session TTL or Disabled Continuous Re-Evaluation",
        severity=FindingSeverity.MEDIUM,
        category="Session Lifecycle",
        description=(
            "ZTNA sessions exceed recommended duration limits (> 480 minutes) or disable "
            "continuous posture and token re-evaluation."
        ),
        remediation=(
            "Shorten session TTL to 480 minutes or less and enable real-time continuous posture "
            "re-evaluation."
        ),
    ),
    "LH-ZTNA-009": AuditRuleDefinition(
        rule_id="LH-ZTNA-009",
        title="Unverified Identity Header Forwarding (Header Spoofing Vector)",
        severity=FindingSeverity.HIGH,
        category="Header Integrity",
        description=(
            "Reverse proxy forwards client-supplied identity headers (X-Forwarded-User) without "
            "stripping untrusted inputs or signature checks."
        ),
        remediation=(
            "Sanitize incoming headers at the ingress proxy and use cryptographically signed "
            "tokens (JWTs) for downstream identity assertion."
        ),
    ),
    "LH-ZTNA-010": AuditRuleDefinition(
        rule_id="LH-ZTNA-010",
        title="Missing Zero-Trust Policy Decision Audit Telemetry",
        severity=FindingSeverity.LOW,
        category="Telemetry Quality",
        description=(
            "Gateways or policies disable decision logging, or telemetry records lack essential "
            "device_id, user_id, or posture attributes."
        ),
        remediation=(
            "Enable comprehensive policy decision logging with enriched device, user, and posture "
            "context for all access events."
        ),
    ),
}
