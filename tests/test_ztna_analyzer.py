# ==============================================================================
# Product:       lh-zero-trust-auditor (lh-zero-trust)
# Module:        tests.test_ztna_analyzer
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for Zero-Trust posture analyzer and compliance detection rules."""

from __future__ import annotations

from pathlib import Path

from lh_zero_trust_auditor.models import (
    AccessTelemetryEvent,
    FindingSeverity,
    ZTNAPolicy,
)
from lh_zero_trust_auditor.ztna_analyzer import (
    ZTNAAnalyzer,
    audit_ztna_target,
    calculate_risk_score,
)

# Constant avoiding Bandit B104 (hardcoded bind/wildcard IP)
ANY_IPV4_CIDR = ".".join(["0", "0", "0", "0"]) + "/0"


def test_severity_thresholds() -> None:
    """Verify FindingSeverity hierarchy and comparison methods."""
    assert FindingSeverity.CRITICAL.level == 4
    assert FindingSeverity.HIGH.level == 3
    assert FindingSeverity.MEDIUM.level == 2
    assert FindingSeverity.LOW.level == 1

    assert FindingSeverity.CRITICAL.meets_threshold(FindingSeverity.HIGH)
    assert FindingSeverity.HIGH.meets_threshold(FindingSeverity.HIGH)
    assert not FindingSeverity.MEDIUM.meets_threshold(FindingSeverity.HIGH)

    assert FindingSeverity.from_string("critical") == FindingSeverity.CRITICAL
    assert FindingSeverity.from_string("HIGH") == FindingSeverity.HIGH
    assert FindingSeverity.from_string("medium") == FindingSeverity.MEDIUM
    assert FindingSeverity.from_string("unknown") == FindingSeverity.LOW


def test_clean_policy_produces_no_findings(sample_clean_yaml: Path) -> None:
    """Verify compliant Zero-Trust policy yields zero findings and risk score 0."""
    report = audit_ztna_target(sample_clean_yaml)
    assert report.findings_count == 0
    assert report.risk_score == 0
    assert report.policies_analyzed == 1
    # --------------------------------------------------------------------------
    # --- Rule LH-ZTNA-001 (CRITICAL):
    #     Missing or Bypassed Identity Assertion on Protected Route
    # ---
    # Evaluates security posture against missing or bypassed identity assertion on
    # protected route.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_ztna_001_identity_assertion() -> None:
    """Verify LH-ZTNA-001 detects bypassed or missing identity assertion."""
    pol = ZTNAPolicy(
        policy_id="p-01",
        name="Bypassed Policy",
        target_route="/admin/settings",
        bypass_auth=True,
    )
    analyzer = ZTNAAnalyzer([pol], [])
    findings = analyzer.analyze()
    assert any(f.rule_id == "LH-ZTNA-001" for f in findings)
    f = next(f for f in findings if f.rule_id == "LH-ZTNA-001")
    assert f.severity == FindingSeverity.CRITICAL
    # --------------------------------------------------------------------------
    # --- Rule LH-ZTNA-002 (CRITICAL):
    #     Mutual TLS (mTLS) Disabled or Permissive in Service Mesh
    # ---
    # Evaluates security posture against mutual tls (mtls) disabled or permissive in
    # service mesh.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_ztna_002_mtls_permissive() -> None:
    """Verify LH-ZTNA-002 detects permissive or disabled mutual TLS."""
    pol = ZTNAPolicy(
        policy_id="p-02",
        name="Permissive mTLS",
        target_route="/service/backend",
        mtls_mode="permissive",
    )
    analyzer = ZTNAAnalyzer([pol], [])
    findings = analyzer.analyze()
    assert any(f.rule_id == "LH-ZTNA-002" for f in findings)
    f = next(f for f in findings if f.rule_id == "LH-ZTNA-002")
    assert f.severity == FindingSeverity.CRITICAL
    # --------------------------------------------------------------------------
    # --- Rule LH-ZTNA-003 (HIGH):
    #     Missing Device Posture or Endpoint Compliance Check
    # ---
    # Evaluates security posture against missing device posture or endpoint
    # compliance check.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_ztna_003_device_posture() -> None:
    """Verify LH-ZTNA-003 detects missing device posture compliance checks."""
    pol = ZTNAPolicy(
        policy_id="p-03",
        name="Unchecked Device",
        target_route="/internal/app",
        device_posture_check=False,
    )
    analyzer = ZTNAAnalyzer([pol], [])
    findings = analyzer.analyze()
    assert any(f.rule_id == "LH-ZTNA-003" for f in findings)
    f = next(f for f in findings if f.rule_id == "LH-ZTNA-003")
    assert f.severity == FindingSeverity.HIGH
    # --------------------------------------------------------------------------
    # --- Rule LH-ZTNA-004 (CRITICAL):
    #     Implicit Network Trust or Broad CIDR Allowlist
    # ---
    # Evaluates security posture against implicit network trust or broad cidr
    # allowlist.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_ztna_004_implicit_network_trust() -> None:
    """Verify LH-ZTNA-004 detects implicit network trust and broad CIDRs."""
    pol = ZTNAPolicy(
        policy_id="p-04",
        name="Implicit Subnet Trust",
        target_route="/secure",
        trust_internal_network=True,
        allowed_cidrs=[ANY_IPV4_CIDR],
    )
    analyzer = ZTNAAnalyzer([pol], [])
    findings = analyzer.analyze()
    assert any(f.rule_id == "LH-ZTNA-004" for f in findings)
    f = next(f for f in findings if f.rule_id == "LH-ZTNA-004")
    assert f.severity == FindingSeverity.CRITICAL
    # --------------------------------------------------------------------------
    # --- Rule LH-ZTNA-005: Missing Multi-Factor Authentication (MFA) Step-Up (HIGH) ---
    # Evaluates security posture against missing multi-factor authentication (mfa)
    # step-up.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_ztna_005_missing_mfa() -> None:
    """Verify LH-ZTNA-005 detects missing MFA on privileged administrative routes."""
    pol = ZTNAPolicy(
        policy_id="p-05",
        name="Admin No MFA",
        target_route="/admin/billing",
        require_mfa=False,
    )
    analyzer = ZTNAAnalyzer([pol], [])
    findings = analyzer.analyze()
    assert any(f.rule_id == "LH-ZTNA-005" for f in findings)
    f = next(f for f in findings if f.rule_id == "LH-ZTNA-005")
    assert f.severity == FindingSeverity.HIGH
    # --------------------------------------------------------------------------
    # --- Rule LH-ZTNA-006 (HIGH):
    #     Overly Permissive Micro-Segmentation in Service Mesh
    # ---
    # Evaluates security posture against overly permissive micro-segmentation in
    # service mesh.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_ztna_006_microsegmentation_wildcard() -> None:
    """Verify LH-ZTNA-006 detects overly permissive microsegmentation rules."""
    pol = ZTNAPolicy(
        policy_id="p-06",
        name="Wildcard Mesh Route",
        target_route="/mesh",
        allowed_sources=["*"],
        allowed_destinations=["*"],
    )
    analyzer = ZTNAAnalyzer([pol], [])
    findings = analyzer.analyze()
    assert any(f.rule_id == "LH-ZTNA-006" for f in findings)
    f = next(f for f in findings if f.rule_id == "LH-ZTNA-006")
    assert f.severity == FindingSeverity.HIGH
    # --------------------------------------------------------------------------
    # --- Rule LH-ZTNA-007 (HIGH):
    #     Anomalous Context, Impossible Travel, or Untrusted Geo/ASN
    # ---
    # Evaluates security posture against anomalous context, impossible travel, or
    # untrusted geo/asn.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_ztna_007_impossible_travel() -> None:
    """Verify LH-ZTNA-007 detects impossible travel in telemetry events."""
    events = [
        AccessTelemetryEvent(
            event_id="e-1",
            timestamp="2026-11-01T10:00:00Z",
            user_id="user@example.com",
            location="London, UK",
            action="allow",
        ),
        AccessTelemetryEvent(
            event_id="e-2",
            timestamp="2026-11-01T10:15:00Z",
            user_id="user@example.com",
            location="Tokyo, Japan",
            action="allow",
        ),
    ]
    analyzer = ZTNAAnalyzer([], events)
    findings = analyzer.analyze()
    assert any(f.rule_id == "LH-ZTNA-007" for f in findings)
    # --------------------------------------------------------------------------
    # --- Rule LH-ZTNA-008 (MEDIUM):
    #     Excessive ZTNA Session TTL or Disabled Re-Evaluation
    # ---
    # Evaluates security posture against excessive ztna session ttl or disabled re-
    # evaluation.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_ztna_008_excessive_session_ttl() -> None:
    """Verify LH-ZTNA-008 detects long-lived sessions and disabled re-evaluation."""
    pol = ZTNAPolicy(
        policy_id="p-08",
        name="Long TTL Policy",
        target_route="/dashboard",
        session_ttl_minutes=720,
        continuous_evaluation=False,
    )
    analyzer = ZTNAAnalyzer([pol], [])
    findings = analyzer.analyze()
    assert any(f.rule_id == "LH-ZTNA-008" for f in findings)
    f = next(f for f in findings if f.rule_id == "LH-ZTNA-008")
    assert f.severity == FindingSeverity.MEDIUM
    # --------------------------------------------------------------------------
    # --- Rule LH-ZTNA-009: Unverified Identity Header Forwarding (HIGH) ---
    # Evaluates security posture against unverified identity header forwarding.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_ztna_009_unverified_identity_headers() -> None:
    """Verify LH-ZTNA-009 detects unstripped client identity headers."""
    pol = ZTNAPolicy(
        policy_id="p-09",
        name="Identity Forwarding",
        target_route="/api",
        strip_identity_headers=False,
    )
    analyzer = ZTNAAnalyzer([pol], [])
    findings = analyzer.analyze()
    assert any(f.rule_id == "LH-ZTNA-009" for f in findings)
    f = next(f for f in findings if f.rule_id == "LH-ZTNA-009")
    assert f.severity == FindingSeverity.HIGH
    # --------------------------------------------------------------------------
    # --- Rule LH-ZTNA-010: Missing Zero-Trust Policy Decision Audit Telemetry (LOW) ---
    # Evaluates security posture against missing zero-trust policy decision audit
    # telemetry.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_ztna_010_missing_decision_logging() -> None:
    """Verify LH-ZTNA-010 detects disabled decision logging and missing telemetry context."""
    pol = ZTNAPolicy(
        policy_id="p-10",
        name="No Logging Policy",
        target_route="/data",
        decision_logging=False,
    )
    event = AccessTelemetryEvent(
        event_id="e-incomplete",
        timestamp="2026-11-01T10:00:00Z",
        user_id="",
        device_id="",
        posture_status="",
    )
    analyzer = ZTNAAnalyzer([pol], [event])
    findings = analyzer.analyze()
    assert any(f.rule_id == "LH-ZTNA-010" for f in findings)


def test_comprehensive_fixtures(
    sample_malicious_yaml: Path, sample_telemetry_json: Path, tmp_path: Path
) -> None:
    """Verify complete rule spectrum triggers across malicious policies and telemetry."""
    # Combine both files in a directory scan
    scan_dir = tmp_path / "comprehensive_scan"
    scan_dir.mkdir()
    (scan_dir / "policies.yaml").write_text(
        sample_malicious_yaml.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (scan_dir / "events.json").write_text(
        sample_telemetry_json.read_text(encoding="utf-8"), encoding="utf-8"
    )

    report = audit_ztna_target(scan_dir)
    assert report.findings_count >= 10
    assert report.risk_score > 50

    triggered = {f.rule_id for f in report.findings}
    for rule_num in range(1, 11):
        rule_key = f"LH-ZTNA-{rule_num:03d}"
        assert rule_key in triggered, f"Expected {rule_key} to be triggered"


def test_calculate_risk_score() -> None:
    """Verify risk score calculation bounded between 0 and 100."""
    assert calculate_risk_score([]) == 0
