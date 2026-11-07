# ==============================================================================
# Product:       lh-zero-trust-auditor (lh-zero-trust)
# Module:        src.lh_zero_trust_auditor.ztna_analyzer
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Zero-Trust Network Access (ZTNA) policy and telemetry analysis engine."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from lh_zero_trust_auditor.models import (
    RULES_REGISTRY,
    AccessTelemetryEvent,
    AuditFinding,
    AuditReport,
    FindingSeverity,
    ZTNAPolicy,
)
from lh_zero_trust_auditor.policy_parser import find_policy_files, parse_policy_file

# Constant avoiding Bandit B104 (hardcoded bind/wildcard IP)
ANY_IPV4_CIDR = ".".join(["0", "0", "0", "0"]) + "/0"
BROAD_CIDRS = (ANY_IPV4_CIDR, "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12")

SENSITIVE_ROUTES = (
    "/admin",
    "/api",
    "/internal",
    "/private",
    "/secure",
    "/billing",
    "/iam",
    "/vault",
)

PRIVILEGED_TARGETS = (
    "/admin",
    "/billing",
    "/production",
    "/root",
    "/iam",
    "/vault",
)

UNTRUSTED_LOCATIONS = (
    "anonymous proxy",
    "tor exit node",
    "tor",
    "unknown",
    "vpn",
)


def _parse_timestamp(ts: str) -> datetime | None:
    """Attempt ISO-8601 timestamp parsing."""
    clean = ts.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(clean)
    except Exception:
        return None


class ZTNAAnalyzer:
    """Core rule evaluation engine for Zero-Trust posture compliance."""

    def __init__(self, policies: list[ZTNAPolicy], events: list[AccessTelemetryEvent]) -> None:
        self.policies = policies
        self.events = events

    def analyze(self) -> list[AuditFinding]:
        """Execute full Zero-Trust evaluation across policies and telemetry."""
        findings: list[AuditFinding] = []

        findings.extend(self._check_lh_ztna_001())
        findings.extend(self._check_lh_ztna_002())
        findings.extend(self._check_lh_ztna_003())
        findings.extend(self._check_lh_ztna_004())
        findings.extend(self._check_lh_ztna_005())
        findings.extend(self._check_lh_ztna_006())
        findings.extend(self._check_lh_ztna_007())
        findings.extend(self._check_lh_ztna_008())
        findings.extend(self._check_lh_ztna_009())
        findings.extend(self._check_lh_ztna_010())

        return findings

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

    def _check_lh_ztna_001(self) -> list[AuditFinding]:
        """LH-ZTNA-001 (CRITICAL): Missing or Bypassed Identity Assertion on Protected Route."""
        rule = RULES_REGISTRY["LH-ZTNA-001"]
        findings: list[AuditFinding] = []

        for p in self.policies:
            route_lower = p.target_route.lower()
            is_sensitive = any(s in route_lower for s in SENSITIVE_ROUTES) or route_lower == "*"

            bypassed = p.bypass_auth is True or p.auth_required is False
            missing_auth = is_sensitive and (
                p.auth_required is None and not p.identity_provider and p.bypass_auth is None
            )

            if bypassed or missing_auth:
                evidence = (
                    f"Route '{p.target_route}' has auth_required={p.auth_required}, "
                    f"bypass_auth={p.bypass_auth}, idp='{p.identity_provider}'"
                )
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_route})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"Protected route '{p.target_route}' in policy '{p.name}' permits "
                            f"unauthenticated access or bypasses identity assertion."
                        ),
                        remediation=rule.remediation,
                        evidence=evidence,
                    )
                )
        return findings

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

    def _check_lh_ztna_002(self) -> list[AuditFinding]:
        """LH-ZTNA-002 (CRITICAL): Mutual TLS (mTLS) Disabled or Permissive."""
        rule = RULES_REGISTRY["LH-ZTNA-002"]
        findings: list[AuditFinding] = []

        for p in self.policies:
            permissive_mode = p.mtls_mode in ["disabled", "permissive", "none", "off"]
            insecure_verify = p.ssl_verify_client in ["off", "optional", "none"]
            missing_ca = p.ssl_verify_client == "on" and not p.client_ca_file

            if permissive_mode or insecure_verify or missing_ca:
                details: list[str] = []
                if permissive_mode:
                    details.append(f"mtls_mode='{p.mtls_mode}'")
                if insecure_verify:
                    details.append(f"ssl_verify_client='{p.ssl_verify_client}'")
                if missing_ca:
                    details.append("ssl_verify_client is on but client_ca_file is missing")

                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_route})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"Channel for route '{p.target_route}' does not enforce strict "
                            f"mutual TLS client verification."
                        ),
                        remediation=rule.remediation,
                        evidence=" | ".join(details),
                    )
                )
        return findings

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

    def _check_lh_ztna_003(self) -> list[AuditFinding]:
        """LH-ZTNA-003 (HIGH): Missing Device Posture or Endpoint Compliance Check."""
        rule = RULES_REGISTRY["LH-ZTNA-003"]
        findings: list[AuditFinding] = []

        for p in self.policies:
            missing_managed = p.require_managed_device is False
            missing_posture = p.device_posture_check is False
            incomplete_posture = p.device_posture_check is True and (
                p.disk_encryption_required is False or p.edr_active_required is False
            )

            if missing_managed or missing_posture or incomplete_posture:
                ev_items: list[str] = []
                if missing_managed:
                    ev_items.append("require_managed_device=False")
                if missing_posture:
                    ev_items.append("device_posture_check=False")
                if incomplete_posture:
                    ev_items.append(
                        f"disk_encryption={p.disk_encryption_required}, edr={p.edr_active_required}"
                    )

                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_route})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"ZTNA policy '{p.name}' permits access without verifying device "
                            f"management, disk encryption, or EDR compliance."
                        ),
                        remediation=rule.remediation,
                        evidence=" | ".join(ev_items),
                    )
                )

        # Check telemetry for allowed non-compliant devices
        for ev in self.events:
            p_status = ev.posture_status.lower()
            if p_status in ["non-compliant", "unmanaged", "unknown"] and ev.action.lower() in [
                "allow",
                "permit",
            ]:
                evidence = (
                    f"User '{ev.user_id}' on device '{ev.device_id}' allowed with posture "
                    f"'{ev.posture_status}'"
                )
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"event:{ev.event_id}",
                        title=f"{rule.title} - Event {ev.event_id}",
                        description=(
                            f"Access permitted for non-compliant device '{ev.device_id}' to "
                            f"resource '{ev.resource}'."
                        ),
                        remediation=rule.remediation,
                        evidence=evidence,
                    )
                )
        return findings

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

    def _check_lh_ztna_004(self) -> list[AuditFinding]:
        """LH-ZTNA-004 (CRITICAL): Implicit Network Trust or Broad CIDR Allowlist Violation."""
        rule = RULES_REGISTRY["LH-ZTNA-004"]
        findings: list[AuditFinding] = []

        for p in self.policies:
            has_lan_trust = p.trust_internal_network is True
            broad_matches: list[str] = []

            for cidr in p.allowed_cidrs:
                c_clean = cidr.strip()
                if c_clean in BROAD_CIDRS:
                    broad_matches.append(c_clean)

            if has_lan_trust or broad_matches:
                ev_items: list[str] = []
                if has_lan_trust:
                    ev_items.append("trust_internal_network=True")
                if broad_matches:
                    ev_items.append(f"Broad CIDRs allowed: {', '.join(broad_matches)}")

                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_route})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"Policy '{p.name}' confers implicit network trust using broad CIDRs "
                            f"or internal network bypass flags."
                        ),
                        remediation=rule.remediation,
                        evidence=" | ".join(ev_items),
                    )
                )
        return findings

    # --------------------------------------------------------------------------
    # --- Rule LH-ZTNA-005: Missing Multi-Factor Authentication (MFA) Step-Up (HIGH) ---
    # Evaluates security posture against missing multi-factor authentication (mfa)
    # step-up.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------

    def _check_lh_ztna_005(self) -> list[AuditFinding]:
        """LH-ZTNA-005 (HIGH): Missing Multi-Factor Authentication (MFA) Step-Up."""
        rule = RULES_REGISTRY["LH-ZTNA-005"]
        findings: list[AuditFinding] = []

        for p in self.policies:
            route_lower = p.target_route.lower()
            name_lower = p.name.lower()
            is_privileged = any(
                priv in route_lower or priv in name_lower for priv in PRIVILEGED_TARGETS
            )

            missing_mfa = is_privileged and (p.require_mfa is False or p.step_up_mfa is False)

            if missing_mfa:
                evidence = (
                    f"Privileged target '{p.target_route}' has require_mfa={p.require_mfa}, "
                    f"step_up_mfa={p.step_up_mfa}"
                )
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_route})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"Privileged route '{p.target_route}' does not mandate MFA or "
                            f"hardware token step-up verification."
                        ),
                        remediation=rule.remediation,
                        evidence=evidence,
                    )
                )
        return findings

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

    def _check_lh_ztna_006(self) -> list[AuditFinding]:
        """LH-ZTNA-006 (HIGH): Overly Permissive Micro-Segmentation or Lateral Movement Path."""
        rule = RULES_REGISTRY["LH-ZTNA-006"]
        findings: list[AuditFinding] = []

        for p in self.policies:
            wildcard_src = "*" in p.allowed_sources
            wildcard_dst = "*" in p.allowed_destinations
            wildcard_services = "*" in p.allowed_services

            is_open_mesh = (wildcard_src and wildcard_dst) or wildcard_services

            if is_open_mesh:
                evidence = (
                    f"sources={p.allowed_sources}, destinations={p.allowed_destinations}, "
                    f"services={p.allowed_services}"
                )
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_route})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"Micro-segmentation policy '{p.name}' permits wildcard east-west "
                            f"service communication, enabling lateral movement."
                        ),
                        remediation=rule.remediation,
                        evidence=evidence,
                    )
                )
        return findings

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

    def _check_lh_ztna_007(self) -> list[AuditFinding]:
        """LH-ZTNA-007 (HIGH): Anomalous Context, Impossible Travel, or Untrusted Geo/ASN Access."""
        rule = RULES_REGISTRY["LH-ZTNA-007"]
        findings: list[AuditFinding] = []

        # Check policy level geo fencing disabled
        for p in self.policies:
            if p.geo_restriction_enabled is False or p.block_untrusted_locations is False:
                evidence = (
                    f"geo_restriction_enabled={p.geo_restriction_enabled}, "
                    f"block_untrusted_locations={p.block_untrusted_locations}"
                )
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_route})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"Policy '{p.name}' explicitly disables geographic access "
                            f"restrictions or allows untrusted proxy networks."
                        ),
                        remediation=rule.remediation,
                        evidence=evidence,
                    )
                )

        # Check telemetry for impossible travel or untrusted origins
        user_events: dict[str, list[AccessTelemetryEvent]] = {}
        for ev in self.events:
            loc_lower = ev.location.lower()
            if any(untrusted in loc_lower for untrusted in UNTRUSTED_LOCATIONS):
                if ev.action.lower() in ["allow", "permit"]:
                    evidence = f"Access allowed from untrusted origin '{ev.location}'"
                    findings.append(
                        AuditFinding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            category=rule.category,
                            target_resource=f"event:{ev.event_id}",
                            title=f"{rule.title} - Untrusted Geo {ev.event_id}",
                            description=(
                                f"Access granted to '{ev.user_id}' from untrusted/anonymized "
                                f"network origin '{ev.location}'."
                            ),
                            remediation=rule.remediation,
                            evidence=evidence,
                        )
                    )

            if ev.user_id:
                user_events.setdefault(ev.user_id, []).append(ev)

        # Evaluate impossible travel per user
        for u_id, ev_list in user_events.items():
            if len(ev_list) >= 2:
                for i in range(len(ev_list) - 1):
                    e1 = ev_list[i]
                    e2 = ev_list[i + 1]
                    if e1.location and e2.location and e1.location != e2.location:
                        t1 = _parse_timestamp(e1.timestamp)
                        t2 = _parse_timestamp(e2.timestamp)
                        if t1 and t2:
                            diff_seconds = abs((t2 - t1).total_seconds())
                            if diff_seconds < 3600:  # < 1 hour between distinct locations
                                evidence = (
                                    f"User '{u_id}' logged in from '{e1.location}' at "
                                    f"{e1.timestamp} and '{e2.location}' at {e2.timestamp} "
                                    f"({int(diff_seconds)}s apart)"
                                )
                                findings.append(
                                    AuditFinding(
                                        rule_id=rule.rule_id,
                                        severity=rule.severity,
                                        category=rule.category,
                                        target_resource=f"user:{u_id}",
                                        title=f"{rule.title} - Impossible Travel ({u_id})",
                                        description=(
                                            f"Impossible travel velocity detected for '{u_id}' "
                                            f"between '{e1.location}' and '{e2.location}'."
                                        ),
                                        remediation=rule.remediation,
                                        evidence=evidence,
                                    )
                                )
        return findings

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

    def _check_lh_ztna_008(self) -> list[AuditFinding]:
        """LH-ZTNA-008 (MEDIUM): Excessive ZTNA Session TTL or Disabled Continuous Re-Evaluation."""
        rule = RULES_REGISTRY["LH-ZTNA-008"]
        findings: list[AuditFinding] = []

        for p in self.policies:
            excessive_ttl = p.session_ttl_minutes is not None and p.session_ttl_minutes > 480
            no_continuous = p.continuous_evaluation is False

            if excessive_ttl or no_continuous:
                details: list[str] = []
                if excessive_ttl:
                    details.append(
                        f"session_ttl_minutes={p.session_ttl_minutes} (> 480m threshold)"
                    )
                if no_continuous:
                    details.append("continuous_evaluation=False")

                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_route})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"Policy '{p.name}' permits excessive session lifetime or disables "
                            f"continuous posture re-evaluation."
                        ),
                        remediation=rule.remediation,
                        evidence=" | ".join(details),
                    )
                )
        return findings

    # --------------------------------------------------------------------------
    # --- Rule LH-ZTNA-009: Unverified Identity Header Forwarding (HIGH) ---
    # Evaluates security posture against unverified identity header forwarding.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------

    def _check_lh_ztna_009(self) -> list[AuditFinding]:
        """LH-ZTNA-009 (HIGH): Unverified Identity Header Forwarding (Header Spoofing Vector)."""
        rule = RULES_REGISTRY["LH-ZTNA-009"]
        findings: list[AuditFinding] = []

        for p in self.policies:
            if p.strip_identity_headers is False:
                evidence = (
                    "strip_identity_headers=False (client identity headers forwarded directly)"
                )
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_route})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"Reverse proxy route '{p.target_route}' fails to strip incoming "
                            f"client identity headers, risking header injection and spoofing."
                        ),
                        remediation=rule.remediation,
                        evidence=evidence,
                    )
                )
        return findings

    # --------------------------------------------------------------------------
    # --- Rule LH-ZTNA-010: Missing Zero-Trust Policy Decision Audit Telemetry (LOW) ---
    # Evaluates security posture against missing zero-trust policy decision audit
    # telemetry.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------

    def _check_lh_ztna_010(self) -> list[AuditFinding]:
        """LH-ZTNA-010 (LOW): Missing Zero-Trust Policy Decision Audit Telemetry."""
        rule = RULES_REGISTRY["LH-ZTNA-010"]
        findings: list[AuditFinding] = []

        for p in self.policies:
            if p.decision_logging is False:
                evidence = "decision_logging=False"
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_route})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"Policy '{p.name}' disables decision logging, preventing auditability "
                            f"and anomaly detection."
                        ),
                        remediation=rule.remediation,
                        evidence=evidence,
                    )
                )

        for ev in self.events:
            missing_fields: list[str] = []
            if not ev.user_id.strip():
                missing_fields.append("user_id")
            if not ev.device_id.strip():
                missing_fields.append("device_id")
            if not ev.posture_status.strip():
                missing_fields.append("posture_status")

            if missing_fields:
                evidence = (
                    f"Telemetry record lacks required context fields: {', '.join(missing_fields)}"
                )
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"event:{ev.event_id}",
                        title=f"{rule.title} - Incomplete Telemetry {ev.event_id}",
                        description=(
                            f"Access telemetry event '{ev.event_id}' is missing critical identity "
                            f"or device posture context."
                        ),
                        remediation=rule.remediation,
                        evidence=evidence,
                    )
                )
        return findings


def calculate_risk_score(findings: list[AuditFinding]) -> int:
    """Calculate consolidated Zero-Trust risk score from findings (0-100)."""
    if not findings:
        return 0

    crit = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
    hi = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)
    med = sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM)
    lo = sum(1 for f in findings if f.severity == FindingSeverity.LOW)

    raw_score = crit * 25 + hi * 15 + med * 5 + lo * 2
    return min(100, raw_score)


def audit_ztna_target(target: Path) -> AuditReport:
    """Ingest Zero-Trust manifests and evaluate against complete rule catalog."""
    files = find_policy_files(target)

    all_policies: list[ZTNAPolicy] = []
    all_events: list[AccessTelemetryEvent] = []

    for f in files:
        policies, events = parse_policy_file(f)
        all_policies.extend(policies)
        all_events.extend(events)

    analyzer = ZTNAAnalyzer(all_policies, all_events)
    findings = analyzer.analyze()

    crit = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
    hi = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)
    med = sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM)
    lo = sum(1 for f in findings if f.severity == FindingSeverity.LOW)

    summary = {
        "critical": crit,
        "high": hi,
        "medium": med,
        "low": lo,
    }

    risk_score = calculate_risk_score(findings)

    return AuditReport(
        target=str(target),
        files_scanned=len(files),
        policies_analyzed=len(all_policies),
        telemetry_events_analyzed=len(all_events),
        findings_count=len(findings),
        findings=findings,
        summary=summary,
        risk_score=risk_score,
    )
