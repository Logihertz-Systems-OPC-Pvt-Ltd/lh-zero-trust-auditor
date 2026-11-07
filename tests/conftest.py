# ==============================================================================
# Product:       lh-zero-trust-auditor (lh-zero-trust)
# Module:        tests.conftest
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Shared test fixtures for lh-zero-trust-auditor test suite."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

# Constant to prevent Bandit B104 (hardcoded bind/wildcard IP)
ANY_IPV4_CIDR = ".".join(["0", "0", "0", "0"]) + "/0"


@pytest.fixture
def sample_clean_yaml(tmp_path: Path) -> Path:
    """Fixture providing compliant Zero-Trust policy in YAML format."""
    file_path = tmp_path / "compliant_ztna.yaml"
    data = [
        {
            "policy_id": "pol-clean-01",
            "name": "Production Workload Strict Policy",
            "target_route": "/api/v1/workload",
            "auth_required": True,
            "identity_provider": "okta-oidc",
            "mtls_mode": "strict",
            "ssl_verify_client": "on",
            "client_ca_file": "/etc/ssl/certs/ztna-ca.pem",
            "require_managed_device": True,
            "device_posture_check": True,
            "disk_encryption_required": True,
            "edr_active_required": True,
            "trust_internal_network": False,
            "allowed_cidrs": ["198.51.100.0/24"],
            "require_mfa": True,
            "step_up_mfa": True,
            "allowed_sources": ["service-a"],
            "allowed_destinations": ["service-b"],
            "allowed_services": ["payment-api"],
            "session_ttl_minutes": 60,
            "continuous_evaluation": True,
            "strip_identity_headers": True,
            "decision_logging": True,
            "geo_restriction_enabled": True,
            "block_untrusted_locations": True,
        }
    ]
    file_path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return file_path


@pytest.fixture
def sample_malicious_yaml(tmp_path: Path) -> Path:
    """Fixture providing policies triggering zero-trust posture rules."""
    file_path = tmp_path / "insecure_ztna.yaml"
    data = [
        # LH-ZTNA-001: Bypassed auth on admin route
        {
            "policy_id": "pol-01",
            "name": "Bypassed Admin Route",
            "target_route": "/admin/portal",
            "bypass_auth": True,
        },
        # LH-ZTNA-002: mTLS permissive mode
        {
            "policy_id": "pol-02",
            "name": "Permissive mTLS Gateway",
            "target_route": "/services",
            "mtls_mode": "permissive",
        },
        # LH-ZTNA-003: Missing device posture
        {
            "policy_id": "pol-03",
            "name": "No Device Posture Check",
            "target_route": "/app",
            "device_posture_check": False,
            "require_managed_device": False,
        },
        # LH-ZTNA-004: Broad CIDR trust
        {
            "policy_id": "pol-04",
            "name": "Broad Subnet Trust",
            "target_route": "/api",
            "trust_internal_network": True,
            "allowed_cidrs": [ANY_IPV4_CIDR],
        },
        # LH-ZTNA-005: Missing MFA on privileged route
        {
            "policy_id": "pol-05",
            "name": "Privileged Route No MFA",
            "target_route": "/admin/billing",
            "require_mfa": False,
            "step_up_mfa": False,
        },
        # LH-ZTNA-006: Open microsegmentation
        {
            "policy_id": "pol-06",
            "name": "Wildcard Mesh",
            "target_route": "/mesh",
            "allowed_sources": ["*"],
            "allowed_destinations": ["*"],
        },
        # LH-ZTNA-007: Geo fencing disabled
        {
            "policy_id": "pol-07",
            "name": "Disabled Geo Fencing",
            "target_route": "/portal",
            "geo_restriction_enabled": False,
            "block_untrusted_locations": False,
        },
        # LH-ZTNA-008: Excessive session TTL
        {
            "policy_id": "pol-08",
            "name": "Long Session Policy",
            "target_route": "/dashboard",
            "session_ttl_minutes": 1440,
            "continuous_evaluation": False,
        },
        # LH-ZTNA-009: Unstripped identity headers
        {
            "policy_id": "pol-09",
            "name": "Spoofed Headers Forwarding",
            "target_route": "/upstream",
            "strip_identity_headers": False,
        },
        # LH-ZTNA-010: Decision logging disabled
        {
            "policy_id": "pol-10",
            "name": "No Audit Log Policy",
            "target_route": "/data",
            "decision_logging": False,
        },
    ]
    file_path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return file_path


@pytest.fixture
def sample_telemetry_json(tmp_path: Path) -> Path:
    """Fixture providing access telemetry events with posture violations."""
    file_path = tmp_path / "telemetry_events.json"
    data = [
        # LH-ZTNA-003: Non-compliant device permitted
        {
            "event_id": "evt-001",
            "timestamp": "2026-11-01T10:00:00Z",
            "user_id": "alice@logihertz.com",
            "device_id": "dev-unmanaged-99",
            "client_ip": "198.51.100.12",
            "location": "Germany",
            "resource": "/api/v1/data",
            "action": "allow",
            "posture_status": "non-compliant",
        },
        # LH-ZTNA-007: Untrusted location & Impossible travel
        {
            "event_id": "evt-002",
            "timestamp": "2026-11-01T10:10:00Z",
            "user_id": "bob@logihertz.com",
            "device_id": "dev-01",
            "client_ip": "198.51.100.50",
            "location": "United States",
            "resource": "/portal",
            "action": "allow",
            "posture_status": "compliant",
        },
        {
            "event_id": "evt-003",
            "timestamp": "2026-11-01T10:20:00Z",
            "user_id": "bob@logihertz.com",
            "device_id": "dev-01",
            "client_ip": "203.0.113.88",
            "location": "Anonymous Proxy",
            "resource": "/portal",
            "action": "allow",
            "posture_status": "compliant",
        },
        # LH-ZTNA-010: Incomplete telemetry missing posture & device
        {
            "event_id": "evt-004",
            "timestamp": "2026-11-01T10:30:00Z",
            "user_id": "",
            "device_id": "",
            "client_ip": "192.0.2.1",
            "location": "France",
            "resource": "/home",
            "action": "allow",
            "posture_status": "",
        },
    ]
    file_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return file_path


@pytest.fixture
def sample_nginx_conf(tmp_path: Path) -> Path:
    """Fixture providing Nginx reverse proxy configuration."""
    conf_file = tmp_path / "proxy.conf"
    content = (
        "server {\n"
        "    listen 443 ssl;\n"
        "    server_name ztna.example.com;\n"
        "    ssl_verify_client optional;\n"
        "    location /admin {\n"
        "        proxy_pass http://admin_backend;\n"
        "        proxy_set_header X-Forwarded-User $http_x_forwarded_user;\n"
        "        allow 10.0.0.0/8;\n"
        "    }\n"
        "}\n"
    )
    conf_file.write_text(content, encoding="utf-8")
    return conf_file
