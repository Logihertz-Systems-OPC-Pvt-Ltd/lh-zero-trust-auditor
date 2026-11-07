# ==============================================================================
# Product:       lh-zero-trust-auditor (lh-zero-trust)
# Module:        tests.test_policy_parser
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for Zero-Trust policy manifests and telemetry parsers."""

from __future__ import annotations

import json
from pathlib import Path

from lh_zero_trust_auditor.policy_parser import (
    find_policy_files,
    parse_conf_file,
    parse_csv_file,
    parse_json_file,
    parse_policy_file,
    parse_yaml_file,
)


def test_parse_yaml_policy(sample_clean_yaml: Path) -> None:
    """Verify parsing compliant ZTNA policy manifest in YAML."""
    policies, events = parse_yaml_file(sample_clean_yaml)
    assert len(policies) == 1
    assert len(events) == 0
    p = policies[0]
    assert p.policy_id == "pol-clean-01"
    assert p.auth_required is True
    assert p.mtls_mode == "strict"
    assert p.require_managed_device is True
    assert p.session_ttl_minutes == 60


def test_parse_json_telemetry(sample_telemetry_json: Path) -> None:
    """Verify parsing access telemetry stream in JSON."""
    policies, events = parse_json_file(sample_telemetry_json)
    assert len(policies) == 0
    assert len(events) == 4
    assert events[0].event_id == "evt-001"
    assert events[0].user_id == "alice@logihertz.com"
    assert events[0].posture_status == "non-compliant"


def test_parse_ndjson_events(tmp_path: Path) -> None:
    """Verify parsing NDJSON newline-delimited telemetry lines."""
    file_path = tmp_path / "events.jsonl"
    lines = [
        json.dumps({"event_id": "nd-1", "user": "user1", "action": "allow"}),
        json.dumps({"event_id": "nd-2", "user": "user2", "action": "deny"}),
    ]
    file_path.write_text("\n".join(lines), encoding="utf-8")
    _, events = parse_json_file(file_path)
    assert len(events) == 2
    assert events[0].event_id == "nd-1"
    assert events[1].event_id == "nd-2"


def test_parse_conf_file(sample_nginx_conf: Path) -> None:
    """Verify parsing Nginx reverse proxy configuration."""
    policies, _ = parse_conf_file(sample_nginx_conf)
    assert len(policies) >= 1
    admin_pol = next(p for p in policies if p.target_route == "/admin")
    assert admin_pol.strip_identity_headers is False
    assert "10.0.0.0/8" in admin_pol.allowed_cidrs


def test_parse_csv_file(tmp_path: Path) -> None:
    """Verify parsing CSV access telemetry export."""
    csv_file = tmp_path / "access.csv"
    content = (
        "Timestamp,User ID,Device ID,Client IP,Location,Resource,Action,Posture Status\n"
        "2026-11-01T10:00:00Z,carol,dev-99,10.0.0.1,DE,/api,allow,compliant\n"
    )
    csv_file.write_text(content, encoding="utf-8")
    _, events = parse_csv_file(csv_file)
    assert len(events) == 1
    assert events[0].user_id == "carol"
    assert events[0].device_id == "dev-99"
    assert events[0].resource == "/api"


def test_find_policy_files(tmp_path: Path) -> None:
    """Verify file discovery across supported configuration formats."""
    (tmp_path / "policy.yaml").write_text("[]\n", encoding="utf-8")
    (tmp_path / "events.json").write_text("[]\n", encoding="utf-8")
    (tmp_path / "proxy.conf").write_text("server {}\n", encoding="utf-8")
    (tmp_path / "ignore.bin").write_text("raw\n", encoding="utf-8")

    found = find_policy_files(tmp_path)
    names = [f.name for f in found]
    assert "policy.yaml" in names
    assert "events.json" in names
    assert "proxy.conf" in names
    assert "ignore.bin" not in names


def test_parse_policy_file_dispatch(sample_clean_yaml: Path, tmp_path: Path) -> None:
    """Verify parse_policy_file dispatches appropriately."""
    policies, _ = parse_policy_file(sample_clean_yaml)
    assert len(policies) == 1

    # Fallback with unknown extension
    unk = tmp_path / "config.raw"
    unk.write_text(sample_clean_yaml.read_text(encoding="utf-8"), encoding="utf-8")
    p_unk, _ = parse_policy_file(unk)
    assert len(p_unk) == 1
