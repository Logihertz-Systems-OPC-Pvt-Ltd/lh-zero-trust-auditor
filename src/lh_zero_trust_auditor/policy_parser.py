# ==============================================================================
# Product:       lh-zero-trust-auditor (lh-zero-trust)
# Module:        src.lh_zero_trust_auditor.policy_parser
# Role:          Input Parser & Configuration Ingestion
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Parsers for Zero-Trust gateway manifests, reverse proxy configs, and telemetry."""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any

import yaml

from lh_zero_trust_auditor.models import AccessTelemetryEvent, ZTNAPolicy


def _extract_bool(data: dict[str, Any], aliases: list[str]) -> bool | None:
    """Extract boolean value checking case-insensitive alias keys."""
    normalized = {k.strip().lower().replace("_", " "): v for k, v in data.items()}
    for alias in aliases:
        norm_alias = alias.strip().lower().replace("_", " ")
        if norm_alias in normalized:
            val = normalized[norm_alias]
            if isinstance(val, bool):
                return val
            if isinstance(val, str):
                s = val.strip().lower()
                if s in ["true", "yes", "1", "on", "enabled", "strict"]:
                    return True
                if s in ["false", "no", "0", "off", "disabled", "optional", "permissive"]:
                    return False
            if isinstance(val, int):
                return bool(val)
    return None


def _extract_str(data: dict[str, Any], aliases: list[str], default: str = "") -> str:
    """Extract string value checking case-insensitive alias keys."""
    normalized = {k.strip().lower().replace("_", " "): v for k, v in data.items()}
    for alias in aliases:
        norm_alias = alias.strip().lower().replace("_", " ")
        if norm_alias in normalized:
            val = normalized[norm_alias]
            if val is not None:
                return str(val).strip()
    return default


def _extract_int(data: dict[str, Any], aliases: list[str]) -> int | None:
    """Extract integer value checking case-insensitive alias keys."""
    normalized = {k.strip().lower().replace("_", " "): v for k, v in data.items()}
    for alias in aliases:
        norm_alias = alias.strip().lower().replace("_", " ")
        if norm_alias in normalized:
            val = normalized[norm_alias]
            try:
                return int(val)
            except (ValueError, TypeError):
                pass
    return None


def _extract_list(data: dict[str, Any], aliases: list[str]) -> list[str]:
    """Extract string list checking case-insensitive alias keys."""
    normalized = {k.strip().lower().replace("_", " "): v for k, v in data.items()}
    for alias in aliases:
        norm_alias = alias.strip().lower().replace("_", " ")
        if norm_alias in normalized:
            val = normalized[norm_alias]
            if isinstance(val, list):
                return [str(x).strip() for x in val if x is not None]
            if isinstance(val, str):
                return [x.strip() for x in val.split(",") if x.strip()]
    return []


def _dict_to_ztna_policy(data: dict[str, Any], source_file: str, line_no: int) -> ZTNAPolicy:
    """Convert parsed dictionary into a ZTNAPolicy object."""
    policy_id = _extract_str(data, ["policy_id", "id", "name", "rule_id"], f"pol-{line_no}")
    name = _extract_str(data, ["name", "title", "description"], policy_id)
    route = _extract_str(data, ["target_route", "route", "path", "endpoint", "url"], "*")

    auth_req = _extract_bool(data, ["auth_required", "require_auth", "authenticated"])
    bypass_auth = _extract_bool(data, ["bypass_auth", "allow_unauthenticated", "public"])
    idp = _extract_str(data, ["identity_provider", "idp", "auth_provider", "sso"])

    mtls_mode = _extract_str(data, ["mtls_mode", "mtls", "tls_mode"]).lower()
    ssl_verify = _extract_str(data, ["ssl_verify_client", "verify_client", "client_auth"]).lower()
    ca_file = _extract_str(data, ["client_ca_file", "ssl_client_certificate", "ca_cert"])

    managed_dev = _extract_bool(data, ["require_managed_device", "managed_device_only", "mdm"])
    posture_chk = _extract_bool(data, ["device_posture_check", "posture_check", "compliance"])
    disk_enc = _extract_bool(data, ["disk_encryption_required", "require_encryption", "filevault"])
    edr_act = _extract_bool(data, ["edr_active_required", "require_edr", "antivirus"])

    trust_lan = _extract_bool(
        data, ["trust_internal_network", "bypass_on_lan", "internal_trust", "trust_intranet"]
    )
    cidrs = _extract_list(data, ["allowed_cidrs", "trusted_subnets", "ip_allowlist", "cidrs"])

    mfa_req = _extract_bool(data, ["require_mfa", "mfa_required", "two_factor"])
    step_up = _extract_bool(data, ["step_up_mfa", "fido2_required", "hardware_token"])

    sources = _extract_list(data, ["allowed_sources", "sources", "from", "source_services"])
    destinations = _extract_list(data, ["allowed_destinations", "destinations", "to"])
    services = _extract_list(data, ["allowed_services", "services", "allowed_workloads"])

    session_ttl = _extract_int(
        data, ["session_ttl_minutes", "session_ttl", "max_session_duration", "token_lifetime"]
    )
    cont_eval = _extract_bool(
        data, ["continuous_evaluation", "continuous_posture", "continuous_reauth"]
    )
    strip_hdrs = _extract_bool(
        data, ["strip_identity_headers", "sanitize_forwarded_headers", "strip_client_headers"]
    )
    logging = _extract_bool(
        data, ["decision_logging", "audit_logging", "log_decisions", "telemetry"]
    )
    geo_restr = _extract_bool(
        data, ["geo_restriction_enabled", "geo_fencing", "country_restrictions"]
    )
    block_untrusted = _extract_bool(
        data, ["block_untrusted_locations", "block_tor", "block_proxies"]
    )

    return ZTNAPolicy(
        policy_id=policy_id,
        name=name,
        target_route=route,
        auth_required=auth_req,
        bypass_auth=bypass_auth,
        identity_provider=idp,
        mtls_mode=mtls_mode,
        ssl_verify_client=ssl_verify,
        client_ca_file=ca_file,
        require_managed_device=managed_dev,
        device_posture_check=posture_chk,
        disk_encryption_required=disk_enc,
        edr_active_required=edr_act,
        trust_internal_network=trust_lan,
        allowed_cidrs=cidrs,
        require_mfa=mfa_req,
        step_up_mfa=step_up,
        allowed_sources=sources,
        allowed_destinations=destinations,
        allowed_services=services,
        session_ttl_minutes=session_ttl,
        continuous_evaluation=cont_eval,
        strip_identity_headers=strip_hdrs,
        decision_logging=logging,
        geo_restriction_enabled=geo_restr,
        block_untrusted_locations=block_untrusted,
        source_file=source_file,
        line_number=line_no,
    )


def _dict_to_telemetry_event(
    data: dict[str, Any], source_file: str, line_no: int
) -> AccessTelemetryEvent:
    """Convert parsed dictionary into an AccessTelemetryEvent."""
    return AccessTelemetryEvent(
        event_id=_extract_str(data, ["event_id", "id", "log_id"], f"evt-{line_no}"),
        timestamp=_extract_str(data, ["timestamp", "time", "date", "datetime"]),
        user_id=_extract_str(data, ["user_id", "user", "username", "identity", "email"]),
        device_id=_extract_str(data, ["device_id", "device", "endpoint_id", "machine_id"]),
        client_ip=_extract_str(data, ["client_ip", "ip", "source_ip", "remote_addr"]),
        location=_extract_str(data, ["location", "country", "geo", "city"]),
        resource=_extract_str(data, ["resource", "target", "path", "url", "route"]),
        action=_extract_str(data, ["action", "decision", "result", "status"], "allow"),
        posture_status=_extract_str(
            data, ["posture_status", "device_posture", "compliance"], "compliant"
        ),
        source_file=source_file,
        line_number=line_no,
    )


def parse_yaml_file(path: Path) -> tuple[list[ZTNAPolicy], list[AccessTelemetryEvent]]:
    # --- Multi-Format Parsing & Normalization Engine ---
    # Autodetects manifest formats (JSON, YAML, .conf, .env, CSV, JSONL),
    # applies fallback decoders, recovers from malformed lines, and standardizes
    # raw configuration attributes into typed domain model instances.
    """Parse YAML ZTNA policy manifest or event log."""
    policies: list[ZTNAPolicy] = []
    events: list[AccessTelemetryEvent] = []
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        loaded = yaml.safe_load(content)

        if isinstance(loaded, list):
            for idx, item in enumerate(loaded, start=1):
                if isinstance(item, dict):
                    if "user_id" in item or "user" in item or "posture_status" in item:
                        events.append(_dict_to_telemetry_event(item, str(path), idx))
                    else:
                        policies.append(_dict_to_ztna_policy(item, str(path), idx))
        elif isinstance(loaded, dict):
            # Check wrapper keys
            if "policies" in loaded and isinstance(loaded["policies"], list):
                for idx, item in enumerate(loaded["policies"], start=1):
                    if isinstance(item, dict):
                        policies.append(_dict_to_ztna_policy(item, str(path), idx))
            elif "events" in loaded and isinstance(loaded["events"], list):
                for idx, item in enumerate(loaded["events"], start=1):
                    if isinstance(item, dict):
                        events.append(_dict_to_telemetry_event(item, str(path), idx))
            else:
                policies.append(_dict_to_ztna_policy(loaded, str(path), 1))
    except Exception:
        return policies, events
    return policies, events


def parse_json_file(path: Path) -> tuple[list[ZTNAPolicy], list[AccessTelemetryEvent]]:
    """Parse JSON ZTNA policy manifest or telemetry stream."""
    policies: list[ZTNAPolicy] = []
    events: list[AccessTelemetryEvent] = []
    try:
        content = path.read_text(encoding="utf-8", errors="replace").strip()
        if not content:
            return [], []

        if content.startswith("["):
            loaded = json.loads(content)
            if isinstance(loaded, list):
                for idx, item in enumerate(loaded, start=1):
                    if isinstance(item, dict):
                        if "user_id" in item or "user" in item or "posture_status" in item:
                            events.append(_dict_to_telemetry_event(item, str(path), idx))
                        else:
                            policies.append(_dict_to_ztna_policy(item, str(path), idx))
                return policies, events
        elif content.startswith("{"):
            try:
                loaded = json.loads(content)
                if isinstance(loaded, dict):
                    if "policies" in loaded and isinstance(loaded["policies"], list):
                        for idx, item in enumerate(loaded["policies"], start=1):
                            if isinstance(item, dict):
                                policies.append(_dict_to_ztna_policy(item, str(path), idx))
                        return policies, events
                    elif "events" in loaded and isinstance(loaded["events"], list):
                        for idx, item in enumerate(loaded["events"], start=1):
                            if isinstance(item, dict):
                                events.append(_dict_to_telemetry_event(item, str(path), idx))
                        return policies, events
                    else:
                        policies.append(_dict_to_ztna_policy(loaded, str(path), 1))
                        return policies, events
            except json.JSONDecodeError:
                pass

        # NDJSON fallback
        for idx, line in enumerate(content.splitlines(), start=1):
            clean = line.strip()
            if clean:
                try:
                    obj = json.loads(clean)
                    if isinstance(obj, dict):
                        if "user_id" in obj or "user" in obj or "posture_status" in obj:
                            events.append(_dict_to_telemetry_event(obj, str(path), idx))
                        else:
                            policies.append(_dict_to_ztna_policy(obj, str(path), idx))
                except json.JSONDecodeError:
                    continue
    except Exception:
        return policies, events
    return policies, events


def parse_conf_file(path: Path) -> tuple[list[ZTNAPolicy], list[AccessTelemetryEvent]]:
    """Parse Nginx or reverse proxy configuration file."""
    policies: list[ZTNAPolicy] = []
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        # Split by location blocks
        location_blocks = re.findall(r"location\s+([^{]+)\{([^}]+)\}", content, re.DOTALL)

        for idx, (route_raw, block_body) in enumerate(location_blocks, start=1):
            route = route_raw.strip()
            data: dict[str, Any] = {"route": route, "name": f"nginx-loc-{idx}"}

            # Check auth directives
            if "auth_request" in block_body:
                data["auth_required"] = True
            elif "auth_basic" in block_body:
                data["auth_required"] = True
            elif any(k in route.lower() for k in ["admin", "api", "internal", "private"]):
                data["auth_required"] = False

            # Check mTLS directives
            m_verify = re.search(r"ssl_verify_client\s+(on|off|optional)", block_body)
            if m_verify:
                data["ssl_verify_client"] = m_verify.group(1)

            m_ca = re.search(r"ssl_client_certificate\s+([^;]+);", block_body)
            if m_ca:
                data["client_ca_file"] = m_ca.group(1).strip()

            # Check CIDRs
            cidrs = re.findall(r"allow\s+([^;]+);", block_body)
            if cidrs:
                data["allowed_cidrs"] = [c.strip() for c in cidrs]

            # Check header forwarding
            if "proxy_set_header" in block_body and "X-Forwarded-User" in block_body:
                if "$http_x_forwarded_user" in block_body:
                    data["strip_identity_headers"] = False
                elif '""' in block_body:
                    data["strip_identity_headers"] = True

            policies.append(_dict_to_ztna_policy(data, str(path), idx))

        # If no location blocks, check server level directives
        if not policies:
            data = {"route": "*", "name": "nginx-server-root"}
            m_verify = re.search(r"ssl_verify_client\s+(on|off|optional)", content)
            if m_verify:
                data["ssl_verify_client"] = m_verify.group(1)
            policies.append(_dict_to_ztna_policy(data, str(path), 1))
    except Exception:
        return policies, []
    return policies, []


def parse_csv_file(path: Path) -> tuple[list[ZTNAPolicy], list[AccessTelemetryEvent]]:
    """Parse CSV visitor/access telemetry logs."""
    events: list[AccessTelemetryEvent] = []
    try:
        with path.open(mode="r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for idx, row in enumerate(reader, start=2):
                if not row:
                    continue
                events.append(_dict_to_telemetry_event(dict(row), str(path), idx))
    except Exception:
        return [], events
    return [], events


def parse_policy_file(path: Path) -> tuple[list[ZTNAPolicy], list[AccessTelemetryEvent]]:
    """Dispatch file parsing based on extension and content."""
    suffix = path.suffix.lower()
    if suffix in [".yaml", ".yml"]:
        return parse_yaml_file(path)
    if suffix in [".json", ".jsonl"]:
        return parse_json_file(path)
    if suffix in [".conf", ".nginx"]:
        return parse_conf_file(path)
    if suffix == ".csv":
        return parse_csv_file(path)

    # Fallback heuristics
    p, e = parse_yaml_file(path)
    if p or e:
        return p, e
    p_j, e_j = parse_json_file(path)
    if p_j or e_j:
        return p_j, e_j
    return parse_conf_file(path)


def find_policy_files(root: Path) -> list[Path]:
    """Find all supported ZTNA policy and telemetry files under root path."""
    if not root.exists():
        return []

    if root.is_file():
        return [root]

    supported_suffixes = {".yaml", ".yml", ".json", ".jsonl", ".conf", ".nginx", ".csv"}
    files: list[Path] = []
    for item in root.rglob("*"):
        if item.is_file() and item.suffix.lower() in supported_suffixes:
            files.append(item)
    return sorted(files)
