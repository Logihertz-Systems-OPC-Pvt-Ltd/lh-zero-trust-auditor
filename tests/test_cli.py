# ==============================================================================
# Product:       lh-zero-trust-auditor (lh-zero-trust)
# Module:        tests.test_cli
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Integration tests for lh-ztna CLI application."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from lh_zero_trust_auditor.cli import app

runner = CliRunner()
ENV = {"COLUMNS": "160", "NO_COLOR": "1", "TERM": "dumb"}


def test_cli_version() -> None:
    """Verify version flag output."""
    res = runner.invoke(app, ["--version"], env=ENV)
    assert res.exit_code == 0
    assert "lh-zero-trust-auditor v0.1.0" in res.stdout


def test_cli_rules() -> None:
    """Verify listing of detection rules catalog."""
    res = runner.invoke(app, ["rules"], env=ENV)
    assert res.exit_code == 0
    assert "LH-ZTNA-001" in res.stdout
    assert "LH-ZTNA-010" in res.stdout
    assert "Missing or Bypassed Identity Assertion" in res.stdout


def test_cli_scan_clean(sample_clean_yaml: Path) -> None:
    """Verify clean Zero-Trust policy scan exits with 0 and shows compliant panel."""
    res = runner.invoke(app, ["scan", str(sample_clean_yaml)], env=ENV)
    assert res.exit_code == 0
    assert "Zero-Trust Posture Compliant" in res.stdout


def test_cli_scan_malicious_fails_by_default(sample_malicious_yaml: Path) -> None:
    """Verify insecure policies trigger non-zero exit code on default high threshold."""
    res = runner.invoke(app, ["scan", str(sample_malicious_yaml)], env=ENV)
    assert res.exit_code == 1
    assert "LH-ZTNA-001" in res.stdout


def test_cli_scan_json_format(sample_clean_yaml: Path) -> None:
    """Verify scan with JSON output formatting to stdout."""
    res = runner.invoke(app, ["scan", str(sample_clean_yaml), "--format", "json"], env=ENV)
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["scanner"] == "lh-zero-trust-auditor"
    assert data["findings_count"] == 0


def test_cli_scan_sarif_format(sample_clean_yaml: Path) -> None:
    """Verify scan with SARIF output formatting to stdout."""
    res = runner.invoke(app, ["scan", str(sample_clean_yaml), "--format", "sarif"], env=ENV)
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["tool"]["driver"]["name"] == "lh-zero-trust-auditor"


def test_cli_scan_file_output(sample_clean_yaml: Path, tmp_path: Path) -> None:
    """Verify writing report to external file."""
    out_file = tmp_path / "report.txt"
    res = runner.invoke(
        app,
        ["scan", str(sample_clean_yaml), "--output", str(out_file)],
        env=ENV,
    )
    assert res.exit_code == 0
    assert out_file.exists()
    assert "Zero-Trust Posture Compliant" in out_file.read_text(encoding="utf-8")


def test_cli_scan_json_file_output(sample_clean_yaml: Path, tmp_path: Path) -> None:
    """Verify writing JSON report to external file."""
    out_json = tmp_path / "report.json"
    res = runner.invoke(
        app,
        ["scan", str(sample_clean_yaml), "--format", "json", "--output", str(out_json)],
        env=ENV,
    )
    assert res.exit_code == 0
    assert out_json.exists()
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["findings_count"] == 0


def test_cli_scan_sarif_file_output(sample_clean_yaml: Path, tmp_path: Path) -> None:
    """Verify writing SARIF report to external file."""
    out_sarif = tmp_path / "report.sarif"
    res = runner.invoke(
        app,
        ["scan", str(sample_clean_yaml), "--format", "sarif", "--output", str(out_sarif)],
        env=ENV,
    )
    assert res.exit_code == 0
    assert out_sarif.exists()
    data = json.loads(out_sarif.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"


def test_cli_scan_min_severity_filter(sample_malicious_yaml: Path) -> None:
    """Verify min-severity filtering."""
    res = runner.invoke(
        app,
        ["scan", str(sample_malicious_yaml), "--min-severity", "critical", "--format", "json"],
        env=ENV,
    )
    data = json.loads(res.stdout)
    for finding in data["findings"]:
        assert finding["severity"] == "CRITICAL"
