"""Tests for scanner.report: aggregate, to_text, to_json, to_csv, to_html, to_sarif."""
import json
import pytest
from scanner.report import (
    aggregate,
    format_size,
    to_csv,
    to_html,
    to_json,
    to_sarif,
    to_text,
)


def test_aggregate_empty():
    r = aggregate([], [])
    assert r["scan_timestamp"]
    assert r["metadata"] == []
    assert r["findings"] == []
    assert r["summary"] == {"artifacts": 0, "findings": 0}


def test_aggregate_with_metadata_and_findings():
    meta = [{"path": "/a.apk", "type": "apk", "metadata": {}}]
    findings = [{"rule_id": "r1", "severity": "high", "message": "msg"}]
    r = aggregate(meta, findings, scan_timestamp="2026-01-01T00:00:00Z")
    assert r["scan_timestamp"] == "2026-01-01T00:00:00Z"
    assert len(r["metadata"]) == 1
    assert len(r["findings"]) == 1
    assert r["summary"]["artifacts"] == 1
    assert r["summary"]["findings"] == 1


def test_format_size():
    assert "B" in format_size(0)
    assert "KB" in format_size(1024)
    assert "MB" in format_size(1024 * 1024)


def test_to_json():
    r = aggregate([], [], scan_timestamp="2026-01-01T00:00:00Z")
    out = to_json(r)
    data = json.loads(out)
    assert data["scan_timestamp"] == "2026-01-01T00:00:00Z"
    assert "metadata" in data
    assert "findings" in data
    assert "summary" in data


def test_to_text():
    r = aggregate(
        [{"path": "/x.apk", "type": "apk", "metadata": {"pkg": "com.test"}}],
        [],
        scan_timestamp="2026-01-01T00:00:00Z",
    )
    out = to_text(r)
    assert "Scan time:" in out
    assert "APK" in out
    assert "com.test" in out
    assert "Total:" in out


def test_to_text_with_finding():
    r = aggregate(
        [],
        [{"rule_id": "r1", "severity": "high", "message": "Bad", "source": "sast"}],
        scan_timestamp="2026-01-01T00:00:00Z",
    )
    out = to_text(r)
    assert "FINDINGS" in out
    assert "r1" in out
    assert "Bad" in out


def test_to_csv():
    r = aggregate(
        [],
        [{"rule_id": "r1", "severity": "high", "message": "M", "source": "sast", "location": {"file": "/p"}}],
        scan_timestamp="2026-01-01T00:00:00Z",
    )
    out = to_csv(r)
    assert "scan_timestamp" in out
    assert "rule_id" in out
    assert "source" in out
    assert "r1" in out


def test_to_html():
    r = aggregate(
        [{"path": "/a.apk", "type": "apk", "size_bytes": 1000, "metadata": {}}],
        [{"rule_id": "r1", "severity": "high", "message": "M", "source": "dynamic"}],
        scan_timestamp="2026-01-01T00:00:00Z",
    )
    out = to_html(r)
    assert "<!DOCTYPE html>" in out
    assert "Scan Report" in out
    assert "Artifacts" in out
    assert "Findings" in out
    assert "r1" in out
    assert "dynamic" in out


def test_to_sarif():
    r = aggregate(
        [],
        [{"rule_id": "dex-hardcoded-password", "severity": "high", "message": "Hardcoded creds"}],
        scan_timestamp="2026-01-01T00:00:00Z",
    )
    out = to_sarif(r, tool_name="test-tool")
    data = json.loads(out)
    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert len(data["runs"]) == 1
    assert data["runs"][0]["tool"]["driver"]["name"] == "test-tool"
    assert len(data["runs"][0]["results"]) == 1
    assert data["runs"][0]["results"][0]["ruleId"] == "dex-hardcoded-password"
