"""Tests for scanner.report: aggregate, to_text, to_json, to_csv, to_html, to_sarif."""
import json
import pytest
from scanner.report import (
    aggregate,
    format_size,
    reenrich_report,
    to_csv,
    to_html,
    to_json,
    to_sarif,
    to_text,
)
from scanner.taxonomy import enrich_finding


def test_aggregate_empty():
    r = aggregate([], [])
    assert r["scan_timestamp"]
    assert r["metadata"] == []
    assert r["findings"] == []
    assert r["summary"]["artifacts"] == 0
    assert r["summary"]["findings"] == 0
    assert r["summary"]["by_severity"]["high"] == 0
    assert r["summary"]["max_severity_score"] == 0.0
    assert r["summary"]["avg_severity_score"] == 0.0


def test_aggregate_with_metadata_and_findings():
    meta = [{"path": "/a.apk", "type": "apk", "metadata": {}}]
    findings = [{"rule_id": "apk-debuggable", "severity": "high", "message": "msg"}]
    enrich_finding(findings[0])
    r = aggregate(meta, findings, scan_timestamp="2026-01-01T00:00:00Z")
    assert r["scan_timestamp"] == "2026-01-01T00:00:00Z"
    assert len(r["metadata"]) == 1
    assert len(r["findings"]) == 1
    assert r["summary"]["artifacts"] == 1
    assert r["summary"]["findings"] == 1
    assert r["summary"]["by_severity"]["high"] == 1
    assert r["summary"]["max_severity_score"] > 0


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
    f = {"rule_id": "apk-debuggable", "severity": "high", "message": "Bad", "source": "sast"}
    enrich_finding(f)
    r = aggregate([], [f], scan_timestamp="2026-01-01T00:00:00Z")
    out = to_text(r)
    assert "FINDINGS" in out
    assert "apk-debuggable" in out
    assert "Bad" in out
    assert "Remediation:" in out
    assert "Revalidate:" in out
    assert "score=" in out


def test_to_csv():
    f = {
        "rule_id": "apk-debuggable",
        "severity": "high",
        "message": "M",
        "source": "sast",
        "location": {"file": "/p"},
    }
    enrich_finding(f)
    r = aggregate([], [f], scan_timestamp="2026-01-01T00:00:00Z")
    out = to_csv(r)
    assert "scan_timestamp" in out
    assert "rule_id" in out
    assert "severity_score" in out
    assert "remediation" in out
    assert "revalidate" in out
    assert "apk-debuggable" in out


def test_to_html():
    f = {"rule_id": "apk-debuggable", "severity": "high", "message": "M", "source": "dynamic"}
    enrich_finding(f)
    r = aggregate(
        [{"path": "/a.apk", "type": "apk", "size_bytes": 1000, "metadata": {}}],
        [f],
        scan_timestamp="2026-01-01T00:00:00Z",
    )
    out = to_html(r)
    assert "<!DOCTYPE html>" in out
    assert "Scan Report" in out
    assert "Artifacts" in out
    assert "Findings" in out
    assert "apk-debuggable" in out
    assert "dynamic" in out
    assert "How to fix" in out
    assert "How to revalidate" in out
    assert "CVSS-estimate" in out
    assert "Severity score" in out
    assert "<style>" in out


def test_to_sarif():
    f = {
        "rule_id": "dex-hardcoded-password",
        "severity": "high",
        "message": "Hardcoded creds",
        "location": {"file": "app.apk", "line": None},
    }
    enrich_finding(f)
    r = aggregate([], [f], scan_timestamp="2026-01-01T00:00:00Z")
    out = to_sarif(r, tool_name="test-tool")
    data = json.loads(out)
    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert len(data["runs"]) == 1
    assert data["runs"][0]["tool"]["driver"]["name"] == "test-tool"
    assert len(data["runs"][0]["results"]) == 1
    result = data["runs"][0]["results"][0]
    assert result["ruleId"] == "dex-hardcoded-password"
    assert result["locations"]
    props = result["properties"]
    assert "severity_score" in props
    assert "remediation" in props
    rule = data["runs"][0]["tool"]["driver"]["rules"][0]
    assert "help" in rule
    assert "Revalidate" in rule["help"]["text"] or "remediation" in rule["help"]["text"].lower() or rule["help"]["text"]
    assert data["runs"][0].get("taxonomies")


def test_reenrich_report():
    f = {"rule_id": "apk-debuggable", "severity": "high", "message": "dbg"}
    r = {
        "scan_timestamp": "2026-01-01T00:00:00Z",
        "metadata": [],
        "findings": [f],
        "summary": {"artifacts": 0, "findings": 1},
    }
    reenrich_report(r)
    assert r["findings"][0]["severity_score"] is not None
    assert r["findings"][0]["remediation"]
    assert "by_severity" in r["summary"]
    assert r["summary"]["max_severity_score"] > 0
