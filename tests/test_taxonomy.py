"""Tests for scanner.taxonomy: classification, severity_score, CVSS-estimate, remediation."""
import pytest
from scanner.taxonomy import (
    TAXONOMY,
    classification_for_csv,
    classification_short,
    compute_severity_score,
    enrich_finding,
    get_classification,
    get_cvss_estimate,
    get_remediation,
    rule_weight,
)


def test_get_classification_known():
    c = get_classification("dex-hardcoded-password")
    assert "cwe" in c
    assert any("CWE-798" in str(e) for e in c["cwe"])
    assert "nist" in c
    assert "owasp" in c


def test_get_classification_unknown():
    c = get_classification("unknown-rule-xyz")
    assert c["cwe"] == []
    assert c["nist"] == []
    assert c["owasp"] == []


def test_enrich_finding():
    f = {"rule_id": "dex-cleartext", "severity": "medium", "message": "HTTP"}
    enrich_finding(f)
    assert "classification" in f
    assert f["classification"]["cwe"]
    assert f["classification"]["owasp"]
    assert isinstance(f["severity_score"], float)
    assert 0.0 <= f["severity_score"] <= 10.0
    assert f["cvss_estimate"]["note"]
    assert "not NVD" in f["cvss_estimate"]["note"]
    assert f["remediation"]
    assert f["revalidate"]
    assert f["cve"] is None


def test_severity_score_mapping():
    high = compute_severity_score("high", "apk-debuggable")
    med = compute_severity_score("medium", "apk-allow-backup")
    low = compute_severity_score("low", "dex-hardcoded-password")
    info = compute_severity_score("info", "so-jni")
    assert high > med > low > info
    assert high == round(8.0 * rule_weight("apk-debuggable"), 1)
    assert 0.0 <= info <= 10.0
    # High-confidence secret formats weight above band base
    aws = compute_severity_score("high", "secret-aws-access-key")
    assert aws >= compute_severity_score("high", "apk-allow-backup")


def test_remediation_present_for_known_rules():
    sample = [
        "apk-debuggable",
        "apk-allow-backup",
        "apk-exported-unprotected",
        "dex-ssl-trust",
        "dex-cleartext",
        "secret-aws-access-key",
        "dex-hardcoded-password",
        "dast-android-ssl-trust-all",
    ]
    for rid in sample:
        assert rid in TAXONOMY or rid.startswith("dast-")
        help_map = get_remediation(rid)
        assert help_map["remediation"], rid
        assert help_map["revalidate"], rid
        rev = help_map["revalidate"].lower()
        assert any(x in rev for x in ("cli.py", "re-scan", "re-run", "--sast", "--dynamic")), rid


def test_cvss_estimate_honest():
    est = get_cvss_estimate("dex-ssl-trust", "high")
    assert "score" in est and "vector" in est
    assert "rule-based" in est["note"].lower() or "not NVD" in est["note"]


def test_classification_short():
    f = {"rule_id": "dex-hardcoded-apikey"}
    s = classification_short(f)
    assert "CWE" in s or "—" == s
    f2 = {"rule_id": "unknown"}
    s2 = classification_short(f2)
    assert s2 == "—"


def test_classification_for_csv():
    f = {"rule_id": "dex-ssl-trust", "classification": None}
    enrich_finding(f)
    row = classification_for_csv(f)
    assert "cwe" in row
    assert "nist" in row
    assert "owasp" in row
    assert "capec" in row
    assert "cisa" in row
    assert "nsa" in row
