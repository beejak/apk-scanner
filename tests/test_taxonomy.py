"""Tests for scanner.taxonomy: get_classification, enrich_finding, classification_short, classification_for_csv."""
import pytest
from scanner.taxonomy import (
    classification_for_csv,
    classification_short,
    enrich_finding,
    get_classification,
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
