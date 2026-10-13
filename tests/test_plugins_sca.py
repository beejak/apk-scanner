"""Tests for optional plugins (skip if missing) and SCA extract/OSV (mocked)."""
from pathlib import Path
from unittest.mock import patch

from scanner.plugins import run_plugins
from scanner.sca.extract import extract_components
from scanner.sca import run_sca
from scanner.taxonomy import enrich_finding, get_classification


def test_plugins_skip_when_tools_missing(tmp_path):
    apk = tmp_path / "x.apk"
    apk.write_bytes(b"PK\x03\x04")
    with patch("shutil.which", return_value=None):
        out = run_plugins(apk, "apk", {}, apkid=True, semgrep=True, mobsfscan=True)
    assert out == []


def test_extract_components_from_jar_name(tmp_path):
    jar = tmp_path / "gson-2.8.9.jar"
    jar.write_bytes(b"PK\x03\x04")
    comps = extract_components(jar, "jar", {})
    assert any(c["name"] == "gson" and c["version"] == "2.8.9" for c in comps)


def test_run_sca_offline_skips(tmp_path):
    jar = tmp_path / "gson-2.8.9.jar"
    jar.write_bytes(b"PK\x03\x04")
    out = run_sca(jar, "jar", {}, enabled=True, offline=True)
    assert out == []


def test_run_sca_uses_osv_and_never_invents(tmp_path):
    jar = tmp_path / "commons-lang3-3.8.jar"
    jar.write_bytes(b"PK\x03\x04")
    fake = [
        {
            "id": "GHSA-test-xxxx",
            "aliases": ["CVE-2020-12345"],
            "summary": "test vuln",
            "database_specific": {"severity": "HIGH"},
        }
    ]
    with patch("scanner.sca.osv.query_osv", return_value=fake):
        out = run_sca(jar, "jar", {}, enabled=True, offline=False)
    assert len(out) == 1
    assert out[0]["rule_id"] == "sca-osv-vuln"
    assert out[0]["cve"] == ["CVE-2020-12345"]
    assert "CVE-2020-12345" in out[0]["message"]
    enrich_finding(out[0])
    assert out[0]["cve"] == ["CVE-2020-12345"]


def test_sca_and_plugin_taxonomy():
    assert get_classification("sca-osv-vuln")["cwe"]
    assert get_classification("plugin-apkid-tag")["maswe"]
    assert get_classification("dex-runtime-exec")["maswe"]
    assert get_classification("apk-exported-intent-risk")["owasp_mobile"]
