"""Tests for optional plugins (skip if missing) and SCA extract/OSV (mocked)."""
from pathlib import Path
from unittest.mock import patch

from scanner.plugins import run_plugins
from scanner.plugins.semgrep_plugin import default_semgrep_config
from scanner.report import aggregate, build_sca_summary, to_html
from scanner.sca.extract import extract_components
from scanner.sca import run_sca
from scanner.taxonomy import enrich_finding, get_classification, get_remediation


def test_plugins_skip_when_tools_missing(tmp_path):
    apk = tmp_path / "x.apk"
    apk.write_bytes(b"PK\x03\x04")
    with patch("shutil.which", return_value=None):
        out = run_plugins(
            apk,
            "apk",
            {},
            apkid=True,
            semgrep=True,
            mobsfscan=True,
            quark=True,
            nuclei=True,
        )
    assert out == []


def test_default_semgrep_config_is_vendored_starter():
    cfg = default_semgrep_config()
    assert "android-mastg-starter.yml" in cfg.replace("\\", "/")
    assert Path(cfg).is_file()


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


def test_sca_summary_board_and_html():
    findings = [
        {
            "rule_id": "sca-osv-vuln",
            "severity": "high",
            "message": "OSV: commons-lang3@3.8 affected by CVE-2020-12345",
            "cve": ["CVE-2020-12345"],
            "evidence": {
                "package": "commons-lang3",
                "version": "3.8",
                "ecosystem": "Maven",
                "osv_id": "GHSA-test-xxxx",
            },
            "location": {"file": "commons-lang3-3.8.jar"},
        }
    ]
    enrich_finding(findings[0])
    comps = [{"name": "commons-lang3", "version": "3.8", "ecosystem": "Maven"}]
    board = build_sca_summary(findings, comps)
    assert board["vuln_count"] == 1
    assert board["vulnerabilities"][0]["cve"] == ["CVE-2020-12345"]
    assert board["inventory"][0]["component"] == "commons-lang3"
    r = aggregate([], findings, sca_components=comps)
    assert r["summary"]["sca"]["cve_count"] == 1
    html = to_html(r)
    assert "SCA / OSV board" in html
    assert "CVE-2020-12345" in html
    assert "commons-lang3" in html


def test_sca_and_plugin_taxonomy():
    assert get_classification("sca-osv-vuln")["cwe"]
    assert get_classification("plugin-apkid-tag")["maswe"]
    assert get_classification("plugin-quark-behavior")["maswe"]
    assert get_classification("plugin-nuclei-android")["maswe"]
    assert get_classification("dex-runtime-exec")["maswe"]
    assert get_classification("apk-exported-intent-risk")["owasp_mobile"]
    assert "Quark" in get_remediation("plugin-quark-behavior")["remediation"]
    assert "nuclei" in get_remediation("plugin-nuclei-android")["remediation"].lower()
