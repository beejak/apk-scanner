"""DAST Android unit tests — no adb/device required (skip path)."""
from pathlib import Path
from unittest.mock import patch

from scanner.dast.android import run_android_dast, _default_frida_script


def test_dast_skips_without_adb(tmp_path):
    apk = tmp_path / "a.apk"
    apk.write_bytes(b"PK\x03\x04")
    with patch("scanner.dast.android._has_adb", return_value=False):
        out = run_android_dast(apk, {"package": "com.example"})
    assert out == []


def test_dast_skips_without_package(tmp_path):
    apk = tmp_path / "a.apk"
    apk.write_bytes(b"PK\x03\x04")
    out = run_android_dast(apk, {})
    assert out == []


def test_frida_script_has_observation_hooks_only():
    js = _default_frida_script()
    assert "SSLContext" in js
    assert "sensitive_log" in js
    assert "cleartext_url" in js
    # No pinning-bypass / weaponization helpers
    assert "sslunpinning" not in js.lower()
    assert "bypass" not in js.lower()
