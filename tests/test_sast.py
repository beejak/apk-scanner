"""SAST unit tests on synthetic ZIP/JAR/plist fixtures (no APK binaries in git)."""
import builtins
import io
import plistlib
import sys
import zipfile
from pathlib import Path

from scanner.metadata import extract
from scanner.metadata.so import _extract_so_fallback, extract_so
from scanner.sast import run_sast
from scanner.sast.patterns import scan_text_for_rules
from scanner.taxonomy import get_classification


def _zip_bytes(entries: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_patterns_weak_cipher_and_webview():
    hits = scan_text_for_rules('Cipher.getInstance("AES/ECB/PKCS5Padding")')
    assert any(h["rule_id"] == "dex-weak-cipher" for h in hits)

    hits2 = scan_text_for_rules("webview.addJavascriptInterface(bridge, \"Android\")")
    assert any(h["rule_id"] == "dex-webview-js-bridge" for h in hits2)

    hits3 = scan_text_for_rules("TrustAllCerts implements X509TrustManager")
    assert any(h["rule_id"] == "dex-ssl-trust" for h in hits3)


def test_patterns_high_confidence_secrets_and_vague_demoted():
    aws = scan_text_for_rules("key=AKIAIOSFODNN7EXAMPLE")
    assert any(h["rule_id"] == "secret-aws-access-key" and h["severity"] == "high" for h in aws)

    google = scan_text_for_rules("AIzaSyDummyGoogleApiKey0123456789ABCDEF")
    assert any(h["rule_id"] == "secret-google-api-key" for h in google)

    vague = scan_text_for_rules("this mentions password in a comment")
    pw = [h for h in vague if h["rule_id"] == "dex-hardcoded-password"]
    assert pw and pw[0]["severity"] == "low"

    secret = scan_text_for_rules("user secret storage helper")
    sec = [h for h in secret if h["rule_id"] == "dex-hardcoded-secret"]
    assert sec and sec[0]["severity"] == "info"


def test_patterns_cleartext_skips_android_schemas():
    hits = scan_text_for_rules("http://schemas.android.com/apk/res/android")
    assert not any(h["rule_id"] == "dex-cleartext" for h in hits)
    hits2 = scan_text_for_rules("http://evil.example.com/api/login")
    assert any(h["rule_id"] == "dex-cleartext" for h in hits2)


def test_metadata_exported_unprotected_only():
    path = Path("dummy.apk")
    meta = {
        "activities": [
            {"name": ".Open", "exported": True, "permission": None},
            {"name": ".Guarded", "exported": True, "permission": "com.example.PERM"},
            {"name": ".Private", "exported": False, "permission": None},
            {"name": ".OpenStr", "exported": "true", "permission": None},
            {"name": ".ClosedStr", "exported": "false", "permission": None},
        ],
        "services": [],
        "receivers": [],
        "providers": [],
        "debuggable": "true",
        "allow_backup": "true",
    }
    findings = run_sast(path, "apk", meta)
    exported = [f for f in findings if f["rule_id"] == "apk-exported-unprotected"]
    assert len(exported) == 2
    assert any(".Open" in f["message"] for f in exported)
    assert any(".OpenStr" in f["message"] for f in exported)
    assert any(f["rule_id"] == "apk-debuggable" for f in findings)
    assert any(f["rule_id"] == "apk-allow-backup" for f in findings)
    assert get_classification("apk-exported-unprotected")["cwe"]


def test_metadata_cleartext_flag():
    findings = run_sast(Path("x.apk"), "apk", {"uses_cleartext_traffic": True})
    assert any(f["rule_id"] == "apk-cleartext-traffic" for f in findings)


def test_synthetic_apk_zip_dex_strings(tmp_path):
    """Tiny ZIP posing as APK with a .dex blob containing ASCII rule bait."""
    bait = (
        b"XXXXXXXXCipher.getInstance(\"DES\")XXXXXXXX"
        b"XXXXXXaddJavascriptInterface(obj)XXXXXX"
        b"XXXXXXhttp://evil.example.com/loginXXXXXX"
        b"XXXXXX key=AKIAIOSFODNN7EXAMPLE; XXXXXX"
        b"XXXXXXTrustAllCertsXXXXXX"
    )
    apk = tmp_path / "synthetic.apk"
    apk.write_bytes(
        _zip_bytes({
            "AndroidManifest.xml": b"<manifest/>",
            "classes.dex": bait,
            "res/xml/network_security_config.xml": (
                b"<network-security-config>"
                b'<base-config cleartextTrafficPermitted="true"/>'
                b"</network-security-config>"
            ),
        })
    )
    findings = run_sast(apk, "apk", {"has_android_manifest": True})
    ids = {f["rule_id"] for f in findings}
    assert "dex-weak-cipher" in ids
    assert "dex-webview-js-bridge" in ids
    assert "dex-cleartext" in ids
    assert "secret-aws-access-key" in ids
    assert "apk-cleartext-traffic" in ids
    assert "dex-ssl-trust" in ids


def test_synthetic_jar_rules(tmp_path):
    jar = tmp_path / "bait.jar"
    props = (
        "url=http://evil.example.com/api\n"
        'Cipher.getInstance("AES/ECB/PKCS5Padding")\n'
        "key=AKIAIOSFODNN7EXAMPLE\n"
    ).encode()
    jar.write_bytes(_zip_bytes({"config.properties": props, "Dummy.class": props}))
    findings = run_sast(jar, "jar", {})
    ids = {f["rule_id"] for f in findings}
    assert "jar-cleartext" in ids
    assert "jar-weak-crypto" in ids
    assert "jar-secret-aws-access-key" in ids


def test_synthetic_ipa_plist_ats(tmp_path):
    info = {
        "CFBundleIdentifier": "com.example.insecure",
        "NSAppTransportSecurity": {
            "NSAllowsArbitraryLoads": True,
            "NSExceptionDomains": {
                "evil.example.com": {"NSExceptionAllowsInsecureHTTPLoads": True},
            },
        },
    }
    ipa = tmp_path / "bait.ipa"
    ipa.write_bytes(
        _zip_bytes({
            "Payload/Bait.app/Info.plist": plistlib.dumps(info),
            "Payload/Bait.app/Bait": b"XXXXXXhttp://evil.example.com/apiXXXXXX",
        })
    )
    findings = run_sast(ipa, "ipa", {})
    ids = {f["rule_id"] for f in findings}
    assert "ipa-allow-arbitrary-loads" in ids
    assert "ipa-exception-insecure-http" in ids


def test_so_fallback_helper(tmp_path):
    so = tmp_path / "libdummy.so"
    so.write_bytes(b"\x7fELF" + b"\x00" * 64)
    out = _extract_so_fallback(so)
    assert out["size_bytes"] == so.stat().st_size
    assert "pyelftools" in out["note"].lower()


def test_so_extract_uses_fallback_on_import_error(tmp_path, monkeypatch):
    so = tmp_path / "libdummy.so"
    so.write_bytes(b"\x7fELF" + b"\x00" * 32)

    real_import = builtins.__import__

    def guarded(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "elftools" or (isinstance(name, str) and name.startswith("elftools.")):
            raise ImportError("forced for test")
        return real_import(name, globals, locals, fromlist, level)

    saved = {k: sys.modules.pop(k) for k in list(sys.modules) if k.startswith("elftools")}
    monkeypatch.setattr(builtins, "__import__", guarded)
    try:
        out = extract_so(so)
        assert out.get("size_bytes") == so.stat().st_size
        assert "note" in out
        out2 = extract(so, "so")
        assert out2.get("size_bytes") == so.stat().st_size
        assert "error" not in out2 or out2.get("note")
    finally:
        sys.modules.update(saved)


def test_new_rule_ids_in_taxonomy():
    for rid in (
        "apk-exported-unprotected",
        "apk-cleartext-traffic",
        "dex-weak-cipher",
        "dex-webview-js-bridge",
        "secret-aws-access-key",
        "secret-google-api-key",
        "ipa-exception-insecure-http",
    ):
        c = get_classification(rid)
        assert c["cwe"], rid
