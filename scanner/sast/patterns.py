"""
Constrained string/regex detectors shared by APK/JAR/IPA/native SAST.

Prefer API/token-shaped matches over bare keyword hits. Vague tokens like
password/secret are low/info only (high false-positive rate).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Pattern, Tuple

# (compiled_pattern, rule_id, severity, message, masvs_id)
# Patterns match against lowercased ASCII strings unless noted.
RegexRule = Tuple[Pattern[str], str, str, str, Optional[str]]

# High-confidence secret formats (case-sensitive originals also checked via separate pass)
_SECRET_FORMAT_RULES: List[Tuple[Pattern[str], str, str, str, Optional[str]]] = [
    (
        re.compile(r"(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])"),
        "secret-aws-access-key",
        "high",
        "AWS access key id-like string (AKIA…).",
        "MASVS-AUTH-4",
    ),
    (
        re.compile(r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])"),
        "secret-google-api-key",
        "high",
        "Google API key-like string (AIza…).",
        "MASVS-AUTH-4",
    ),
    (
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "secret-private-key-pem",
        "high",
        "PEM private key block.",
        "MASVS-CRYPTO-1",
    ),
]

# Constrained API / crypto / WebView / trust heuristics (matched on lowercased text)
_CONSTRAINED_RULES: List[RegexRule] = [
    (
        re.compile(
            r"cipher\.getinstance\s*\(\s*[\"'][^\"']*"
            r"(des|desede|rc4|rc2|blowfish|aes/ecb|pbewithmd5)"
            r"[^\"']*[\"']",
            re.I,
        ),
        "dex-weak-cipher",
        "high",
        "Weak or deprecated Cipher.getInstance transformation (e.g. DES/ECB/RC4).",
        "MASVS-CRYPTO-2",
    ),
    (
        re.compile(r"messagedigest\.getinstance\s*\(\s*[\"']\s*(md5|sha-?1)\s*[\"']", re.I),
        "dex-weak-hash",
        "medium",
        "Weak MessageDigest algorithm (MD5/SHA-1).",
        "MASVS-CRYPTO-2",
    ),
    (
        re.compile(r"addjavascriptinterface\s*\(", re.I),
        "dex-webview-js-bridge",
        "high",
        "WebView addJavascriptInterface (JS bridge) usage.",
        "MASVS-PLATFORM-2",
    ),
    (
        re.compile(r"setjavascriptenabled\s*\(\s*true\s*\)", re.I),
        "dex-webview-js-enabled",
        "medium",
        "WebView setJavaScriptEnabled(true).",
        "MASVS-PLATFORM-2",
    ),
    (
        re.compile(r"setallowfileaccess\s*\(\s*true\s*\)", re.I),
        "dex-webview-file-access",
        "medium",
        "WebView setAllowFileAccess(true).",
        "MASVS-PLATFORM-2",
    ),
    (
        re.compile(
            r"(trustall(?:certs?|hostname)?|trustymanager|trustmanager\s*\[\s*\]\s*=|"
            r"x509trustmanager|checkservertrusted\s*\([^)]*\)\s*\{\s*\}|"
            r"allow_all_hostname_verifier|hostnameverifier[^\n]{0,40}return\s+true|"
            r"sslcontext\.init\s*\([^)]*null[^)]*\))",
            re.I,
        ),
        "dex-ssl-trust",
        "high",
        "Trust-all / disabled certificate validation heuristic.",
        "MASVS-NETWORK-2",
    ),
    (
        re.compile(r"usescleartexttraffic\s*=\s*[\"']?true", re.I),
        "apk-cleartext-traffic",
        "high",
        "usesCleartextTraffic=true in app config/strings.",
        "MASVS-NETWORK-1",
    ),
    (
        re.compile(
            r"cleartexttrafficpermitted\s*=\s*[\"']?true|cleartextpermitted\s*=\s*[\"']?true",
            re.I,
        ),
        "apk-cleartext-traffic",
        "high",
        "Network security config permits cleartext traffic.",
        "MASVS-NETWORK-1",
    ),
    (
        re.compile(r"https?://[a-z0-9][-a-z0-9.]*[a-z0-9](?::\d+)?(?:/[^\s\"'<>]*)?", re.I),
        "dex-cleartext",
        "medium",
        "Cleartext HTTP URL; prefer HTTPS.",
        "MASVS-NETWORK-1",
    ),
]

# Vague token heuristics — demoted severity (match lowercased)
_VAGUE_RULES: List[RegexRule] = [
    (
        re.compile(r"\bpassword\b"),
        "dex-hardcoded-password",
        "low",
        "Possible password/credential reference (low confidence; high FP).",
        "MASVS-AUTH-4",
    ),
    (
        re.compile(r"\bsecret\b"),
        "dex-hardcoded-secret",
        "info",
        "Possible secret reference (low confidence; high FP).",
        "MASVS-CRYPTO-1",
    ),
    (
        re.compile(r"\bapi[_-]?key\b"),
        "dex-hardcoded-apikey",
        "low",
        "Possible API key reference (low confidence unless format match).",
        "MASVS-AUTH-4",
    ),
    (
        re.compile(r"sharedpreferences|getsharedpreferences"),
        "dex-storage-sharedprefs",
        "info",
        "Uses SharedPreferences; ensure sensitive data is encrypted.",
        "MASVS-STORAGE-2",
    ),
    (
        re.compile(r"android\.util\.log|log\.[diewv]\s*\("),
        "dex-logging",
        "low",
        "Android Log usage; ensure no sensitive data in release.",
        "MASVS-PRIVACY-2",
    ),
]

# JAR-specific id remaps from dex-* style when scanning JAR
_JAR_ID_MAP = {
    "dex-hardcoded-password": "jar-hardcoded-password",
    "dex-hardcoded-secret": "jar-hardcoded-secret",
    "dex-hardcoded-apikey": "jar-hardcoded-apikey",
    "dex-cleartext": "jar-cleartext",
    "dex-ssl-trust": "jar-ssl-trust",
    "dex-weak-cipher": "jar-weak-crypto",
    "dex-weak-hash": "jar-weak-crypto",
    "secret-aws-access-key": "jar-secret-aws-access-key",
    "secret-google-api-key": "jar-secret-google-api-key",
    "secret-private-key-pem": "jar-secret-private-key-pem",
}

_IPA_ID_MAP = {
    "dex-hardcoded-password": "ipa-hardcoded-password",
    "dex-hardcoded-secret": "ipa-hardcoded-secret",
    "dex-hardcoded-apikey": "ipa-hardcoded-apikey",
    "dex-cleartext": "ipa-cleartext",
    "secret-aws-access-key": "ipa-secret-aws-access-key",
    "secret-google-api-key": "ipa-secret-google-api-key",
    "secret-private-key-pem": "ipa-secret-private-key-pem",
}


def scan_text_for_rules(
    text: str,
    *,
    id_map: Optional[Dict[str, str]] = None,
    include_vague: bool = True,
    http_only_cleartext: bool = True,
) -> List[Dict[str, Any]]:
    """
    Apply constrained (+ optional vague) rules to a single string.
    Returns finding dicts without location/source (caller fills those).
    """
    out: List[Dict[str, Any]] = []
    if not text:
        return out

    # High-confidence formats on original case
    for pat, rule_id, severity, message, masvs_id in _SECRET_FORMAT_RULES:
        if pat.search(text):
            rid = (id_map or {}).get(rule_id, rule_id)
            out.append(_finding(rid, severity, message, masvs_id, text))

    lower = text.lower()

    for pat, rule_id, severity, message, masvs_id in _CONSTRAINED_RULES:
        if rule_id == "dex-cleartext":
            # Only flag true http:// (not https://)
            if "http://" not in lower:
                continue
            # Skip common schema/docs noise
            m = re.search(r"http://[a-z0-9][-a-z0-9.]*[a-z0-9](?::\d+)?(?:/[^\s\"'<>]*)?", lower)
            if not m:
                continue
            host = m.group(0)
            if any(x in host for x in ("schemas.android.com", "www.w3.org", "xmlpull.org", "apache.org/xml")):
                continue
            if http_only_cleartext and not host.startswith("http://"):
                continue
            rid = (id_map or {}).get(rule_id, rule_id)
            out.append(_finding(rid, severity, message, masvs_id, text))
            continue
        if pat.search(lower) or pat.search(text):
            rid = (id_map or {}).get(rule_id, rule_id)
            out.append(_finding(rid, severity, message, masvs_id, text))

    if include_vague:
        for pat, rule_id, severity, message, masvs_id in _VAGUE_RULES:
            if pat.search(lower):
                rid = (id_map or {}).get(rule_id, rule_id)
                out.append(_finding(rid, severity, message, masvs_id, text))

    return out


def _finding(
    rule_id: str,
    severity: str,
    message: str,
    masvs_id: Optional[str],
    snippet: str,
) -> Dict[str, Any]:
    snip = snippet.replace("\n", " ")
    if len(snip) > 60:
        snip = snip[:60] + "..."
    return {
        "rule_id": rule_id,
        "severity": severity,
        "message": f"{message} (seen: {snip})",
        "masvs_id": masvs_id,
    }


def jar_id_map() -> Dict[str, str]:
    return dict(_JAR_ID_MAP)


def ipa_id_map() -> Dict[str, str]:
    return dict(_IPA_ID_MAP)
