"""
Constrained string/regex detectors shared by APK/JAR/IPA/native SAST.

Prefer API/token-shaped matches over bare keyword hits. Vague tokens like
password/secret are info-only unless assignment-shaped (still low).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Pattern, Tuple

# (compiled_pattern, rule_id, severity, message, masvs_id)
RegexRule = Tuple[Pattern[str], str, str, str, Optional[str]]

# High-confidence secret formats (case-sensitive originals also checked via separate pass)
_SECRET_FORMAT_RULES: List[Tuple[Pattern[str], str, str, str, Optional[str]]] = [
    (
        re.compile(r"(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])"),
        "secret-aws-access-key",
        "critical",
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
        "critical",
        "PEM private key block.",
        "MASVS-CRYPTO-1",
    ),
]

# Constrained API / crypto / WebView / trust / injection heuristics (matched on lowercased text)
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
        "critical",
        "WebView addJavascriptInterface (JS bridge) — high-impact if content is untrusted.",
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
            r"setallow(?:universalaccessfromfileurls|fileaccessfromfileurls)\s*\(\s*true\s*\)",
            re.I,
        ),
        "dex-webview-file-uri",
        "high",
        "WebView allows file:// / universal access from file URLs.",
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
        "critical",
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
    (
        re.compile(
            r"(?:rawquery|execsql|sqliteDatabase\.query)\s*\([^)]*"
            r"(?:\+|concat|string\.format|stringbuilder)",
            re.I,
        ),
        "dex-sql-concat",
        "high",
        "SQL query built with string concat / format (injection lead).",
        "MASVS-CODE-2",
    ),
    (
        re.compile(
            r"contentresolver\.(?:query|insert|update|delete)\s*\(|"
            r"content://[a-z0-9_.]+/",
            re.I,
        ),
        "dex-content-provider-access",
        "medium",
        "ContentProvider / ContentResolver access pattern.",
        "MASVS-PLATFORM-1",
    ),
    (
        re.compile(
            r"objectinputstream\s*\(|readobject\s*\(\s*\)|"
            r"objectmapper\.enabledefaulttyping|"
            r"json\.parseobject\s*\([^)]*Feature\.SupportAutoType|"
            r"yaml\.load\s*\(",
            re.I,
        ),
        "dex-unsafe-deserialization",
        "high",
        "Unsafe deserialization / polymorphic typing heuristic.",
        "MASVS-CODE-4",
    ),
    (
        re.compile(
            r"(?:\.\./|\.\.\\|file:///)|"
            r"new\s+file\s*\([^)]*(?:\+|concat)|"
            r"getexternal(?:storage|files)dir",
            re.I,
        ),
        "dex-path-traversal",
        "high",
        "Path traversal / file URI / external-storage path heuristic.",
        "MASVS-CODE-2",
    ),
    (
        re.compile(
            r"runtime\.getruntime\s*\(\s*\)\s*\.exec\s*\(|"
            r"processbuilder\s*\(",
            re.I,
        ),
        "dex-runtime-exec",
        "critical",
        "Runtime.exec / ProcessBuilder — command execution surface.",
        "MASVS-CODE-4",
    ),
]

# Vague token heuristics — heavily demoted (match lowercased)
_VAGUE_RULES: List[RegexRule] = [
    (
        # Assignment-shaped only at low; bare "password" word → info via separate pattern below
        re.compile(
            r"(?:password|passwd|pwd)\s*[:=]\s*[\"'][^\"']{3,}[\"']",
            re.I,
        ),
        "dex-hardcoded-password",
        "low",
        "Assignment-shaped password literal (still low confidence; may be UI/test).",
        "MASVS-AUTH-4",
    ),
    (
        re.compile(r"\bpassword\b"),
        "dex-hardcoded-password",
        "info",
        "Bare password token (info only; high FP — not a credential finding).",
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
        "info",
        "Possible API key reference (info unless format match).",
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
        "info",
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
    "dex-sql-concat": "jar-sql-concat",
    "dex-unsafe-deserialization": "jar-unsafe-deserialization",
    "dex-path-traversal": "jar-path-traversal",
    "dex-runtime-exec": "jar-runtime-exec",
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
        vague_hits: List[Dict[str, Any]] = []
        for pat, rule_id, severity, message, masvs_id in _VAGUE_RULES:
            if pat.search(lower) or pat.search(text):
                rid = (id_map or {}).get(rule_id, rule_id)
                vague_hits.append(_finding(rid, severity, message, masvs_id, text))
        # Prefer assignment-shaped password over bare token (avoid double noise)
        has_assign_pw = any(
            h["rule_id"] in ("dex-hardcoded-password", "jar-hardcoded-password", "ipa-hardcoded-password")
            and h["severity"] == "low"
            for h in vague_hits
        )
        for h in vague_hits:
            if (
                has_assign_pw
                and h["rule_id"]
                in ("dex-hardcoded-password", "jar-hardcoded-password", "ipa-hardcoded-password")
                and h["severity"] == "info"
            ):
                continue
            out.append(h)

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
