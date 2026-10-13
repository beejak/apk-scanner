"""
MASWE v1 + OWASP Mobile Top 10 2024 helpers for rule_id enrichment.

Honest packaging: these are lookup labels after a finding exists; they do not
deepen detection. IDs follow public OWASP MASWE / Mobile Top 10 2024 naming.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

# OWASP Mobile Top 10 (2024) short entries
_M2024 = {
    "M1": ("M1:2024", "Improper Credential Usage", "https://owasp.org/www-project-mobile-top-10/"),
    "M2": ("M2:2024", "Inadequate Supply Chain Security", "https://owasp.org/www-project-mobile-top-10/"),
    "M3": ("M3:2024", "Insecure Authentication/Authorization", "https://owasp.org/www-project-mobile-top-10/"),
    "M4": ("M4:2024", "Insufficient Input/Output Validation", "https://owasp.org/www-project-mobile-top-10/"),
    "M5": ("M5:2024", "Insecure Communication", "https://owasp.org/www-project-mobile-top-10/"),
    "M6": ("M6:2024", "Inadequate Privacy Controls", "https://owasp.org/www-project-mobile-top-10/"),
    "M7": ("M7:2024", "Insufficient Binary Protections", "https://owasp.org/www-project-mobile-top-10/"),
    "M8": ("M8:2024", "Security Misconfiguration", "https://owasp.org/www-project-mobile-top-10/"),
    "M9": ("M9:2024", "Insecure Data Storage", "https://owasp.org/www-project-mobile-top-10/"),
    "M10": ("M10:2024", "Insufficient Cryptography", "https://owasp.org/www-project-mobile-top-10/"),
}

MASWE_URL = "https://mas.owasp.org/MASWE/"


def _maswe(mid: str, label: str) -> Dict[str, str]:
    return {"id": mid, "label": label, "url": MASWE_URL}


def _m2024(key: str) -> Dict[str, str]:
    eid, label, url = _M2024[key]
    return {"id": eid, "label": label, "url": url}


# Family key (after prefix strip) → (maswe entries, mobile top10 keys)
_FAMILY_MASWE: Dict[str, Tuple[List[Dict[str, str]], List[str]]] = {
    "hardcoded-password": ([_maswe("MASWE-0001", "Hardcoded credentials")], ["M1"]),
    "hardcoded-apikey": ([_maswe("MASWE-0001", "Hardcoded credentials")], ["M1"]),
    "hardcoded-secret": ([_maswe("MASWE-0001", "Hardcoded credentials"), _maswe("MASWE-0028", "Hardcoded crypto material")], ["M1", "M10"]),
    "aws-access-key": ([_maswe("MASWE-0001", "Hardcoded credentials")], ["M1"]),
    "google-api-key": ([_maswe("MASWE-0001", "Hardcoded credentials")], ["M1"]),
    "private-key-pem": ([_maswe("MASWE-0028", "Hardcoded crypto material")], ["M1", "M10"]),
    "cleartext": ([_maswe("MASWE-0050", "Cleartext traffic")], ["M5"]),
    "cleartext-traffic": ([_maswe("MASWE-0050", "Cleartext traffic")], ["M5"]),
    "ssl-trust": ([_maswe("MASWE-0051", "Improper certificate validation")], ["M5"]),
    "ssl-trust-all": ([_maswe("MASWE-0051", "Improper certificate validation")], ["M5"]),
    "logging": ([_maswe("MASWE-0063", "Sensitive data in logs")], ["M6"]),
    "storage-sharedprefs": ([_maswe("MASWE-0013", "Insecure local storage")], ["M9"]),
    "debuggable": ([_maswe("MASWE-0090", "Debuggable release")], ["M7"]),
    "allow-backup": ([_maswe("MASWE-0014", "Backup exposure")], ["M9"]),
    "exported-component": ([_maswe("MASWE-0070", "Exported component")], ["M8"]),
    "exported-unprotected": ([_maswe("MASWE-0070", "Exported component"), _maswe("MASWE-0071", "Unprotected IPC")], ["M8", "M3"]),
    "exported-intent-risk": ([_maswe("MASWE-0071", "Unprotected IPC / intent")], ["M8", "M3"]),
    "exported-provider-unprotected": ([_maswe("MASWE-0072", "Exported ContentProvider")], ["M8", "M9"]),
    "weak-cipher": ([_maswe("MASWE-0026", "Weak cryptography")], ["M10"]),
    "weak-hash": ([_maswe("MASWE-0026", "Weak cryptography")], ["M10"]),
    "weak-crypto": ([_maswe("MASWE-0026", "Weak cryptography")], ["M10"]),
    "webview-js-bridge": ([_maswe("MASWE-0075", "WebView JavaScript bridge")], ["M8", "M4"]),
    "webview-js-enabled": ([_maswe("MASWE-0075", "WebView JavaScript")], ["M8"]),
    "webview-file-access": ([_maswe("MASWE-0076", "WebView file access")], ["M8"]),
    "webview-file-uri": ([_maswe("MASWE-0076", "WebView file URI access")], ["M8", "M4"]),
    "sql-concat": ([_maswe("MASWE-0040", "SQL injection via concat")], ["M4"]),
    "content-provider-access": ([_maswe("MASWE-0072", "ContentProvider access")], ["M8"]),
    "unsafe-deserialization": ([_maswe("MASWE-0042", "Unsafe deserialization")], ["M4"]),
    "path-traversal": ([_maswe("MASWE-0041", "Path traversal / file URI")], ["M4"]),
    "runtime-exec": ([_maswe("MASWE-0043", "OS command execution")], ["M4"]),
    "allow-arbitrary-loads": ([_maswe("MASWE-0050", "Cleartext / ATS bypass")], ["M5"]),
    "allow-local-networking": ([_maswe("MASWE-0050", "Cleartext / local networking")], ["M5"]),
    "exception-insecure-http": ([_maswe("MASWE-0050", "Insecure HTTP exception")], ["M5"]),
    "file-sharing": ([_maswe("MASWE-0013", "File sharing exposure")], ["M9"]),
    "documents-in-place": ([_maswe("MASWE-0013", "Document access")], ["M9"]),
    "sensitive-file": ([_maswe("MASWE-0001", "Sensitive files in package")], ["M1", "M2"]),
    "exposed-credential": ([_maswe("MASWE-0001", "Exposed credentials")], ["M1", "M2"]),
    "jni": ([_maswe("MASWE-0080", "JNI / native boundary")], ["M7"]),
    "sensitive-log": ([_maswe("MASWE-0063", "Sensitive data in logs")], ["M6"]),
    "cleartext-observed": ([_maswe("MASWE-0050", "Cleartext observed at runtime")], ["M5"]),
}


def family_maswe_mobile(family: str) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    """Return (maswe list, owasp_mobile_2024 list) for a rule family key."""
    entry = _FAMILY_MASWE.get(family)
    if not entry:
        return [], []
    maswe, keys = entry
    mobile = [_m2024(k) for k in keys if k in _M2024]
    return list(maswe), mobile


# Full taxonomy blobs for new high-impact rules (merged into TAXONOMY).
NEW_RULE_TAXONOMY: Dict[str, Dict[str, List[Dict[str, str]]]] = {
    "apk-exported-intent-risk": {
        "cwe": [{"id": "CWE-926", "label": "Improper export of Android component", "url": "https://cwe.mitre.org/data/definitions/926.html"}],
        "nist": [{"id": "AC-4", "label": "Information flow enforcement"}],
        "owasp": [
            {"id": "MASVS-PLATFORM-1", "label": "Platform interaction / exported components"},
            _m2024("M8"),
            _m2024("M3"),
        ],
        "capec": [{"id": "CAPEC-180", "label": "Exploiting software via component vulnerability"}],
        "cisa": [{"id": "LeastPriv", "label": "Protect exported components"}],
        "nsa": [{"id": "MobileApp", "label": "Secure IPC and exports (NSA)"}],
        "maswe": [_maswe("MASWE-0071", "Unprotected IPC / intent")],
    },
    "apk-exported-provider-unprotected": {
        "cwe": [
            {"id": "CWE-926", "label": "Improper export of Android component"},
            {"id": "CWE-200", "label": "Information exposure"},
        ],
        "nist": [{"id": "AC-4", "label": "Information flow enforcement"}, {"id": "SC-28", "label": "Protection of information at rest"}],
        "owasp": [
            {"id": "MASVS-PLATFORM-1", "label": "Platform interaction"},
            _m2024("M8"),
            _m2024("M9"),
        ],
        "capec": [{"id": "CAPEC-180", "label": "Exploiting component vulnerability"}],
        "cisa": [{"id": "LeastPriv", "label": "Protect ContentProviders"}],
        "nsa": [{"id": "MobileApp", "label": "Secure providers (NSA)"}],
        "maswe": [_maswe("MASWE-0072", "Exported ContentProvider")],
    },
    "dex-webview-file-uri": {
        "cwe": [{"id": "CWE-22", "label": "Path traversal"}, {"id": "CWE-79", "label": "XSS"}],
        "nist": [{"id": "AC-4", "label": "Information flow enforcement"}],
        "owasp": [{"id": "MASVS-PLATFORM-2", "label": "WebView hardening"}, _m2024("M8"), _m2024("M4")],
        "capec": [{"id": "CAPEC-126", "label": "Path Traversal"}],
        "cisa": [{"id": "LeastPriv", "label": "Restrict WebView file access"}],
        "nsa": [{"id": "MobileApp", "label": "Harden WebView (NSA)"}],
        "maswe": [_maswe("MASWE-0076", "WebView file URI access")],
    },
    "dex-sql-concat": {
        "cwe": [{"id": "CWE-89", "label": "SQL injection", "url": "https://cwe.mitre.org/data/definitions/89.html"}],
        "nist": [{"id": "SI-10", "label": "Information input validation"}],
        "owasp": [{"id": "MASVS-CODE-2", "label": "Injection / data processing"}, _m2024("M4")],
        "capec": [{"id": "CAPEC-66", "label": "SQL Injection"}],
        "cisa": [{"id": "InputVal", "label": "Parameterized queries"}],
        "nsa": [{"id": "AppSec", "label": "Prevent injection (NSA)"}],
        "maswe": [_maswe("MASWE-0040", "SQL injection via concat")],
    },
    "jar-sql-concat": {
        "cwe": [{"id": "CWE-89", "label": "SQL injection"}],
        "nist": [{"id": "SI-10", "label": "Information input validation"}],
        "owasp": [{"id": "MASVS-CODE-2", "label": "Injection"}, _m2024("M4")],
        "capec": [{"id": "CAPEC-66", "label": "SQL Injection"}],
        "cisa": [{"id": "InputVal", "label": "Parameterized queries"}],
        "nsa": [{"id": "AppSec", "label": "Prevent injection (NSA)"}],
        "maswe": [_maswe("MASWE-0040", "SQL injection via concat")],
    },
    "dex-content-provider-access": {
        "cwe": [{"id": "CWE-926", "label": "Improper export / IPC"}, {"id": "CWE-200", "label": "Information exposure"}],
        "nist": [{"id": "AC-4", "label": "Information flow enforcement"}],
        "owasp": [{"id": "MASVS-PLATFORM-1", "label": "Platform interaction"}, _m2024("M8")],
        "capec": [{"id": "CAPEC-180", "label": "Component vulnerability"}],
        "cisa": [{"id": "LeastPriv", "label": "Restrict ContentResolver use"}],
        "nsa": [{"id": "MobileApp", "label": "Secure IPC (NSA)"}],
        "maswe": [_maswe("MASWE-0072", "ContentProvider access")],
    },
    "dex-unsafe-deserialization": {
        "cwe": [{"id": "CWE-502", "label": "Deserialization of untrusted data", "url": "https://cwe.mitre.org/data/definitions/502.html"}],
        "nist": [{"id": "SI-10", "label": "Information input validation"}],
        "owasp": [{"id": "MASVS-CODE-4", "label": "Unsafe deserialization"}, _m2024("M4")],
        "capec": [{"id": "CAPEC-586", "label": "Object Injection"}],
        "cisa": [{"id": "InputVal", "label": "Avoid unsafe deserialization"}],
        "nsa": [{"id": "AppSec", "label": "Safe serialization (NSA)"}],
        "maswe": [_maswe("MASWE-0042", "Unsafe deserialization")],
    },
    "jar-unsafe-deserialization": {
        "cwe": [{"id": "CWE-502", "label": "Deserialization of untrusted data"}],
        "nist": [{"id": "SI-10", "label": "Information input validation"}],
        "owasp": [{"id": "MASVS-CODE-4", "label": "Unsafe deserialization"}, _m2024("M4")],
        "capec": [{"id": "CAPEC-586", "label": "Object Injection"}],
        "cisa": [{"id": "InputVal", "label": "Avoid unsafe deserialization"}],
        "nsa": [{"id": "AppSec", "label": "Safe serialization (NSA)"}],
        "maswe": [_maswe("MASWE-0042", "Unsafe deserialization")],
    },
    "dex-path-traversal": {
        "cwe": [{"id": "CWE-22", "label": "Path traversal", "url": "https://cwe.mitre.org/data/definitions/22.html"}],
        "nist": [{"id": "AC-4", "label": "Information flow enforcement"}],
        "owasp": [{"id": "MASVS-CODE-2", "label": "Path / file handling"}, _m2024("M4")],
        "capec": [{"id": "CAPEC-126", "label": "Path Traversal"}],
        "cisa": [{"id": "LeastPriv", "label": "Validate paths"}],
        "nsa": [{"id": "AppSec", "label": "Safe file paths (NSA)"}],
        "maswe": [_maswe("MASWE-0041", "Path traversal / file URI")],
    },
    "jar-path-traversal": {
        "cwe": [{"id": "CWE-22", "label": "Path traversal"}],
        "nist": [{"id": "AC-4", "label": "Information flow enforcement"}],
        "owasp": [{"id": "MASVS-CODE-2", "label": "Path / file handling"}, _m2024("M4")],
        "capec": [{"id": "CAPEC-126", "label": "Path Traversal"}],
        "cisa": [{"id": "LeastPriv", "label": "Validate paths"}],
        "nsa": [{"id": "AppSec", "label": "Safe file paths (NSA)"}],
        "maswe": [_maswe("MASWE-0041", "Path traversal / file URI")],
    },
    "dex-runtime-exec": {
        "cwe": [{"id": "CWE-78", "label": "OS command injection", "url": "https://cwe.mitre.org/data/definitions/78.html"}],
        "nist": [{"id": "CM-7", "label": "Least functionality"}, {"id": "SI-10", "label": "Input validation"}],
        "owasp": [{"id": "MASVS-CODE-4", "label": "Command execution"}, _m2024("M4")],
        "capec": [{"id": "CAPEC-88", "label": "OS Command Injection"}],
        "cisa": [{"id": "LeastPriv", "label": "Avoid Runtime.exec with untrusted input"}],
        "nsa": [{"id": "AppSec", "label": "No shell from apps (NSA)"}],
        "maswe": [_maswe("MASWE-0043", "OS command execution")],
    },
    "jar-runtime-exec": {
        "cwe": [{"id": "CWE-78", "label": "OS command injection"}],
        "nist": [{"id": "CM-7", "label": "Least functionality"}],
        "owasp": [{"id": "MASVS-CODE-4", "label": "Command execution"}, _m2024("M4")],
        "capec": [{"id": "CAPEC-88", "label": "OS Command Injection"}],
        "cisa": [{"id": "LeastPriv", "label": "Avoid ProcessBuilder with untrusted input"}],
        "nsa": [{"id": "AppSec", "label": "No shell from apps (NSA)"}],
        "maswe": [_maswe("MASWE-0043", "OS command execution")],
    },
    "dast-android-sensitive-log": {
        "cwe": [{"id": "CWE-532", "label": "Information exposure through log files"}],
        "nist": [{"id": "AU-3", "label": "Content of audit records"}],
        "owasp": [{"id": "MASVS-PRIVACY-2", "label": "No sensitive data in logs"}, _m2024("M6")],
        "capec": [{"id": "CAPEC-169", "label": "Footprinting"}],
        "cisa": [{"id": "LogSensitive", "label": "Do not log sensitive data"}],
        "nsa": [{"id": "Logging", "label": "Avoid sensitive data in logs (NSA)"}],
        "maswe": [_maswe("MASWE-0063", "Sensitive data in logs")],
    },
    "dast-android-cleartext-observed": {
        "cwe": [{"id": "CWE-319", "label": "Cleartext transmission of sensitive data"}],
        "nist": [{"id": "SC-8", "label": "Transmission confidentiality"}],
        "owasp": [{"id": "MASVS-NETWORK-1", "label": "Secure data in transit"}, _m2024("M5")],
        "capec": [{"id": "CAPEC-94", "label": "Man in the middle"}],
        "cisa": [{"id": "EncryptTransit", "label": "Encrypt data in transit"}],
        "nsa": [{"id": "Encrypt", "label": "Use TLS (NSA)"}],
        "maswe": [_maswe("MASWE-0050", "Cleartext observed at runtime")],
    },
    "plugin-apkid-tag": {
        "cwe": [{"id": "CWE-693", "label": "Protection mechanism failure"}],
        "nist": [{"id": "RA-5", "label": "Vulnerability scanning"}],
        "owasp": [{"id": "MASVS-RESILIENCE-1", "label": "Binary protections / packing"}, _m2024("M7")],
        "capec": [{"id": "CAPEC-169", "label": "Footprinting"}],
        "cisa": [{"id": "SecureBuild", "label": "Know packer/obfuscator posture"}],
        "nsa": [{"id": "MobileApp", "label": "Binary analysis (NSA)"}],
        "maswe": [_maswe("MASWE-0091", "Packer / protector detection")],
    },
    "plugin-semgrep": {
        "cwe": [{"id": "CWE-693", "label": "Protection mechanism failure"}],
        "nist": [{"id": "RA-5", "label": "Vulnerability scanning"}],
        "owasp": [{"id": "MASVS-CODE-1", "label": "Code quality / SAST backend"}, _m2024("M4")],
        "capec": [{"id": "CAPEC-169", "label": "Footprinting"}],
        "cisa": [{"id": "SecureBuild", "label": "Static analysis"}],
        "nsa": [{"id": "AppSec", "label": "Static analysis (NSA)"}],
        "maswe": [_maswe("MASWE-0040", "Static rule hit (external)")],
    },
    "plugin-mobsfscan": {
        "cwe": [{"id": "CWE-693", "label": "Protection mechanism failure"}],
        "nist": [{"id": "RA-5", "label": "Vulnerability scanning"}],
        "owasp": [{"id": "MASVS-CODE-1", "label": "Mobile SAST backend"}, _m2024("M8")],
        "capec": [{"id": "CAPEC-169", "label": "Footprinting"}],
        "cisa": [{"id": "SecureBuild", "label": "Static analysis"}],
        "nsa": [{"id": "MobileApp", "label": "Mobile static analysis (NSA)"}],
        "maswe": [_maswe("MASWE-0040", "Static rule hit (external)")],
    },
    "sca-osv-vuln": {
        "cwe": [{"id": "CWE-1104", "label": "Use of unmaintained third-party components"}],
        "nist": [{"id": "RA-5", "label": "Vulnerability scanning"}, {"id": "SA-22", "label": "Unsupported components"}],
        "owasp": [{"id": "MASVS-CODE-1", "label": "Third-party components"}, _m2024("M2")],
        "capec": [{"id": "CAPEC-180", "label": "Exploiting component vulnerability"}],
        "cisa": [{"id": "Patch", "label": "Patch known vulnerable components"}],
        "nsa": [{"id": "SupplyChain", "label": "Software supply chain (NSA)"}],
        "maswe": [_maswe("MASWE-0100", "Vulnerable third-party component")],
    },
}


def merge_maswe_into_classification(
    rule_id: str,
    family: str,
    cls: Dict[str, List[Dict[str, str]]],
) -> Dict[str, List[Dict[str, str]]]:
    """Ensure maswe + owasp_mobile keys exist; merge family defaults when empty."""
    out = dict(cls)
    if rule_id in NEW_RULE_TAXONOMY:
        for k, v in NEW_RULE_TAXONOMY[rule_id].items():
            if k not in out or not out[k]:
                out[k] = list(v)
    maswe, mobile = family_maswe_mobile(family)
    if not out.get("maswe"):
        out["maswe"] = maswe
    if not out.get("owasp_mobile"):
        out["owasp_mobile"] = mobile
    # Also append 2024 Mobile Top 10 into owasp list if not already present
    existing_owasp_ids = {e.get("id") for e in (out.get("owasp") or [])}
    for m in mobile:
        if m.get("id") not in existing_owasp_ids:
            out.setdefault("owasp", []).append(m)
            existing_owasp_ids.add(m.get("id"))
    out.setdefault("maswe", [])
    out.setdefault("owasp_mobile", out.get("owasp_mobile") or mobile)
    return out


def primary_maswe_id(cls: Dict[str, Any]) -> Optional[str]:
    entries = cls.get("maswe") or []
    if entries:
        return entries[0].get("id")
    return None
