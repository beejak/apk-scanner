"""
Cross-reference findings with CWE, NIST, OWASP, CAPEC, CISA, NSA, MASWE, OWASP Mobile Top 10 2024.
Maps rule_id (and optionally masvs_id) to standard classifications for easy-to-understand reporting.

Also provides rule-based severity_score (0–10), CVSS-like estimates (not NVD CVE CVSS),
and remediation / revalidate guidance. Real CVE IDs only via SCA (OSV) when component+version
extracted — never invented; otherwise cve is null.
"""

from typing import Any, Dict, List, Optional, Tuple

from .taxonomy_maswe import (
    NEW_RULE_TAXONOMY,
    merge_maswe_into_classification,
    primary_maswe_id,
)

# Rule_id -> classification: CWE, NIST, OWASP, CAPEC, CISA, NSA.
# Each entry: short label for "easy to understand" + official ID + optional URL.
TAXONOMY: Dict[str, Dict[str, List[Dict[str, str]]]] = {
    "dex-hardcoded-password": {
        "cwe": [{"id": "CWE-798", "label": "Hard-coded credentials", "url": "https://cwe.mitre.org/data/definitions/798.html"}],
        "nist": [{"id": "IA-5", "label": "Authenticator management", "url": "https://csf.tools/reference/nist-sp-800-53-r5/ia/ia-5/"}],
        "owasp": [{"id": "MASVS-AUTH-4", "label": "No sensitive data in credentials", "url": "https://mas.owasp.org/MASVS/"}, {"id": "M1", "label": "Improper credential usage (Mobile Top 10)", "url": "https://owasp.org/www-project-mobile-top-10/"}],
        "capec": [{"id": "CAPEC-114", "label": "Credential stuffing", "url": "https://capec.mitre.org/data/definitions/114.html"}],
        "cisa": [{"id": "StrongAuth", "label": "Use strong authentication; no hardcoded secrets", "url": "https://www.cisa.gov/secure-our-world"}],
        "nsa": [{"id": "MobileApp", "label": "Mobile app: avoid hardcoded credentials (NSA mobile guidance)", "url": "https://media.defense.gov/"}],
    },
    "dex-hardcoded-apikey": {
        "cwe": [{"id": "CWE-798", "label": "Hard-coded credentials", "url": "https://cwe.mitre.org/data/definitions/798.html"}],
        "nist": [{"id": "IA-5", "label": "Authenticator management", "url": "https://csf.tools/reference/nist-sp-800-53-r5/ia/ia-5/"}],
        "owasp": [{"id": "MASVS-AUTH-4", "label": "No sensitive data in credentials", "url": "https://mas.owasp.org/MASVS/"}, {"id": "M1", "label": "Improper credential usage", "url": "https://owasp.org/www-project-mobile-top-10/"}],
        "capec": [{"id": "CAPEC-114", "label": "Credential stuffing", "url": "https://capec.mitre.org/data/definitions/114.html"}],
        "cisa": [{"id": "NoSecrets", "label": "Do not embed API keys or secrets in code", "url": "https://www.cisa.gov/"}],
        "nsa": [{"id": "MobileApp", "label": "Mobile: protect API keys and secrets", "url": "https://media.defense.gov/"}],
    },
    "dex-hardcoded-secret": {
        "cwe": [{"id": "CWE-798", "label": "Hard-coded credentials"}, {"id": "CWE-321", "label": "Hard-coded cryptographic key", "url": "https://cwe.mitre.org/data/definitions/321.html"}],
        "nist": [{"id": "SC-28", "label": "Protection of information at rest", "url": "https://csf.tools/reference/nist-sp-800-53-r5/sc/sc-28/"}, {"id": "IA-5", "label": "Authenticator management"}],
        "owasp": [{"id": "MASVS-CRYPTO-1", "label": "Standard crypto; no hardcoded keys", "url": "https://mas.owasp.org/MASVS/"}, {"id": "M2", "label": "Insecure data storage (Mobile Top 10)", "url": "https://owasp.org/www-project-mobile-top-10/"}],
        "capec": [{"id": "CAPEC-116", "label": "Excavation", "url": "https://capec.mitre.org/data/definitions/116.html"}],
        "cisa": [{"id": "NoSecrets", "label": "Secrets in secure vault; not in code", "url": "https://www.cisa.gov/"}],
        "nsa": [{"id": "MobileApp", "label": "Mobile: protect cryptographic keys", "url": "https://media.defense.gov/"}],
    },
    "dex-cleartext": {
        "cwe": [{"id": "CWE-319", "label": "Cleartext transmission of sensitive data", "url": "https://cwe.mitre.org/data/definitions/319.html"}],
        "nist": [{"id": "SC-8", "label": "Transmission confidentiality and integrity", "url": "https://csf.tools/reference/nist-sp-800-53-r5/sc/sc-8/"}],
        "owasp": [{"id": "MASVS-NETWORK-1", "label": "Secure data in transit (e.g. TLS)", "url": "https://mas.owasp.org/MASVS/"}, {"id": "M3", "label": "Insecure communication (Mobile Top 10)", "url": "https://owasp.org/www-project-mobile-top-10/"}],
        "capec": [{"id": "CAPEC-94", "label": "Man in the middle", "url": "https://capec.mitre.org/data/definitions/94.html"}],
        "cisa": [{"id": "EncryptTransit", "label": "Encrypt data in transit (CISA secure our world)", "url": "https://www.cisa.gov/secure-our-world"}],
        "nsa": [{"id": "Encrypt", "label": "Use TLS for all network traffic (NSA guidance)", "url": "https://media.defense.gov/"}],
    },
    "dex-ssl-trust": {
        "cwe": [{"id": "CWE-295", "label": "Improper certificate validation", "url": "https://cwe.mitre.org/data/definitions/295.html"}],
        "nist": [{"id": "SC-8", "label": "Transmission confidentiality"}, {"id": "SC-23", "label": "Session authenticity", "url": "https://csf.tools/reference/nist-sp-800-53-r5/sc/sc-23/"}],
        "owasp": [{"id": "MASVS-NETWORK-2", "label": "Certificate pinning / secure channel", "url": "https://mas.owasp.org/MASVS/"}, {"id": "M3", "label": "Insecure communication"}],
        "capec": [{"id": "CAPEC-94", "label": "Man in the middle"}],
        "cisa": [{"id": "ValidateCerts", "label": "Validate TLS certificates; no trust-all", "url": "https://www.cisa.gov/"}],
        "nsa": [{"id": "TLS", "label": "Proper certificate validation (NSA)", "url": "https://media.defense.gov/"}],
    },
    "dast-android-ssl-trust-all": {
        "cwe": [{"id": "CWE-295", "label": "Improper certificate validation", "url": "https://cwe.mitre.org/data/definitions/295.html"}],
        "nist": [{"id": "SC-8", "label": "Transmission confidentiality"}, {"id": "SC-23", "label": "Session authenticity"}],
        "owasp": [{"id": "MASVS-NETWORK-2", "label": "Certificate pinning / secure channel"}, {"id": "M3", "label": "Insecure communication"}],
        "capec": [{"id": "CAPEC-94", "label": "Man in the middle"}],
        "cisa": [{"id": "ValidateCerts", "label": "Validate TLS certificates; no trust-all"}],
        "nsa": [{"id": "TLS", "label": "Proper certificate validation (NSA)"}],
    },
    "dex-logging": {
        "cwe": [{"id": "CWE-532", "label": "Information exposure through log files", "url": "https://cwe.mitre.org/data/definitions/532.html"}],
        "nist": [{"id": "AU-3", "label": "Content of audit records", "url": "https://csf.tools/reference/nist-sp-800-53-r5/au/au-3/"}, {"id": "SC-8", "label": "Transmission confidentiality"}],
        "owasp": [{"id": "MASVS-PRIVACY-2", "label": "No sensitive data in logs", "url": "https://mas.owasp.org/MASVS/"}, {"id": "M4", "label": "Insecure authentication (logging)", "url": "https://owasp.org/www-project-mobile-top-10/"}],
        "capec": [{"id": "CAPEC-169", "label": "Footprinting", "url": "https://capec.mitre.org/data/definitions/169.html"}],
        "cisa": [{"id": "LogSensitive", "label": "Do not log sensitive data", "url": "https://www.cisa.gov/"}],
        "nsa": [{"id": "Logging", "label": "Avoid sensitive data in logs (NSA)", "url": "https://media.defense.gov/"}],
    },
    "dex-storage-sharedprefs": {
        "cwe": [{"id": "CWE-312", "label": "Cleartext storage of sensitive information", "url": "https://cwe.mitre.org/data/definitions/312.html"}],
        "nist": [{"id": "SC-28", "label": "Protection of information at rest"}],
        "owasp": [{"id": "MASVS-STORAGE-2", "label": "Sensitive data encrypted at rest", "url": "https://mas.owasp.org/MASVS/"}, {"id": "M2", "label": "Insecure data storage"}],
        "capec": [{"id": "CAPEC-37", "label": "Retrieve embedded sensitive data", "url": "https://capec.mitre.org/data/definitions/37.html"}],
        "cisa": [{"id": "EncryptAtRest", "label": "Encrypt sensitive data at rest", "url": "https://www.cisa.gov/"}],
        "nsa": [{"id": "MobileApp", "label": "Encrypt app storage (NSA mobile)", "url": "https://media.defense.gov/"}],
    },
    "apk-debuggable": {
        "cwe": [{"id": "CWE-489", "label": "Active debug code", "url": "https://cwe.mitre.org/data/definitions/489.html"}],
        "nist": [{"id": "CM-7", "label": "Least functionality", "url": "https://csf.tools/reference/nist-sp-800-53-r5/cm/cm-7/"}, {"id": "RA-5", "label": "Vulnerability scanning"}],
        "owasp": [{"id": "MASVS-RESILIENCE-1", "label": "App not debuggable in release", "url": "https://mas.owasp.org/MASVS/"}, {"id": "M9", "label": "Reverse engineering (Mobile Top 10)", "url": "https://owasp.org/www-project-mobile-top-10/"}],
        "capec": [{"id": "CAPEC-169", "label": "Footprinting"}],
        "cisa": [{"id": "SecureBuild", "label": "Disable debug in production (CISA)", "url": "https://www.cisa.gov/"}],
        "nsa": [{"id": "MobileApp", "label": "Release builds: no debug (NSA)", "url": "https://media.defense.gov/"}],
    },
    "apk-allow-backup": {
        "cwe": [{"id": "CWE-200", "label": "Information exposure", "url": "https://cwe.mitre.org/data/definitions/200.html"}],
        "nist": [{"id": "SC-28", "label": "Protection of information at rest"}],
        "owasp": [{"id": "MASVS-STORAGE-2", "label": "Sensitive data not in backups", "url": "https://mas.owasp.org/MASVS/"}, {"id": "M2", "label": "Insecure data storage"}],
        "capec": [{"id": "CAPEC-37", "label": "Retrieve embedded sensitive data"}],
        "cisa": [{"id": "Backup", "label": "Restrict backup of sensitive app data", "url": "https://www.cisa.gov/"}],
        "nsa": [{"id": "MobileApp", "label": "Control backup exposure (NSA)", "url": "https://media.defense.gov/"}],
    },
    "apk-exported-component": {
        "cwe": [{"id": "CWE-926", "label": "Improper export of Android component", "url": "https://cwe.mitre.org/data/definitions/926.html"}],
        "nist": [{"id": "AC-4", "label": "Information flow enforcement", "url": "https://csf.tools/reference/nist-sp-800-53-r5/ac/ac-4/"}, {"id": "AC-17", "label": "Remote access"}],
        "owasp": [{"id": "MASVS-PLATFORM-1", "label": "Platform interaction / exported components", "url": "https://mas.owasp.org/MASVS/"}, {"id": "M8", "label": "Code tampering / insufficient integrity", "url": "https://owasp.org/www-project-mobile-top-10/"}],
        "capec": [{"id": "CAPEC-180", "label": "Exploiting software via component vulnerability", "url": "https://capec.mitre.org/data/definitions/180.html"}],
        "cisa": [{"id": "LeastPriv", "label": "Least privilege; protect exported components", "url": "https://www.cisa.gov/"}],
        "nsa": [{"id": "MobileApp", "label": "Secure IPC and exports (NSA)", "url": "https://media.defense.gov/"}],
    },
    "apk-exported-unprotected": {
        "cwe": [{"id": "CWE-926", "label": "Improper export of Android component", "url": "https://cwe.mitre.org/data/definitions/926.html"}],
        "nist": [{"id": "AC-4", "label": "Information flow enforcement", "url": "https://csf.tools/reference/nist-sp-800-53-r5/ac/ac-4/"}, {"id": "AC-17", "label": "Remote access"}],
        "owasp": [{"id": "MASVS-PLATFORM-1", "label": "Platform interaction / exported components", "url": "https://mas.owasp.org/MASVS/"}, {"id": "M8", "label": "Security misconfiguration / IPC", "url": "https://owasp.org/www-project-mobile-top-10/"}],
        "capec": [{"id": "CAPEC-180", "label": "Exploiting software via component vulnerability", "url": "https://capec.mitre.org/data/definitions/180.html"}],
        "cisa": [{"id": "LeastPriv", "label": "Least privilege; protect exported components", "url": "https://www.cisa.gov/"}],
        "nsa": [{"id": "MobileApp", "label": "Secure IPC and exports (NSA)", "url": "https://media.defense.gov/"}],
    },
    "apk-cleartext-traffic": {
        "cwe": [{"id": "CWE-319", "label": "Cleartext transmission of sensitive data", "url": "https://cwe.mitre.org/data/definitions/319.html"}],
        "nist": [{"id": "SC-8", "label": "Transmission confidentiality and integrity", "url": "https://csf.tools/reference/nist-sp-800-53-r5/sc/sc-8/"}],
        "owasp": [{"id": "MASVS-NETWORK-1", "label": "Secure data in transit (e.g. TLS)", "url": "https://mas.owasp.org/MASVS/"}, {"id": "M3", "label": "Insecure communication (Mobile Top 10)", "url": "https://owasp.org/www-project-mobile-top-10/"}],
        "capec": [{"id": "CAPEC-94", "label": "Man in the middle", "url": "https://capec.mitre.org/data/definitions/94.html"}],
        "cisa": [{"id": "EncryptTransit", "label": "Encrypt data in transit", "url": "https://www.cisa.gov/secure-our-world"}],
        "nsa": [{"id": "Encrypt", "label": "Use TLS for all network traffic (NSA)", "url": "https://media.defense.gov/"}],
    },
    "dex-weak-cipher": {
        "cwe": [{"id": "CWE-327", "label": "Use of broken crypto algorithm", "url": "https://cwe.mitre.org/data/definitions/327.html"}],
        "nist": [{"id": "SC-13", "label": "Cryptographic protection", "url": "https://csf.tools/reference/nist-sp-800-53-r5/sc/sc-13/"}],
        "owasp": [{"id": "MASVS-CRYPTO-2", "label": "Strong crypto; no weak algorithms", "url": "https://mas.owasp.org/MASVS/"}, {"id": "M5", "label": "Insecure cryptography", "url": "https://owasp.org/www-project-mobile-top-10/"}],
        "capec": [{"id": "CAPEC-97", "label": "Cryptanalysis", "url": "https://capec.mitre.org/data/definitions/97.html"}],
        "cisa": [{"id": "StrongCrypto", "label": "Use approved cryptography (CISA)", "url": "https://www.cisa.gov/"}],
        "nsa": [{"id": "Crypto", "label": "Use approved algorithms (NSA)", "url": "https://media.defense.gov/"}],
    },
    "dex-weak-hash": {
        "cwe": [{"id": "CWE-328", "label": "Use of weak hash", "url": "https://cwe.mitre.org/data/definitions/328.html"}],
        "nist": [{"id": "SC-13", "label": "Cryptographic protection"}],
        "owasp": [{"id": "MASVS-CRYPTO-2", "label": "Strong crypto; no weak algorithms"}, {"id": "M5", "label": "Insecure cryptography"}],
        "capec": [{"id": "CAPEC-97", "label": "Cryptanalysis"}],
        "cisa": [{"id": "StrongCrypto", "label": "Use approved cryptography"}],
        "nsa": [{"id": "Crypto", "label": "Use approved algorithms (NSA)"}],
    },
    "dex-webview-js-bridge": {
        "cwe": [{"id": "CWE-749", "label": "Exposed dangerous method", "url": "https://cwe.mitre.org/data/definitions/749.html"}],
        "nist": [{"id": "AC-4", "label": "Information flow enforcement"}],
        "owasp": [{"id": "MASVS-PLATFORM-2", "label": "WebView / JS bridge hardening", "url": "https://mas.owasp.org/MASVS/"}, {"id": "M8", "label": "Security misconfiguration", "url": "https://owasp.org/www-project-mobile-top-10/"}],
        "capec": [{"id": "CAPEC-182", "label": "Flash Injection / bridge abuse", "url": "https://capec.mitre.org/data/definitions/182.html"}],
        "cisa": [{"id": "LeastPriv", "label": "Limit exposed interfaces"}],
        "nsa": [{"id": "MobileApp", "label": "Harden WebView bridges (NSA)"}],
    },
    "dex-webview-js-enabled": {
        "cwe": [{"id": "CWE-79", "label": "Cross-site scripting", "url": "https://cwe.mitre.org/data/definitions/79.html"}],
        "nist": [{"id": "SI-10", "label": "Information input validation"}],
        "owasp": [{"id": "MASVS-PLATFORM-2", "label": "WebView hardening"}, {"id": "M8", "label": "Security misconfiguration"}],
        "capec": [{"id": "CAPEC-63", "label": "Cross-Site Scripting"}],
        "cisa": [{"id": "LeastPriv", "label": "Limit WebView capabilities"}],
        "nsa": [{"id": "MobileApp", "label": "Harden WebView (NSA)"}],
    },
    "dex-webview-file-access": {
        "cwe": [{"id": "CWE-22", "label": "Path traversal", "url": "https://cwe.mitre.org/data/definitions/22.html"}],
        "nist": [{"id": "AC-4", "label": "Information flow enforcement"}],
        "owasp": [{"id": "MASVS-PLATFORM-2", "label": "WebView file access"}, {"id": "M8", "label": "Security misconfiguration"}],
        "capec": [{"id": "CAPEC-126", "label": "Path Traversal"}],
        "cisa": [{"id": "LeastPriv", "label": "Restrict file access"}],
        "nsa": [{"id": "MobileApp", "label": "Restrict WebView file access (NSA)"}],
    },
    "secret-aws-access-key": {
        "cwe": [{"id": "CWE-798", "label": "Hard-coded credentials", "url": "https://cwe.mitre.org/data/definitions/798.html"}],
        "nist": [{"id": "IA-5", "label": "Authenticator management"}],
        "owasp": [{"id": "MASVS-AUTH-4", "label": "No sensitive data in credentials"}, {"id": "M1", "label": "Improper credential usage"}],
        "capec": [{"id": "CAPEC-114", "label": "Credential stuffing"}],
        "cisa": [{"id": "NoSecrets", "label": "Do not embed cloud keys in apps"}],
        "nsa": [{"id": "MobileApp", "label": "Protect cloud credentials (NSA)"}],
    },
    "secret-google-api-key": {
        "cwe": [{"id": "CWE-798", "label": "Hard-coded credentials"}],
        "nist": [{"id": "IA-5", "label": "Authenticator management"}],
        "owasp": [{"id": "MASVS-AUTH-4", "label": "No sensitive data in credentials"}, {"id": "M1", "label": "Improper credential usage"}],
        "capec": [{"id": "CAPEC-114", "label": "Credential stuffing"}],
        "cisa": [{"id": "NoSecrets", "label": "Do not embed API keys in apps"}],
        "nsa": [{"id": "MobileApp", "label": "Protect API keys (NSA)"}],
    },
    "secret-private-key-pem": {
        "cwe": [{"id": "CWE-321", "label": "Hard-coded cryptographic key", "url": "https://cwe.mitre.org/data/definitions/321.html"}],
        "nist": [{"id": "SC-28", "label": "Protection of information at rest"}, {"id": "IA-5", "label": "Authenticator management"}],
        "owasp": [{"id": "MASVS-CRYPTO-1", "label": "No hardcoded keys"}, {"id": "M2", "label": "Insecure data storage"}],
        "capec": [{"id": "CAPEC-116", "label": "Excavation"}],
        "cisa": [{"id": "NoSecrets", "label": "Secrets in secure vault"}],
        "nsa": [{"id": "MobileApp", "label": "Protect private keys (NSA)"}],
    },
    "jar-secret-aws-access-key": {
        "cwe": [{"id": "CWE-798", "label": "Hard-coded credentials"}],
        "nist": [{"id": "IA-5", "label": "Authenticator management"}],
        "owasp": [{"id": "MASVS-AUTH-4", "label": "No sensitive data in credentials"}],
        "capec": [{"id": "CAPEC-114", "label": "Credential stuffing"}],
        "cisa": [{"id": "NoSecrets", "label": "No cloud keys in JAR"}],
        "nsa": [{"id": "AppSec", "label": "Protect cloud credentials (NSA)"}],
    },
    "jar-secret-google-api-key": {
        "cwe": [{"id": "CWE-798", "label": "Hard-coded credentials"}],
        "nist": [{"id": "IA-5", "label": "Authenticator management"}],
        "owasp": [{"id": "MASVS-AUTH-4", "label": "No sensitive data in credentials"}],
        "capec": [{"id": "CAPEC-114", "label": "Credential stuffing"}],
        "cisa": [{"id": "NoSecrets", "label": "No API keys in JAR"}],
        "nsa": [{"id": "AppSec", "label": "Protect API keys (NSA)"}],
    },
    "jar-secret-private-key-pem": {
        "cwe": [{"id": "CWE-321", "label": "Hard-coded cryptographic key"}],
        "nist": [{"id": "SC-28", "label": "Protection of information at rest"}],
        "owasp": [{"id": "MASVS-CRYPTO-1", "label": "No hardcoded keys"}],
        "capec": [{"id": "CAPEC-116", "label": "Excavation"}],
        "cisa": [{"id": "NoSecrets", "label": "Secrets in secure vault"}],
        "nsa": [{"id": "AppSec", "label": "Protect private keys (NSA)"}],
    },
    "ipa-secret-aws-access-key": {
        "cwe": [{"id": "CWE-798", "label": "Hard-coded credentials"}],
        "nist": [{"id": "IA-5", "label": "Authenticator management"}],
        "owasp": [{"id": "MASVS-AUTH-4", "label": "No sensitive data in credentials"}],
        "capec": [{"id": "CAPEC-114", "label": "Credential stuffing"}],
        "cisa": [{"id": "NoSecrets", "label": "No cloud keys in IPA"}],
        "nsa": [{"id": "MobileApp", "label": "Protect cloud credentials (NSA)"}],
    },
    "ipa-secret-google-api-key": {
        "cwe": [{"id": "CWE-798", "label": "Hard-coded credentials"}],
        "nist": [{"id": "IA-5", "label": "Authenticator management"}],
        "owasp": [{"id": "MASVS-AUTH-4", "label": "No sensitive data in credentials"}],
        "capec": [{"id": "CAPEC-114", "label": "Credential stuffing"}],
        "cisa": [{"id": "NoSecrets", "label": "No API keys in IPA"}],
        "nsa": [{"id": "MobileApp", "label": "Protect API keys (NSA)"}],
    },
    "ipa-secret-private-key-pem": {
        "cwe": [{"id": "CWE-321", "label": "Hard-coded cryptographic key"}],
        "nist": [{"id": "SC-28", "label": "Protection of information at rest"}],
        "owasp": [{"id": "MASVS-CRYPTO-1", "label": "No hardcoded keys"}],
        "capec": [{"id": "CAPEC-116", "label": "Excavation"}],
        "cisa": [{"id": "NoSecrets", "label": "Secrets in secure vault"}],
        "nsa": [{"id": "MobileApp", "label": "Protect private keys (NSA)"}],
    },
    "ipa-exception-insecure-http": {
        "cwe": [{"id": "CWE-319", "label": "Cleartext transmission of sensitive data"}],
        "nist": [{"id": "SC-8", "label": "Transmission confidentiality and integrity"}],
        "owasp": [{"id": "MASVS-NETWORK-1", "label": "Secure data in transit"}, {"id": "M3", "label": "Insecure communication"}],
        "capec": [{"id": "CAPEC-94", "label": "Man in the middle"}],
        "cisa": [{"id": "EncryptTransit", "label": "Encrypt data in transit"}],
        "nsa": [{"id": "Encrypt", "label": "Use TLS (NSA)"}],
    },
    "so-hardcoded-password": {
        "cwe": [{"id": "CWE-798", "label": "Hard-coded credentials"}],
        "nist": [{"id": "IA-5", "label": "Authenticator management"}],
        "owasp": [{"id": "MASVS-AUTH-4", "label": "No sensitive data in credentials"}, {"id": "M1", "label": "Improper credential usage"}],
        "capec": [{"id": "CAPEC-114", "label": "Credential stuffing"}],
        "cisa": [{"id": "NoSecrets", "label": "No hardcoded secrets in binaries"}],
        "nsa": [{"id": "Native", "label": "Native code: protect credentials (NSA)"}],
    },
    "so-hardcoded-apikey": {
        "cwe": [{"id": "CWE-798", "label": "Hard-coded credentials"}],
        "nist": [{"id": "IA-5", "label": "Authenticator management"}],
        "owasp": [{"id": "MASVS-AUTH-4", "label": "No sensitive data in credentials"}],
        "capec": [{"id": "CAPEC-114", "label": "Credential stuffing"}],
        "cisa": [{"id": "NoSecrets", "label": "No API keys in binaries"}],
        "nsa": [{"id": "Native", "label": "Native: protect API keys"}],
    },
    "so-weak-crypto": {
        "cwe": [{"id": "CWE-327", "label": "Use of broken crypto algorithm", "url": "https://cwe.mitre.org/data/definitions/327.html"}],
        "nist": [{"id": "SC-13", "label": "Cryptographic protection", "url": "https://csf.tools/reference/nist-sp-800-53-r5/sc/sc-13/"}],
        "owasp": [{"id": "MASVS-CRYPTO-2", "label": "Strong crypto; no weak algorithms", "url": "https://mas.owasp.org/MASVS/"}, {"id": "M2", "label": "Insecure data storage"}],
        "capec": [{"id": "CAPEC-97", "label": "Cryptanalysis", "url": "https://capec.mitre.org/data/definitions/97.html"}],
        "cisa": [{"id": "StrongCrypto", "label": "Use approved cryptography (CISA)", "url": "https://www.cisa.gov/"}],
        "nsa": [{"id": "Crypto", "label": "Use approved algorithms (NSA)", "url": "https://media.defense.gov/"}],
    },
    "so-jni": {
        "cwe": [{"id": "CWE-749", "label": "Exposed dangerous method", "url": "https://cwe.mitre.org/data/definitions/749.html"}],
        "nist": [{"id": "SC-39", "label": "Process isolation", "url": "https://csf.tools/reference/nist-sp-800-53-r5/sc/sc-39/"}],
        "owasp": [{"id": "MASVS-CODE-1", "label": "Code quality; secure JNI", "url": "https://mas.owasp.org/MASVS/"}],
        "capec": [{"id": "CAPEC-180", "label": "Exploiting component vulnerability"}],
        "cisa": [{"id": "SecureNative", "label": "Secure native code interfaces"}],
        "nsa": [{"id": "Native", "label": "JNI security (NSA mobile)"}],
    },
    # JAR (Java executable)
    "jar-hardcoded-password": {
        "cwe": [{"id": "CWE-798", "label": "Hard-coded credentials"}],
        "nist": [{"id": "IA-5", "label": "Authenticator management"}],
        "owasp": [{"id": "MASVS-AUTH-4", "label": "No sensitive data in credentials"}, {"id": "M1", "label": "Improper credential usage"}],
        "capec": [{"id": "CAPEC-114", "label": "Credential stuffing"}],
        "cisa": [{"id": "NoSecrets", "label": "No hardcoded credentials in JAR"}],
        "nsa": [{"id": "AppSec", "label": "Application security: protect credentials (NSA)"}],
    },
    "jar-hardcoded-apikey": {
        "cwe": [{"id": "CWE-798", "label": "Hard-coded credentials"}],
        "nist": [{"id": "IA-5", "label": "Authenticator management"}],
        "owasp": [{"id": "MASVS-AUTH-4", "label": "No sensitive data in credentials"}],
        "capec": [{"id": "CAPEC-114", "label": "Credential stuffing"}],
        "cisa": [{"id": "NoSecrets", "label": "No API keys in JAR"}],
        "nsa": [{"id": "AppSec", "label": "Protect API keys (NSA)"}],
    },
    "jar-hardcoded-secret": {
        "cwe": [{"id": "CWE-798", "label": "Hard-coded credentials"}, {"id": "CWE-321", "label": "Hard-coded cryptographic key"}],
        "nist": [{"id": "SC-28", "label": "Protection of information at rest"}, {"id": "IA-5", "label": "Authenticator management"}],
        "owasp": [{"id": "MASVS-CRYPTO-1", "label": "Standard crypto; no hardcoded keys"}, {"id": "M2", "label": "Insecure data storage"}],
        "capec": [{"id": "CAPEC-116", "label": "Excavation"}],
        "cisa": [{"id": "NoSecrets", "label": "Secrets in secure vault; not in JAR"}],
        "nsa": [{"id": "AppSec", "label": "Protect cryptographic keys (NSA)"}],
    },
    "jar-cleartext": {
        "cwe": [{"id": "CWE-319", "label": "Cleartext transmission of sensitive data"}],
        "nist": [{"id": "SC-8", "label": "Transmission confidentiality and integrity"}],
        "owasp": [{"id": "MASVS-NETWORK-1", "label": "Secure data in transit"}, {"id": "M3", "label": "Insecure communication"}],
        "capec": [{"id": "CAPEC-94", "label": "Man in the middle"}],
        "cisa": [{"id": "EncryptTransit", "label": "Encrypt data in transit"}],
        "nsa": [{"id": "Encrypt", "label": "Use TLS (NSA)"}],
    },
    "jar-ssl-trust": {
        "cwe": [{"id": "CWE-295", "label": "Improper certificate validation"}],
        "nist": [{"id": "SC-8", "label": "Transmission confidentiality"}, {"id": "SC-23", "label": "Session authenticity"}],
        "owasp": [{"id": "MASVS-NETWORK-2", "label": "Certificate pinning / secure channel"}, {"id": "M3", "label": "Insecure communication"}],
        "capec": [{"id": "CAPEC-94", "label": "Man in the middle"}],
        "cisa": [{"id": "ValidateCerts", "label": "Validate TLS certificates"}],
        "nsa": [{"id": "TLS", "label": "Proper certificate validation (NSA)"}],
    },
    "jar-weak-crypto": {
        "cwe": [{"id": "CWE-327", "label": "Use of broken crypto algorithm"}],
        "nist": [{"id": "SC-13", "label": "Cryptographic protection"}],
        "owasp": [{"id": "MASVS-CRYPTO-2", "label": "Strong crypto; no weak algorithms"}, {"id": "M2", "label": "Insecure data storage"}],
        "capec": [{"id": "CAPEC-97", "label": "Cryptanalysis"}],
        "cisa": [{"id": "StrongCrypto", "label": "Use approved cryptography"}],
        "nsa": [{"id": "Crypto", "label": "Use approved algorithms (NSA)"}],
    },
    # IPA (iOS)
    "ipa-allow-arbitrary-loads": {
        "cwe": [{"id": "CWE-319", "label": "Cleartext transmission of sensitive data"}],
        "nist": [{"id": "SC-8", "label": "Transmission confidentiality and integrity"}],
        "owasp": [{"id": "MASVS-NETWORK-1", "label": "Secure data in transit (e.g. TLS)"}, {"id": "M3", "label": "Insecure communication"}],
        "capec": [{"id": "CAPEC-94", "label": "Man in the middle"}],
        "cisa": [{"id": "EncryptTransit", "label": "Encrypt data in transit"}],
        "nsa": [{"id": "Encrypt", "label": "Use TLS for network traffic (NSA)"}],
    },
    "ipa-allow-local-networking": {
        "cwe": [{"id": "CWE-319", "label": "Cleartext transmission"}],
        "nist": [{"id": "SC-8", "label": "Transmission confidentiality"}],
        "owasp": [{"id": "MASVS-NETWORK-1", "label": "Secure data in transit"}],
        "capec": [{"id": "CAPEC-94", "label": "Man in the middle"}],
        "cisa": [{"id": "EncryptTransit", "label": "Secure local traffic"}],
        "nsa": [{"id": "Encrypt", "label": "Secure networking (NSA)"}],
    },
    "ipa-file-sharing": {
        "cwe": [{"id": "CWE-200", "label": "Information exposure"}],
        "nist": [{"id": "SC-28", "label": "Protection of information at rest"}],
        "owasp": [{"id": "MASVS-STORAGE-2", "label": "Sensitive data not exposed"}, {"id": "M2", "label": "Insecure data storage"}],
        "capec": [{"id": "CAPEC-37", "label": "Retrieve embedded sensitive data"}],
        "cisa": [{"id": "Backup", "label": "Restrict file sharing of sensitive data"}],
        "nsa": [{"id": "MobileApp", "label": "Control file sharing (NSA)"}],
    },
    "ipa-documents-in-place": {
        "cwe": [{"id": "CWE-200", "label": "Information exposure"}],
        "nist": [{"id": "SC-28", "label": "Protection of information at rest"}],
        "owasp": [{"id": "MASVS-STORAGE-2", "label": "Sensitive data scope"}],
        "capec": [{"id": "CAPEC-37", "label": "Retrieve embedded sensitive data"}],
        "cisa": [{"id": "Backup", "label": "Restrict document scope"}],
        "nsa": [{"id": "MobileApp", "label": "Document access control (NSA)"}],
    },
    "ipa-hardcoded-password": {
        "cwe": [{"id": "CWE-798", "label": "Hard-coded credentials"}],
        "nist": [{"id": "IA-5", "label": "Authenticator management"}],
        "owasp": [{"id": "MASVS-AUTH-4", "label": "No sensitive data in credentials"}, {"id": "M1", "label": "Improper credential usage"}],
        "capec": [{"id": "CAPEC-114", "label": "Credential stuffing"}],
        "cisa": [{"id": "NoSecrets", "label": "No hardcoded credentials in IPA"}],
        "nsa": [{"id": "MobileApp", "label": "Protect credentials (NSA)"}],
    },
    "ipa-hardcoded-apikey": {
        "cwe": [{"id": "CWE-798", "label": "Hard-coded credentials"}],
        "nist": [{"id": "IA-5", "label": "Authenticator management"}],
        "owasp": [{"id": "MASVS-AUTH-4", "label": "No sensitive data in credentials"}],
        "capec": [{"id": "CAPEC-114", "label": "Credential stuffing"}],
        "cisa": [{"id": "NoSecrets", "label": "No API keys in IPA"}],
        "nsa": [{"id": "MobileApp", "label": "Protect API keys (NSA)"}],
    },
    "ipa-hardcoded-secret": {
        "cwe": [{"id": "CWE-798", "label": "Hard-coded credentials"}, {"id": "CWE-321", "label": "Hard-coded cryptographic key"}],
        "nist": [{"id": "SC-28", "label": "Protection of information at rest"}, {"id": "IA-5", "label": "Authenticator management"}],
        "owasp": [{"id": "MASVS-CRYPTO-1", "label": "No hardcoded keys"}, {"id": "M2", "label": "Insecure data storage"}],
        "capec": [{"id": "CAPEC-116", "label": "Excavation"}],
        "cisa": [{"id": "NoSecrets", "label": "Secrets in secure vault"}],
        "nsa": [{"id": "MobileApp", "label": "Protect keys (NSA)"}],
    },
    "ipa-cleartext": {
        "cwe": [{"id": "CWE-319", "label": "Cleartext transmission of sensitive data"}],
        "nist": [{"id": "SC-8", "label": "Transmission confidentiality and integrity"}],
        "owasp": [{"id": "MASVS-NETWORK-1", "label": "Secure data in transit"}, {"id": "M3", "label": "Insecure communication"}],
        "capec": [{"id": "CAPEC-94", "label": "Man in the middle"}],
        "cisa": [{"id": "EncryptTransit", "label": "Encrypt data in transit"}],
        "nsa": [{"id": "Encrypt", "label": "Use TLS (NSA)"}],
    },
    # SDK
    "sdk-sensitive-file": {
        "cwe": [{"id": "CWE-312", "label": "Cleartext storage of sensitive information"}, {"id": "CWE-200", "label": "Information exposure"}],
        "nist": [{"id": "SC-28", "label": "Protection of information at rest"}, {"id": "CM-7", "label": "Least functionality"}],
        "owasp": [{"id": "MASVS-STORAGE-2", "label": "Sensitive data encrypted at rest"}, {"id": "M2", "label": "Insecure data storage"}],
        "capec": [{"id": "CAPEC-37", "label": "Retrieve embedded sensitive data"}],
        "cisa": [{"id": "NoSecrets", "label": "Do not commit keys or credentials to SDK"}],
        "nsa": [{"id": "SupplyChain", "label": "Secure SDK contents (NSA supply chain)"}],
    },
    "sdk-exposed-credential": {
        "cwe": [{"id": "CWE-798", "label": "Hard-coded credentials"}, {"id": "CWE-312", "label": "Cleartext storage of sensitive information"}],
        "nist": [{"id": "IA-5", "label": "Authenticator management"}, {"id": "SC-28", "label": "Protection of information at rest"}],
        "owasp": [{"id": "MASVS-AUTH-4", "label": "No sensitive data in credentials"}, {"id": "M2", "label": "Insecure data storage"}],
        "capec": [{"id": "CAPEC-114", "label": "Credential stuffing"}, {"id": "CAPEC-37", "label": "Retrieve embedded sensitive data"}],
        "cisa": [{"id": "NoSecrets", "label": "No credentials in config or source (CISA)"}],
        "nsa": [{"id": "SupplyChain", "label": "No credentials in SDK (NSA)"}],
    },
}

# Merge high-impact / plugin / SCA / DAST rule taxonomies (MASWE + Mobile Top 10 2024).
TAXONOMY.update(NEW_RULE_TAXONOMY)


# Severity band → base score (0.0–10.0). Final score = min(10, base * rule_weight).
SEVERITY_BASE: Dict[str, float] = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.5,
    "low": 3.0,
    "info": 1.0,
}

CVSS_NOTE = "rule-based estimate, not NVD CVSS for a CVE"

# Rule weight multipliers (confidence / actionability). Default 1.0.
RULE_WEIGHTS: Dict[str, float] = {
    "secret-aws-access-key": 1.05,
    "secret-google-api-key": 1.1,
    "secret-private-key-pem": 1.05,
    "jar-secret-aws-access-key": 1.05,
    "jar-secret-google-api-key": 1.1,
    "jar-secret-private-key-pem": 1.05,
    "ipa-secret-aws-access-key": 1.05,
    "ipa-secret-google-api-key": 1.1,
    "ipa-secret-private-key-pem": 1.05,
    "apk-debuggable": 1.05,
    "apk-cleartext-traffic": 1.05,
    "apk-exported-unprotected": 1.05,
    "apk-exported-intent-risk": 1.1,
    "apk-exported-provider-unprotected": 1.05,
    "dex-ssl-trust": 1.05,
    "dex-webview-js-bridge": 1.05,
    "dex-runtime-exec": 1.05,
    "dex-sql-concat": 1.05,
    "dex-unsafe-deserialization": 1.05,
    "dex-path-traversal": 1.0,
    "dast-android-ssl-trust-all": 1.1,
    "dast-android-sensitive-log": 1.05,
    "dast-android-cleartext-observed": 1.05,
    "sca-osv-vuln": 1.1,
    "dex-hardcoded-password": 0.7,
    "dex-hardcoded-apikey": 0.75,
    "dex-hardcoded-secret": 0.7,
    "dex-storage-sharedprefs": 0.7,
    "dex-logging": 0.65,
    "so-jni": 0.7,
}

# CVSS-like estimate per rule: score + simplified v3.1-style vector + honesty note.
# Not NVD CVSS for a CVE — requires SCA for real CVE/CVSS.
_CVSS_BY_FAMILY: Dict[str, Tuple[float, str]] = {
    "hardcoded-password": (5.3, "AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
    "hardcoded-apikey": (6.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "hardcoded-secret": (5.5, "AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
    "cleartext": (7.4, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "ssl-trust": (8.1, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "ssl-trust-all": (8.1, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "logging": (3.3, "AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"),
    "storage-sharedprefs": (4.0, "AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "debuggable": (7.5, "AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "allow-backup": (5.3, "AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "exported-component": (5.5, "AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
    "exported-unprotected": (6.5, "AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
    "cleartext-traffic": (7.4, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "weak-cipher": (5.9, "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "weak-hash": (5.3, "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "weak-crypto": (5.9, "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "webview-js-bridge": (8.1, "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N"),
    "webview-js-enabled": (5.4, "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"),
    "webview-file-access": (6.1, "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"),
    "webview-file-uri": (7.1, "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "sql-concat": (8.1, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "content-provider-access": (5.3, "AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "unsafe-deserialization": (8.1, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "path-traversal": (7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "runtime-exec": (9.0, "AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "exported-intent-risk": (7.5, "AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N"),
    "exported-provider-unprotected": (8.2, "AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"),
    "sensitive-log": (5.3, "AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"),
    "cleartext-observed": (7.4, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "apkid-tag": (3.0, "AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    "semgrep": (5.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "mobsfscan": (5.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "osv-vuln": (7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "aws-access-key": (9.1, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "google-api-key": (7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "private-key-pem": (8.6, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "allow-arbitrary-loads": (7.4, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "allow-local-networking": (5.3, "AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "exception-insecure-http": (6.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "file-sharing": (4.3, "AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "documents-in-place": (3.3, "AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "sensitive-file": (6.5, "AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "exposed-credential": (7.5, "AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "jni": (3.0, "AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
}

# Explicit overrides when family key alone is ambiguous.
CVSS_ESTIMATES: Dict[str, Dict[str, Any]] = {}

# Remediation + revalidate guidance per rule_id (or family fallback).
_HELP_BY_FAMILY: Dict[str, Tuple[str, str]] = {
    "hardcoded-password": (
        "Remove hardcoded passwords from app binaries and resources. Use platform secret stores "
        "(Android Keystore / iOS Keychain) or authenticate via a backend; never ship production credentials in the APK/IPA/JAR.",
        "Rebuild the artifact, then re-run: python cli.py <path> --sast -o json. Expect this rule_id to be absent "
        "(or only leftover false-positive token hits at low/info). Compare finding counts for the same path.",
    ),
    "hardcoded-apikey": (
        "Move API keys out of client code. Prefer short-lived tokens from your backend; restrict keys by package "
        "signature / bundle ID and IP where the vendor allows.",
        "Rebuild and re-scan with --sast. Clear when the matching key string no longer appears in findings for this rule_id.",
    ),
    "hardcoded-secret": (
        "Remove embedded secrets/crypto keys from the binary. Load keys from a secure backend or hardware-backed store at runtime.",
        "Rebuild and re-run --sast; this rule_id should clear when the secret patterns are gone.",
    ),
    "cleartext": (
        "Use HTTPS/TLS for all sensitive traffic. Replace http:// endpoints with https:// and enforce TLS in the network stack.",
        "Rebuild and re-scan with --sast. Expect dex-/jar-/ipa-cleartext hits for those URLs to disappear (schema/example URLs may still match).",
    ),
    "ssl-trust": (
        "Remove custom TrustManager / HostnameVerifier implementations that accept all certificates. Use the system trust store; "
        "add certificate pinning only with a maintained pin set.",
        "Rebuild and re-scan with --sast (and --dynamic if you use the Frida SSL check). Expect ssl-trust / trust-all rule_ids to clear.",
    ),
    "ssl-trust-all": (
        "Do not initialize SSLContext with a null or accepting-all TrustManager. Fix the app to validate certificates properly.",
        "Re-run with --dynamic on a device/emulator when Frida is available; the dast-android-ssl-trust-all finding should be gone.",
    ),
    "logging": (
        "Stop logging passwords, tokens, or PII. Use redaction or remove sensitive log lines before release builds.",
        "Rebuild release and re-scan with --sast; dex-logging findings for those strings should clear.",
    ),
    "storage-sharedprefs": (
        "Do not store secrets in plaintext SharedPreferences. Use EncryptedSharedPreferences or Keystore-backed storage.",
        "Rebuild and re-scan with --sast. Expect dex-storage-sharedprefs hits related to the sensitive keys to clear.",
    ),
    "debuggable": (
        "Set android:debuggable=false for release builds (default when using a release build type). Do not ship debug APKs to production.",
        "Build a release APK and re-run --sast; apk-debuggable should be absent when the manifest flag is false/unset for release.",
    ),
    "allow-backup": (
        "Set android:allowBackup=false, or use a backup rules / data extraction rules file that excludes sensitive data.",
        "Rebuild and re-scan with --sast; apk-allow-backup should clear when allowBackup is false or appropriately restricted.",
    ),
    "exported-component": (
        "Review exported activities/services/receivers/providers. Export only what is required; prefer explicit intents.",
        "Rebuild and re-scan with --sast; review remaining apk-exported-* findings for intentional exports.",
    ),
    "exported-unprotected": (
        "Add a permission (signature/custom) on exported components, or set android:exported=false if not needed by other apps.",
        "Rebuild and re-scan with --sast; apk-exported-unprotected should clear for components that are no longer exported without permission.",
    ),
    "cleartext-traffic": (
        "Disable cleartext in the manifest / network security config (usesCleartextTraffic=false; cleartextTrafficPermitted=false).",
        "Rebuild and re-scan with --sast; apk-cleartext-traffic should clear when cleartext is disallowed.",
    ),
    "weak-cipher": (
        "Replace weak Cipher algorithms (e.g. DES, RC4, ECB) with modern algorithms (AES-GCM) via Cipher.getInstance with strong transforms.",
        "Rebuild and re-scan with --sast; dex-weak-cipher / jar-weak-crypto hits for those algorithm strings should clear.",
    ),
    "weak-hash": (
        "Replace MD5/SHA-1 for security uses with SHA-256 or stronger (or a proper KDF/MAC). Do not use broken digests for integrity/auth.",
        "Rebuild and re-scan with --sast; dex-weak-hash findings for those MessageDigest strings should clear.",
    ),
    "weak-crypto": (
        "Remove weak crypto algorithm names from native/JAR code paths; use approved algorithms (AES-GCM, SHA-256+).",
        "Rebuild and re-scan with --sast; so-weak-crypto / jar-weak-crypto should clear when weak algorithm strings are gone.",
    ),
    "webview-js-bridge": (
        "Avoid addJavascriptInterface on untrusted content; if required, expose minimal APIs and validate all inputs.",
        "Rebuild and re-scan with --sast; dex-webview-js-bridge should clear when the bridge is removed or no longer matched.",
    ),
    "webview-js-enabled": (
        "Enable JavaScript only when required; load only trusted content and apply WebView hardening (safe browsing, no file access).",
        "Rebuild and re-scan with --sast; review remaining dex-webview-js-enabled hits for intentional trusted WebViews.",
    ),
    "webview-file-access": (
        "Disable WebView file access (setAllowFileAccess(false) / setAllowFileAccessFromFileURLs(false)) unless strictly required.",
        "Rebuild and re-scan with --sast; dex-webview-file-access should clear when file-access APIs are not used insecurely.",
    ),
    "webview-file-uri": (
        "Disable setAllowFileAccessFromFileURLs / setAllowUniversalAccessFromFileURLs unless strictly required for trusted content.",
        "Rebuild and re-scan with --sast; dex-webview-file-uri should clear when those APIs are not enabled.",
    ),
    "sql-concat": (
        "Use parameterized queries / selectionArgs; never concatenate untrusted input into SQL or ContentProvider queries.",
        "Rebuild and re-scan with --sast; dex-/jar-sql-concat should clear when concat-based SQL patterns are gone.",
    ),
    "content-provider-access": (
        "Review ContentResolver usage; ensure providers are permission-protected and callers validate URIs.",
        "Rebuild and re-scan with --sast; treat remaining hits as leads for intentional provider use.",
    ),
    "unsafe-deserialization": (
        "Avoid ObjectInputStream / default typing / unsafe YAML load on untrusted data; use allowlists or safer formats (JSON with schemas).",
        "Rebuild and re-scan with --sast; dex-/jar-unsafe-deserialization should clear when those APIs are removed or hardened.",
    ),
    "path-traversal": (
        "Canonicalize and validate file paths; block ../ and unexpected file:// URIs; prefer app-private storage APIs.",
        "Rebuild and re-scan with --sast; path-traversal rule_ids should clear or drop when unsafe path construction is fixed.",
    ),
    "runtime-exec": (
        "Avoid Runtime.exec / ProcessBuilder in apps; if required, use fixed argument lists with no shell and no untrusted input.",
        "Rebuild and re-scan with --sast; dex-/jar-runtime-exec should clear when exec/ProcessBuilder usage is removed.",
    ),
    "exported-intent-risk": (
        "Set android:exported=false when not needed, or require a signature/custom permission; validate Intent extras.",
        "Rebuild and re-scan with --sast; apk-exported-intent-risk should clear for activities no longer exported without permission.",
    ),
    "exported-provider-unprotected": (
        "Protect ContentProviders with permissions or set exported=false; never expose sensitive data via open providers.",
        "Rebuild and re-scan with --sast; apk-exported-provider-unprotected should clear when providers are protected.",
    ),
    "sensitive-log": (
        "Stop logging passwords, tokens, or PII at runtime; use redaction or remove sensitive log lines in release.",
        "Re-run with --dynamic when Frida/adb available; dast-android-sensitive-log should clear when hooks no longer observe sensitive logs.",
    ),
    "cleartext-observed": (
        "Use HTTPS only; disable cleartext in network security config; fix any runtime HTTP URLs.",
        "Re-run with --dynamic; dast-android-cleartext-observed should clear when no cleartext HTTP is observed.",
    ),
    "apkid-tag": (
        "Informational packer/obfuscator tag from APKiD. Review whether packing is intentional for release.",
        "Re-run with --apkid after changing packing; tags change with the binary, not a fix/revalidate defect by themselves.",
    ),
    "semgrep": (
        "Review the Semgrep rule message and fix the underlying code issue; re-run Semgrep or this scanner with --semgrep.",
        "Re-run: python cli.py <path> --sast --semgrep -o json. Expect the mapped plugin-semgrep finding to clear when Semgrep no longer reports it.",
    ),
    "mobsfscan": (
        "Review the mobsfscan finding and apply the suggested secure-coding fix; re-scan with --mobsfscan.",
        "Re-run: python cli.py <path> --sast --mobsfscan -o json. Expect plugin-mobsfscan hits to clear when mobsfscan is clean.",
    ),
    "osv-vuln": (
        "Upgrade or replace the vulnerable component to a fixed version listed by OSV/NVD. Do not ignore known CVEs in shipped libs.",
        "Re-run with --sca after upgrading; sca-osv-vuln for that package@version should clear when OSV no longer reports vulns (or version is fixed).",
    ),
    "aws-access-key": (
        "Rotate the AWS access key immediately. Remove it from the app; use Cognito/STS or a backend that vends temporary credentials.",
        "After rotation and rebuild, re-scan with --sast; secret-*/aws-access-key findings should be gone. Confirm key disabled in AWS IAM.",
    ),
    "google-api-key": (
        "Restrict the Google API key (Android/iOS app restriction) or move calls server-side. Rotate if the key was exposed.",
        "Rebuild and re-scan with --sast; google-api-key rule_ids should clear when the AIza… string is removed.",
    ),
    "private-key-pem": (
        "Remove PEM private keys from the package. Generate/store keys in Keystore/Keychain or a secrets manager; rotate any exposed key.",
        "Rebuild and re-scan with --sast; private-key-pem findings should clear when BEGIN PRIVATE KEY blocks are gone.",
    ),
    "allow-arbitrary-loads": (
        "Set NSAllowsArbitraryLoads to false (or remove it). Use ATS exceptions only for specific, justified domains.",
        "Rebuild the IPA and re-scan with --sast; ipa-allow-arbitrary-loads should clear when ATS no longer allows arbitrary loads.",
    ),
    "allow-local-networking": (
        "Limit NSAllowsLocalNetworking; prefer TLS even on local networks when carrying sensitive data.",
        "Rebuild and re-scan with --sast; ipa-allow-local-networking should clear when the plist flag is removed/false.",
    ),
    "exception-insecure-http": (
        "Remove NSExceptionAllowsInsecureHTTPLoads for production domains; serve HTTPS only.",
        "Rebuild and re-scan with --sast; ipa-exception-insecure-http should clear when insecure HTTP exceptions are removed.",
    ),
    "file-sharing": (
        "Disable UIFileSharingEnabled if users should not browse app documents via Finder/iTunes; keep sensitive files out of Documents.",
        "Rebuild and re-scan with --sast; ipa-file-sharing should clear when file sharing is disabled.",
    ),
    "documents-in-place": (
        "Review LSSupportsOpeningDocumentsInPlace; ensure document access does not expose sensitive app data unintentionally.",
        "Rebuild and re-scan with --sast; ipa-documents-in-place should clear when the capability is removed if unused.",
    ),
    "sensitive-file": (
        "Remove keystores, PEM files, and credential-like filenames from the SDK distribution; load secrets at runtime from a vault.",
        "Re-scan the SDK path with --sast; sdk-sensitive-file should clear when those files are removed from the tree.",
    ),
    "exposed-credential": (
        "Remove credentials from SDK configs and source. Use environment injection or a secrets manager in consuming apps.",
        "Re-scan with --sast; sdk-exposed-credential should clear when credential patterns are gone from configs.",
    ),
    "jni": (
        "Treat JNI as a trust boundary: validate inputs, avoid exposing privileged native APIs broadly. Review for buffer issues separately.",
        "Re-scan the .so with --sast; so-jni is informational — expect it if JNI symbols remain (not always a defect).",
    ),
}

REMEDIATION: Dict[str, Dict[str, str]] = {}


def _rule_family(rule_id: str) -> str:
    """Strip artifact prefix to a family key used for CVSS/help fallbacks."""
    rid = rule_id or ""
    for prefix in (
        "dast-android-",
        "plugin-",
        "sca-",
        "secret-",
        "jar-secret-",
        "ipa-secret-",
        "apk-",
        "dex-",
        "jar-",
        "ipa-",
        "so-",
        "sdk-",
    ):
        if rid.startswith(prefix):
            return rid[len(prefix) :]
    return rid


def get_classification(rule_id: str, masvs_id: Optional[str] = None) -> Dict[str, List[Dict[str, str]]]:
    """Return CWE, NIST, OWASP, CAPEC, CISA, NSA, MASWE, OWASP Mobile 2024 for a rule_id."""
    _ = masvs_id
    base = TAXONOMY.get(rule_id, {
        "cwe": [],
        "nist": [],
        "owasp": [],
        "capec": [],
        "cisa": [],
        "nsa": [],
        "maswe": [],
        "owasp_mobile": [],
    })
    # Copy so callers can mutate safely
    cls = {k: list(v) for k, v in base.items()}
    return merge_maswe_into_classification(rule_id, _rule_family(rule_id), cls)


def rule_weight(rule_id: str) -> float:
    """Return weight multiplier for severity_score (default 1.0)."""
    return float(RULE_WEIGHTS.get(rule_id or "", 1.0))


def compute_severity_score(severity: str, rule_id: str = "") -> float:
    """Numeric score 0.0–10.0 from severity band × rule weight."""
    base = SEVERITY_BASE.get((severity or "info").lower(), 1.0)
    score = base * rule_weight(rule_id or "")
    return round(min(10.0, max(0.0, score)), 1)


def get_cvss_estimate(rule_id: str, severity: Optional[str] = None) -> Dict[str, Any]:
    """
    Rule-based CVSS-like estimate. Not an NVD score for a CVE.
    """
    if rule_id in CVSS_ESTIMATES:
        est = dict(CVSS_ESTIMATES[rule_id])
        est.setdefault("note", CVSS_NOTE)
        return est
    family = _rule_family(rule_id)
    if family in _CVSS_BY_FAMILY:
        score, vector = _CVSS_BY_FAMILY[family]
        return {"score": score, "vector": vector, "note": CVSS_NOTE}
    # Fallback from severity band only
    band = SEVERITY_BASE.get((severity or "info").lower(), 1.0)
    return {
        "score": round(band, 1),
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "note": CVSS_NOTE,
    }


def get_remediation(rule_id: str) -> Dict[str, str]:
    """Return remediation and revalidate strings for a rule_id."""
    if rule_id in REMEDIATION:
        entry = REMEDIATION[rule_id]
        return {
            "remediation": entry.get("remediation", ""),
            "revalidate": entry.get("revalidate", ""),
        }
    family = _rule_family(rule_id)
    if family in _HELP_BY_FAMILY:
        rem, rev = _HELP_BY_FAMILY[family]
        return {"remediation": rem, "revalidate": rev}
    return {
        "remediation": (
            "Review the finding message and location; apply secure-coding guidance for the matched pattern, "
            "then rebuild the artifact."
        ),
        "revalidate": (
            "Re-run: python cli.py <path> --sast -o json (add --dynamic if applicable). "
            "Expect this rule_id to clear or drop when the issue is fixed."
        ),
    }


def enrich_finding(f: Dict[str, Any]) -> Dict[str, Any]:
    """Add classification, MASWE, scores, remediation; preserve real SCA cve list if set."""
    rule_id = f.get("rule_id") or ""
    severity = f.get("severity") or "info"
    cls = get_classification(rule_id, f.get("masvs_id"))
    f["classification"] = cls
    mid = primary_maswe_id(cls)
    if mid:
        f["maswe_id"] = mid
    mobile = cls.get("owasp_mobile") or []
    if mobile:
        f["owasp_mobile"] = mobile[0].get("id")
    f["severity_score"] = compute_severity_score(severity, rule_id)
    f["cvss_estimate"] = get_cvss_estimate(rule_id, severity)
    help_map = get_remediation(rule_id)
    f["remediation"] = help_map["remediation"]
    f["revalidate"] = help_map["revalidate"]
    # Real CVE IDs only from SCA (list or id). Never invent CVE-YYYY-NNNN.
    if "cve" not in f:
        f["cve"] = None
    return f


def classification_short(f: Dict[str, Any]) -> str:
    """One-line human-readable classification: CWE-798 (...); MASWE-...; M1:2024; ..."""
    cls = f.get("classification") or get_classification(f.get("rule_id") or "")
    parts = []
    for db in ("cwe", "nist", "owasp", "maswe", "owasp_mobile", "capec", "cisa", "nsa"):
        entries = cls.get(db) or []
        for e in entries[:2]:  # max 2 per DB for brevity
            parts.append(f"{e.get('id', '')} ({e.get('label', '')})")
    return "; ".join(parts) if parts else "—"


def classification_for_csv(f: Dict[str, Any]) -> Dict[str, str]:
    """Return one column per DB with semicolon-separated id (label) for CSV."""
    cls = f.get("classification") or get_classification(f.get("rule_id") or "")
    out = {}
    for db in ("cwe", "nist", "owasp", "maswe", "owasp_mobile", "capec", "cisa", "nsa"):
        entries = cls.get(db) or []
        out[db] = "; ".join(f"{e.get('id', '')} ({e.get('label', '')})" for e in entries)
    return out
