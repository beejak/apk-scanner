"""
Cross-reference findings with CWE, NIST, OWASP, CAPEC, CISA, NSA.
Maps rule_id (and optionally masvs_id) to standard classifications for easy-to-understand reporting.
"""

from typing import Any, Dict, List, Optional

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


def get_classification(rule_id: str, masvs_id: Optional[str] = None) -> Dict[str, List[Dict[str, str]]]:
    """Return CWE, NIST, OWASP, CAPEC, CISA, NSA for a rule_id. Empty lists for unknown rules."""
    return TAXONOMY.get(rule_id, {
        "cwe": [],
        "nist": [],
        "owasp": [],
        "capec": [],
        "cisa": [],
        "nsa": [],
    })


def enrich_finding(f: Dict[str, Any]) -> Dict[str, Any]:
    """Add classification to a finding dict (mutates and returns)."""
    rule_id = f.get("rule_id") or ""
    cls = get_classification(rule_id, f.get("masvs_id"))
    f["classification"] = cls
    return f


def classification_short(f: Dict[str, Any]) -> str:
    """One-line human-readable classification: CWE-798 (Hard-coded credentials); NIST IA-5; ..."""
    cls = f.get("classification") or get_classification(f.get("rule_id") or "")
    parts = []
    for db in ("cwe", "nist", "owasp", "capec", "cisa", "nsa"):
        entries = cls.get(db) or []
        for e in entries[:2]:  # max 2 per DB for brevity
            parts.append(f"{e.get('id', '')} ({e.get('label', '')})")
    return "; ".join(parts) if parts else "—"


def classification_for_csv(f: Dict[str, Any]) -> Dict[str, str]:
    """Return one column per DB with semicolon-separated id (label) for CSV."""
    cls = f.get("classification") or get_classification(f.get("rule_id") or "")
    out = {}
    for db in ("cwe", "nist", "owasp", "capec", "cisa", "nsa"):
        entries = cls.get(db) or []
        out[db] = "; ".join(f"{e.get('id', '')} ({e.get('label', '')})" for e in entries)
    return out
