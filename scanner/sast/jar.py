"""
JAR (Java) SAST: scan JAR contents for hardcoded secrets, cleartext, weak crypto patterns.
"""

import re
import zipfile
from pathlib import Path
from typing import Any, Dict, List

# Same pattern ideas as DEX, with jar-* rule_ids
_JAR_PATTERNS = [
    ("password", "jar-hardcoded-password", "high", "Possible hardcoded password/credential in JAR.", "MASVS-AUTH-4"),
    ("api_key", "jar-hardcoded-apikey", "high", "Possible hardcoded API key in JAR.", "MASVS-AUTH-4"),
    ("apikey", "jar-hardcoded-apikey", "high", "Possible hardcoded API key in JAR.", "MASVS-AUTH-4"),
    ("secret", "jar-hardcoded-secret", "medium", "Possible hardcoded secret in JAR.", "MASVS-CRYPTO-1"),
    ("http://", "jar-cleartext", "medium", "Cleartext HTTP URL in JAR; use HTTPS.", "MASVS-NETWORK-1"),
    ("trustall", "jar-ssl-trust", "high", "Possible trust-all certificates in JAR.", "MASVS-NETWORK-2"),
    ("md5", "jar-weak-crypto", "medium", "MD5 or weak crypto reference in JAR.", "MASVS-CRYPTO-2"),
    ("des_encrypt", "jar-weak-crypto", "high", "DES or weak crypto in JAR.", "MASVS-CRYPTO-2"),
]


def run_jar_rules(jar_path: Path) -> List[Dict[str, Any]]:
    """Scan JAR (ZIP) for string patterns in .class and text files. Returns list of findings."""
    findings: List[Dict[str, Any]] = []
    path_str = str(jar_path)
    seen: set = set()

    try:
        with zipfile.ZipFile(jar_path, "r") as zf:
            for name in zf.namelist():
                if not name.endswith(".class") and not name.endswith(".xml") and not name.endswith(".properties"):
                    continue
                try:
                    data = zf.read(name)
                except Exception:
                    continue
                if not data:
                    continue
                for m in re.finditer(rb"[\x20-\x7e]{8,200}", data):
                    s = m.group(0).decode("ascii", errors="replace").lower()
                    for pattern, rule_id, severity, message, masvs_id in _JAR_PATTERNS:
                        if pattern in s:
                            key = (rule_id, s[:80])
                            if key in seen:
                                continue
                            seen.add(key)
                            findings.append({
                                "rule_id": rule_id,
                                "severity": severity,
                                "message": f"{message} (in {name}: {s[:50]}...)",
                                "location": {"file": path_str, "line": None},
                                "masvs_id": masvs_id,
                                "source": "sast",
                            })
    except Exception:
        pass
    return findings
