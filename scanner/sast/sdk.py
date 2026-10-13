"""
SDK directory SAST: sensitive files and credential patterns in config/source.
"""

import re
from pathlib import Path
from typing import Any, Dict, List

# Filenames or path segments that suggest sensitive material
_SENSITIVE_NAMES = [
    ".pem", ".key", ".p12", ".pfx", ".keystore", ".jks",
    "secret", "credential", "password", "api_key", "apikey",
    ".env", "credentials", "secrets.",
]
# Content patterns in text files (pattern_lower, rule_id, severity, message, masvs_id)
_SDK_PATTERNS = [
    ("password\\s*=", "sdk-exposed-credential", "high", "Password or credential pattern in SDK file.", "MASVS-AUTH-4"),
    ("api_key\\s*=", "sdk-exposed-credential", "high", "API key pattern in SDK file.", "MASVS-AUTH-4"),
    ("secret\\s*=", "sdk-exposed-credential", "medium", "Secret pattern in SDK file.", "MASVS-CRYPTO-1"),
]


def run_sdk_rules(sdk_path: Path, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Scan SDK directory for sensitive files and credential-like content. Returns list of findings."""
    findings: List[Dict[str, Any]] = []
    path_str = str(sdk_path)
    seen: set = set()

    if not sdk_path.is_dir():
        return findings

    # 1) Sensitive filenames
    for p in sdk_path.rglob("*"):
        if not p.is_file():
            continue
        name_lower = p.name.lower()
        for frag in _SENSITIVE_NAMES:
            if frag in name_lower:
                key = ("sdk-sensitive-file", p.name)
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "rule_id": "sdk-sensitive-file",
                    "severity": "high",
                    "message": f"Sensitive file in SDK: {p.name} (ensure not committed or restrict access).",
                    "location": {"file": str(p), "line": None},
                    "masvs_id": "MASVS-STORAGE-2",
                    "source": "sast",
                })
                break

    # 2) Text files: .properties, .xml, .json, .env, .yaml, .yml, .config
    text_ext = (".properties", ".xml", ".json", ".env", ".yaml", ".yml", ".config", ".cfg", ".ini", ".conf")
    for p in sdk_path.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in text_ext:
            continue
        try:
            raw = p.read_bytes()
            if b"\x00" in raw[:1000]:
                continue
            text = raw.decode("utf-8", errors="replace").lower()
        except Exception:
            continue
        for pattern, rule_id, severity, message, masvs_id in _SDK_PATTERNS:
            if re.search(pattern, text):
                key = (rule_id, str(p))
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "rule_id": rule_id,
                    "severity": severity,
                    "message": f"{message} File: {p.name}",
                    "location": {"file": str(p), "line": None},
                    "masvs_id": masvs_id,
                    "source": "sast",
                })
    return findings
