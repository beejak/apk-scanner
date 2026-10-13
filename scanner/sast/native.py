"""
Native .so SAST: string/symbol pattern checks (secrets, crypto, JNI).
"""

from pathlib import Path
from typing import Any, Dict, List

import re

_NATIVE_PATTERNS = [
    (re.compile(rb"password\s*=\s*[\"'][^\"']+[\"']", re.I), "so-hardcoded-password", "high", "Possible hardcoded password in binary.", "MASVS-AUTH-4"),
    (re.compile(rb"api[_-]?key\s*=\s*[\"'][^\"']+[\"']", re.I), "so-hardcoded-apikey", "high", "Possible hardcoded API key in binary.", "MASVS-AUTH-4"),
    (re.compile(rb"md5\s*\(|MD5_Init|EVP_md5", re.I), "so-weak-crypto", "medium", "MD5 usage (weak crypto).", "MASVS-CRYPTO-2"),
    (re.compile(rb"DES_ecb_encrypt|DES_cbc", re.I), "so-weak-crypto", "high", "DES usage (weak crypto).", "MASVS-CRYPTO-2"),
    (re.compile(rb"JNI_OnLoad", re.I), "so-jni", "info", "JNI_OnLoad present; ensure no sensitive logic in native code.", None),
]


def _read_elf_sections(path: Path) -> bytes:
    """Read binary for string scan (up to 2MB to avoid huge files)."""
    try:
        with open(path, "rb") as f:
            return f.read(2 * 1024 * 1024)
    except Exception:
        return b""


def run_native_rules(path: Path, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Run pattern checks on .so binary. Returns list of findings."""
    findings: List[Dict[str, Any]] = []
    path_str = str(path)

    try:
        data = _read_elf_sections(path)
    except Exception:
        return findings

    seen: set = set()
    for pattern, rule_id, severity, message, masvs_id in _NATIVE_PATTERNS:
        for m in pattern.finditer(data):
            snippet = m.group(0)[:60].decode("utf-8", errors="replace")
            key = (rule_id, snippet)
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                "rule_id": rule_id,
                "severity": severity,
                "message": f"{message} (e.g. {snippet})",
                "location": {"file": path_str, "line": None},
                "masvs_id": masvs_id,
                "source": "sast",
            })

    return findings
