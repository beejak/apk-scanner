"""
DEX-based SAST for APK using androguard (optional).
Extracts strings and method/class names; runs pattern rules.
"""

from pathlib import Path
from typing import List, Dict, Any

# Patterns: (pattern_lower, rule_id, severity, message, masvs_id)
_DEX_PATTERNS = [
    ("password", "dex-hardcoded-password", "high", "Possible hardcoded password/credential reference.", "MASVS-AUTH-4"),
    ("api_key", "dex-hardcoded-apikey", "high", "Possible hardcoded API key.", "MASVS-AUTH-4"),
    ("apikey", "dex-hardcoded-apikey", "high", "Possible hardcoded API key.", "MASVS-AUTH-4"),
    ("secret", "dex-hardcoded-secret", "medium", "Possible hardcoded secret.", "MASVS-CRYPTO-1"),
    ("shared_preferences", "dex-storage-sharedprefs", "info", "Uses SharedPreferences; ensure sensitive data is encrypted.", "MASVS-STORAGE-2"),
    ("android.util.log", "dex-logging", "low", "Android Log usage; ensure no sensitive data in release.", "MASVS-PRIVACY-2"),
    ("log.d(", "dex-logging", "low", "Log.d() usage; ensure no sensitive data in release.", "MASVS-PRIVACY-2"),
    ("log.e(", "dex-logging", "low", "Log.e() usage; ensure no sensitive data in release.", "MASVS-PRIVACY-2"),
    ("http://", "dex-cleartext", "medium", "Cleartext HTTP URL; use HTTPS.", "MASVS-NETWORK-1"),
    ("trustall", "dex-ssl-trust", "high", "Possible trust-all certificates (insecure).", "MASVS-NETWORK-2"),
    ("allowsignedcontent", "dex-ssl-trust", "medium", "Possible relaxed SSL/certificate validation.", "MASVS-NETWORK-2"),
]


def run_dex_rules(apk_path: Path) -> List[Dict[str, Any]]:
    """Run DEX pattern rules on APK. Uses androguard if available; else ZIP-based string scan."""
    findings: List[Dict[str, Any]] = []
    path_str = str(apk_path)

    try:
        from androguard.misc import AnalyzeAPK
        a, d, dx = AnalyzeAPK(path_str)
        return _run_dex_androguard(path_str, d, dx)
    except ImportError:
        return _run_dex_zip_fallback(apk_path)
    except Exception:
        return _run_dex_zip_fallback(apk_path)


def _run_dex_zip_fallback(apk_path: Path) -> List[Dict[str, Any]]:
    """No androguard: extract DEX from APK (ZIP) and scan raw bytes for ASCII strings matching patterns."""
    import zipfile
    import re
    findings = []
    path_str = str(apk_path)
    seen = set()
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for name in zf.namelist():
                if not name.endswith(".dex"):
                    continue
                data = zf.read(name)
                # Extract ASCII strings (min length 8)
                for m in re.finditer(rb"[\x20-\x7e]{8,200}", data):
                    s = m.group(0).decode("ascii", errors="replace").lower()
                    for pattern, rule_id, severity, message, masvs_id in _DEX_PATTERNS:
                        if pattern in s:
                            key = (rule_id, s[:80])
                            if key in seen:
                                continue
                            seen.add(key)
                            findings.append({
                                "rule_id": rule_id,
                                "severity": severity,
                                "message": f"{message} (seen in DEX: {s[:50]}...)",
                                "location": {"file": path_str, "line": None},
                                "masvs_id": masvs_id,
                                "source": "sast",
                            })
    except Exception:
        pass
    return findings


def _run_dex_androguard(path_str: str, d, dx) -> List[Dict[str, Any]]:
    """Run DEX rules using androguard Analysis."""
    findings: List[Dict[str, Any]] = []
    seen: set = set()

    for dex in d:
        # Get strings from DEX
        try:
            strings = dex.get_strings() if hasattr(dex, "get_strings") else _get_strings_from_analysis(dex, dx)
        except Exception:
            strings = []
        for s in strings:
            if not isinstance(s, str):
                s = str(s) if s is not None else ""
            s_lower = s.lower()
            for pattern, rule_id, severity, message, masvs_id in _DEX_PATTERNS:
                if pattern in s_lower:
                    key = (rule_id, s_lower[:80])
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append({
                        "rule_id": rule_id,
                        "severity": severity,
                        "message": f"{message} (seen: {(s[:60] + '...') if len(s) > 60 else s})",
                        "location": {"file": path_str, "line": None},
                        "masvs_id": masvs_id,
                        "source": "sast",
                    })

        # Method/class names
        try:
            for cls in dex.get_classes():
                name = getattr(cls, "get_name", lambda: None)()
                if name:
                    name_str = str(name)
                    name_lower = name_str.lower()
                    for pattern, rule_id, severity, message, masvs_id in _DEX_PATTERNS:
                        if pattern in name_lower:
                            key = (rule_id, name_lower[:80])
                            if key in seen:
                                continue
                            seen.add(key)
                            findings.append({
                                "rule_id": rule_id,
                                "severity": severity,
                                "message": f"{message} (class: {name_str})",
                                "location": {"file": path_str, "line": None},
                                "masvs_id": masvs_id,
                                "source": "sast",
                            })
        except Exception:
            pass

    return findings


def _get_strings_from_analysis(dex, dx) -> List[str]:
    """Fallback: try to get strings from analysis or dex internals."""
    out = []
    try:
        if hasattr(dex, "get_string"):
            for i in range(getattr(dex, "get_string_size", lambda: 0)() or 0):
                try:
                    s = dex.get_string(i)
                    if s:
                        out.append(s)
                except Exception:
                    pass
    except Exception:
        pass
    return out
