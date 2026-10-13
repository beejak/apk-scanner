"""
DEX pattern-scan SAST for APK (constrained regex on strings / class names).

Default path: ZIP ASCII string scan (fast, no full decompile).
Optional: set APK_SCANNER_ANDROGUARD=1 to also run androguard string tables
(AnalyzeAPK is heavy; not needed for pattern lint).
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from .patterns import scan_text_for_rules


def run_dex_rules(apk_path: Path, metadata: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Run DEX pattern rules on APK. ZIP scan by default; optional androguard merge."""
    findings: List[Dict[str, Any]] = []
    path_str = str(apk_path)
    _ = metadata  # reserved for future DEX+manifest correlation

    findings.extend(_run_dex_zip_fallback(apk_path))

    if os.environ.get("APK_SCANNER_ANDROGUARD", "").strip() in ("1", "true", "yes"):
        try:
            from androguard.misc import AnalyzeAPK
            a, d, dx = AnalyzeAPK(path_str)
            findings.extend(_run_dex_androguard(path_str, d, dx))
        except ImportError:
            pass
        except Exception:
            pass
    return _dedupe(findings)


def _run_dex_zip_fallback(apk_path: Path) -> List[Dict[str, Any]]:
    """Extract DEX/XML from APK (ZIP) and scan ASCII strings."""
    import re
    import zipfile

    findings: List[Dict[str, Any]] = []
    path_str = str(apk_path)
    seen: set = set()
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for name in zf.namelist():
                lower_name = name.lower()
                if lower_name.endswith(".xml") and (
                    "network_security" in lower_name or "networksecurity" in lower_name
                ):
                    try:
                        raw = zf.read(name).decode("utf-8", errors="replace")
                    except Exception:
                        continue
                    for hit in scan_text_for_rules(raw, include_vague=False):
                        key = (hit["rule_id"], hit["message"][:80])
                        if key in seen:
                            continue
                        seen.add(key)
                        hit["location"] = {"file": path_str, "line": None}
                        hit["source"] = "sast"
                        findings.append(hit)

            for name in zf.namelist():
                if not name.endswith(".dex"):
                    continue
                data = zf.read(name)
                for m in re.finditer(rb"[\x20-\x7e]{8,200}", data):
                    s = m.group(0).decode("ascii", errors="replace")
                    for hit in scan_text_for_rules(s):
                        key = (hit["rule_id"], s[:80].lower())
                        if key in seen:
                            continue
                        seen.add(key)
                        hit["location"] = {"file": path_str, "line": None}
                        hit["source"] = "sast"
                        findings.append(hit)
    except Exception:
        pass
    return findings


def _run_dex_androguard(path_str: str, d, dx) -> List[Dict[str, Any]]:
    """Optional: run DEX rules using androguard Analysis string tables."""
    findings: List[Dict[str, Any]] = []
    seen: set = set()

    for dex in d:
        try:
            strings = dex.get_strings() if hasattr(dex, "get_strings") else _get_strings_from_analysis(dex, dx)
        except Exception:
            strings = []
        for s in strings:
            if not isinstance(s, str):
                s = str(s) if s is not None else ""
            for hit in scan_text_for_rules(s):
                key = (hit["rule_id"], s.lower()[:80])
                if key in seen:
                    continue
                seen.add(key)
                hit["location"] = {"file": path_str, "line": None}
                hit["source"] = "sast"
                findings.append(hit)

        try:
            for cls in dex.get_classes():
                name = getattr(cls, "get_name", lambda: None)()
                if not name:
                    continue
                name_str = str(name)
                for hit in scan_text_for_rules(name_str, include_vague=False):
                    key = (hit["rule_id"], name_str.lower()[:80])
                    if key in seen:
                        continue
                    seen.add(key)
                    hit["message"] = hit["message"].replace("(seen:", f"(class: {name_str}; seen:")
                    hit["location"] = {"file": path_str, "line": None}
                    hit["source"] = "sast"
                    findings.append(hit)
        except Exception:
            pass

    return findings


def _get_strings_from_analysis(dex, dx) -> List[str]:
    """Fallback: try to get strings from analysis or dex internals."""
    out: List[str] = []
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


def _dedupe(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: set = set()
    out: List[Dict[str, Any]] = []
    for f in findings:
        key = (f.get("rule_id"), (f.get("message") or "")[:100])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
