"""
IPA (iOS) SAST: plist security settings and optional binary string scan.
"""

import plistlib
import re
import zipfile
from pathlib import Path
from typing import Any, Dict, List


def run_ipa_rules(ipa_path: Path, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check IPA Info.plist and Payload for insecure settings and patterns. Returns list of findings."""
    findings: List[Dict[str, Any]] = []
    path_str = str(ipa_path)

    # 1) Plist-based: read Info.plist from IPA
    try:
        with zipfile.ZipFile(ipa_path, "r") as zf:
            plist_path = None
            for n in zf.namelist():
                if "Payload/" in n and n.endswith("Info.plist"):
                    plist_path = n
                    break
            if plist_path:
                data = zf.read(plist_path)
                info = plistlib.loads(data)
                # NSAppTransportSecurity -> NSAllowsArbitraryLoads = true
                ats = info.get("NSAppTransportSecurity")
                if isinstance(ats, dict) and ats.get("NSAllowsArbitraryLoads") is True:
                    findings.append({
                        "rule_id": "ipa-allow-arbitrary-loads",
                        "severity": "high",
                        "message": "NSAllowsArbitraryLoads is true; allows cleartext HTTP.",
                        "location": {"file": path_str, "line": None},
                        "masvs_id": "MASVS-NETWORK-1",
                        "source": "sast",
                    })
                if isinstance(ats, dict) and ats.get("NSAllowsLocalNetworking") is True:
                    findings.append({
                        "rule_id": "ipa-allow-local-networking",
                        "severity": "medium",
                        "message": "NSAllowsLocalNetworking is true; ensure local traffic is safe.",
                        "location": {"file": path_str, "line": None},
                        "masvs_id": "MASVS-NETWORK-1",
                        "source": "sast",
                    })
                # UIFileSharingEnabled / LSSupportsOpeningDocumentsInPlace
                if info.get("UIFileSharingEnabled") is True:
                    findings.append({
                        "rule_id": "ipa-file-sharing",
                        "severity": "medium",
                        "message": "UIFileSharingEnabled allows file access from Files app; protect sensitive data.",
                        "location": {"file": path_str, "line": None},
                        "masvs_id": "MASVS-STORAGE-2",
                        "source": "sast",
                    })
                if info.get("LSSupportsOpeningDocumentsInPlace") is True:
                    findings.append({
                        "rule_id": "ipa-documents-in-place",
                        "severity": "low",
                        "message": "LSSupportsOpeningDocumentsInPlace is true; ensure document scope is appropriate.",
                        "location": {"file": path_str, "line": None},
                        "masvs_id": "MASVS-STORAGE-2",
                        "source": "sast",
                    })

            # 2) Binary string scan in Payload/*.app (first 2MB of executables)
            seen: set = set()
            for name in zf.namelist():
                if "Payload/" not in name or ".app/" not in name:
                    continue
                if not name.endswith(".app/") and "/" in name.rstrip("/"):
                    base = name.split("/")[-1]
                    if base in ("Info.plist", "PkgInfo"):
                        continue
                    # Binary or plist
                    try:
                        data = zf.read(name)[: 2 * 1024 * 1024]
                    except Exception:
                        continue
                    for m in re.finditer(rb"[\x20-\x7e]{8,200}", data):
                        s = m.group(0).decode("ascii", errors="replace").lower()
                        for pattern, rule_id, severity, message, masvs_id in _IPA_PATTERNS:
                            if pattern in s:
                                key = (rule_id, s[:80])
                                if key in seen:
                                    continue
                                seen.add(key)
                                findings.append({
                                    "rule_id": rule_id,
                                    "severity": severity,
                                    "message": f"{message} (in IPA: {s[:50]}...)",
                                    "location": {"file": path_str, "line": None},
                                    "masvs_id": masvs_id,
                                    "source": "sast",
                                })
    except Exception:
        pass
    return findings


_IPA_PATTERNS = [
    ("password", "ipa-hardcoded-password", "high", "Possible hardcoded password in IPA.", "MASVS-AUTH-4"),
    ("api_key", "ipa-hardcoded-apikey", "high", "Possible hardcoded API key in IPA.", "MASVS-AUTH-4"),
    ("apikey", "ipa-hardcoded-apikey", "high", "Possible hardcoded API key in IPA.", "MASVS-AUTH-4"),
    ("secret", "ipa-hardcoded-secret", "medium", "Possible hardcoded secret in IPA.", "MASVS-CRYPTO-1"),
    ("http://", "ipa-cleartext", "medium", "Cleartext HTTP URL in IPA; use HTTPS.", "MASVS-NETWORK-1"),
]
