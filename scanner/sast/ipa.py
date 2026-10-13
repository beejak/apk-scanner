"""
IPA (iOS) SAST: plist security settings and constrained binary string scan.
"""

import plistlib
import re
import zipfile
from pathlib import Path
from typing import Any, Dict, List

from .patterns import ipa_id_map, scan_text_for_rules


def run_ipa_rules(ipa_path: Path, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check IPA Info.plist and Payload for insecure settings and patterns."""
    findings: List[Dict[str, Any]] = []
    path_str = str(ipa_path)
    id_map = ipa_id_map()

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
                # Exception domains with NSExceptionAllowsInsecureHTTPLoads
                if isinstance(ats, dict):
                    exc = ats.get("NSExceptionDomains")
                    if isinstance(exc, dict):
                        for domain, cfg in exc.items():
                            if isinstance(cfg, dict) and cfg.get("NSExceptionAllowsInsecureHTTPLoads") is True:
                                findings.append({
                                    "rule_id": "ipa-exception-insecure-http",
                                    "severity": "medium",
                                    "message": (
                                        f"NSExceptionAllowsInsecureHTTPLoads for domain {domain}."
                                    ),
                                    "location": {"file": path_str, "line": None},
                                    "masvs_id": "MASVS-NETWORK-1",
                                    "source": "sast",
                                })
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

            seen: set = set()
            for name in zf.namelist():
                if "Payload/" not in name or ".app/" not in name:
                    continue
                if not name.endswith(".app/") and "/" in name.rstrip("/"):
                    base = name.split("/")[-1]
                    if base in ("Info.plist", "PkgInfo"):
                        continue
                    try:
                        data = zf.read(name)[: 2 * 1024 * 1024]
                    except Exception:
                        continue
                    for m in re.finditer(rb"[\x20-\x7e]{8,200}", data):
                        s = m.group(0).decode("ascii", errors="replace")
                        for hit in scan_text_for_rules(s, id_map=id_map):
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
