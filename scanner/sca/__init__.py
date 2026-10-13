"""
CVE/SCA: real OSV lookups only when component+version can be extracted.

Never invent CVE IDs. Offline / rate-limit → skip politely and leave cve null
on pattern findings; SCA findings only emitted when OSV returns vulns.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


def run_sca(
    path: Path,
    artifact_type: str,
    metadata: Dict[str, Any],
    *,
    enabled: bool = False,
    offline: bool = False,
) -> List[Dict[str, Any]]:
    if not enabled:
        return []
    if offline:
        logger.info("SCA offline (--sca-offline or no network); skip CVE lookup for %s", path.name)
        return []
    try:
        from .extract import extract_components
        from .osv import query_osv

        comps = extract_components(path, artifact_type, metadata)
        if not comps:
            logger.info("SCA: no component+version extracted for %s; skip", path.name)
            return []
        findings: List[Dict[str, Any]] = []
        for comp in comps:
            vulns = query_osv(comp["name"], comp["version"], ecosystem=comp.get("ecosystem"))
            for v in vulns:
                cve_ids = v.get("aliases") or []
                cve_ids = [a for a in cve_ids if str(a).startswith("CVE-")]
                if not cve_ids and v.get("id", "").startswith("CVE-"):
                    cve_ids = [v["id"]]
                # Only emit when we have a real advisory id from OSV (CVE or GHSA/OSV id)
                adv_id = cve_ids[0] if cve_ids else v.get("id")
                if not adv_id:
                    continue
                findings.append({
                    "rule_id": "sca-osv-vuln",
                    "severity": _sev_from_osv(v),
                    "message": (
                        f"OSV: {comp['name']}@{comp['version']} affected by {adv_id}"
                        f" — {(v.get('summary') or '')[:160]}"
                    ),
                    "location": {"file": str(path), "line": None},
                    "source": "sca",
                    "masvs_id": "MASVS-CODE-1",
                    "cve": cve_ids or None,
                    "evidence": {
                        "package": comp["name"],
                        "version": comp["version"],
                        "ecosystem": comp.get("ecosystem"),
                        "osv_id": v.get("id"),
                        "aliases": v.get("aliases") or [],
                    },
                })
        return findings
    except Exception as e:
        logger.info("SCA skipped: %s", e)
        return []


def _sev_from_osv(v: Dict[str, Any]) -> str:
    sev = (v.get("database_specific") or {}).get("severity") or ""
    sev = str(sev).upper()
    if sev in ("CRITICAL",):
        return "critical"
    if sev in ("HIGH",):
        return "high"
    if sev in ("MODERATE", "MEDIUM"):
        return "medium"
    if sev in ("LOW",):
        return "low"
    # Default medium when OSV returned a vuln but no severity band
    return "medium"
