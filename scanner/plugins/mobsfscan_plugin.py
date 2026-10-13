"""
Optional mobsfscan subprocess backend.

Requires `mobsfscan` on PATH. Graceful skip if missing.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


def run_mobsfscan(
    path: Path,
    artifact_type: str,
    metadata: Dict[str, Any],
) -> List[Dict[str, Any]]:
    _ = metadata
    if not shutil.which("mobsfscan"):
        logger.info("mobsfscan not on PATH; skip --mobsfscan for %s", path.name)
        return []

    with tempfile.TemporaryDirectory(prefix="apk-scanner-mobsf-") as td:
        out_json = Path(td) / "mobsf.json"
        try:
            proc = subprocess.run(
                ["mobsfscan", str(path), "-o", str(out_json), "-j"],
                capture_output=True,
                text=True,
                timeout=300,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.info("mobsfscan failed: %s", e)
            return []

        raw = ""
        if out_json.is_file():
            raw = out_json.read_text(encoding="utf-8", errors="replace")
        elif proc.stdout.strip():
            raw = proc.stdout
        if not raw.strip():
            logger.info("mobsfscan produced no output for %s", path.name)
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            logger.info("mobsfscan JSON parse failed for %s", path.name)
            return []

    findings: List[Dict[str, Any]] = []
    # mobsfscan shapes vary; collect common keys
    results = data.get("results") or data.get("nodejs") or data.get("findings") or data
    if isinstance(results, dict):
        for rule_name, payload in results.items():
            if not isinstance(payload, dict):
                continue
            meta = payload.get("metadata") or {}
            sev = (meta.get("severity") or payload.get("severity") or "WARNING").lower()
            severity = {
                "error": "high",
                "warning": "medium",
                "info": "info",
                "critical": "critical",
                "high": "high",
                "medium": "medium",
                "low": "low",
            }.get(sev, "medium")
            desc = meta.get("description") or payload.get("message") or rule_name
            findings.append({
                "rule_id": "plugin-mobsfscan",
                "severity": severity,
                "message": f"mobsfscan {rule_name}: {desc}",
                "location": {"file": str(path), "line": None},
                "source": "plugin",
                "masvs_id": "MASVS-CODE-1",
                "evidence": {"mobsfscan_rule": rule_name, "artifact_type": artifact_type},
            })
    elif isinstance(results, list):
        for item in results:
            if not isinstance(item, dict):
                continue
            findings.append({
                "rule_id": "plugin-mobsfscan",
                "severity": "medium",
                "message": f"mobsfscan: {item.get('message') or item.get('rule') or item}",
                "location": {"file": str(path), "line": None},
                "source": "plugin",
                "masvs_id": "MASVS-CODE-1",
            })
    return findings
