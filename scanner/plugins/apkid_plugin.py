"""
Optional APKiD subprocess backend (packer / compiler / obfuscator tags).

Requires `apkid` on PATH. Graceful skip if missing.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


def run_apkid(apk_path: Path, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    _ = metadata
    if not shutil.which("apkid"):
        logger.info("APKiD not on PATH; skip --apkid for %s", apk_path.name)
        return []
    try:
        proc = subprocess.run(
            ["apkid", "-j", str(apk_path)],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.info("APKiD failed: %s", e)
        return []
    if proc.returncode != 0 and not proc.stdout.strip():
        logger.info("APKiD exited %s; skip", proc.returncode)
        return []
    findings: List[Dict[str, Any]] = []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        # Some versions print multiple JSON objects / non-strict output
        text = (proc.stdout or "").strip()
        if not text:
            return []
        findings.append({
            "rule_id": "plugin-apkid-tag",
            "severity": "info",
            "message": f"APKiD raw output (parse failed): {text[:200]}",
            "location": {"file": str(apk_path), "line": None},
            "source": "plugin",
            "masvs_id": "MASVS-RESILIENCE-1",
        })
        return findings

    files = data if isinstance(data, list) else data.get("files") or data.get("results") or [data]
    if isinstance(files, dict):
        files = [files]
    for entry in files:
        if not isinstance(entry, dict):
            continue
        matches = entry.get("matches") or entry.get("results") or {}
        if isinstance(matches, dict):
            for kind, tags in matches.items():
                tag_list = tags if isinstance(tags, list) else [tags]
                tag_str = ", ".join(str(t) for t in tag_list)
                findings.append({
                    "rule_id": "plugin-apkid-tag",
                    "severity": "info",
                    "message": f"APKiD {kind}: {tag_str}",
                    "location": {"file": str(apk_path), "line": None},
                    "source": "plugin",
                    "masvs_id": "MASVS-RESILIENCE-1",
                    "evidence": {"apkid": {kind: tag_list}},
                })
        elif isinstance(matches, list):
            for m in matches:
                findings.append({
                    "rule_id": "plugin-apkid-tag",
                    "severity": "info",
                    "message": f"APKiD match: {m}",
                    "location": {"file": str(apk_path), "line": None},
                    "source": "plugin",
                    "masvs_id": "MASVS-RESILIENCE-1",
                })
    return findings
