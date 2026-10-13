"""
Optional Quark-Engine subprocess backend (malware behavior / family scoring hints).

Requires `quark` on PATH. Graceful skip if missing.
Honesty: behavior score / family hints from Quark rules — not an AV verdict.
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


def run_quark(apk_path: Path, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    _ = metadata
    if not shutil.which("quark"):
        logger.info("quark not on PATH; skip --quark for %s", apk_path.name)
        return []

    tmp_dir = Path(tempfile.mkdtemp(prefix="apk-scanner-quark-"))
    out_json = tmp_dir / "quark-report.json"
    try:
        # Quark-Engine: quark -a APK --json OUT (versions vary; try common forms)
        proc = subprocess.run(
            ["quark", "-a", str(apk_path), "--json", str(out_json)],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if not out_json.is_file() or out_json.stat().st_size == 0:
            proc = subprocess.run(
                ["quark", "-a", str(apk_path), "-o", str(out_json)],
                capture_output=True,
                text=True,
                timeout=300,
            )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.info("Quark failed: %s", e)
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return []

    data: Any = None
    if out_json.is_file() and out_json.stat().st_size > 0:
        try:
            data = json.loads(out_json.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            data = None
    if data is None and (proc.stdout or "").strip():
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            logger.info(
                "Quark produced non-JSON for %s (exit %s); skip merge",
                apk_path.name,
                proc.returncode,
            )
            shutil.rmtree(tmp_dir, ignore_errors=True)
            return []

    shutil.rmtree(tmp_dir, ignore_errors=True)
    if data is None:
        logger.info("Quark no report for %s; skip", apk_path.name)
        return []

    return _findings_from_quark(apk_path, data)


def _findings_from_quark(apk_path: Path, data: Any) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    # Quark JSON shapes differ by version; accept common keys
    crime_list = []
    if isinstance(data, dict):
        crime_list = (
            data.get("crimes")
            or data.get("rule_results")
            or data.get("results")
            or []
        )
        score = data.get("threat_level") or data.get("score") or data.get("total_score")
        if score is not None:
            findings.append({
                "rule_id": "plugin-quark-score",
                "severity": "info",
                "message": (
                    f"Quark behavior score/threat hint: {score} "
                    "(family/behavior scoring — not an AV verdict)"
                ),
                "location": {"file": str(apk_path), "line": None},
                "source": "quark",
                "masvs_id": "MASVS-RESILIENCE-1",
                "evidence": {"quark_score": score},
            })
    elif isinstance(data, list):
        crime_list = data

    if not isinstance(crime_list, list):
        crime_list = []

    for entry in crime_list[:40]:
        if not isinstance(entry, dict):
            continue
        crime = (
            entry.get("crime")
            or entry.get("rule")
            or entry.get("description")
            or entry.get("name")
            or "quark-rule"
        )
        conf = entry.get("confidence") or entry.get("score") or entry.get("weight")
        family = entry.get("label") or entry.get("family") or entry.get("malware")
        parts = [f"Quark rule: {crime}"]
        if family:
            parts.append(f"family/label hint: {family}")
        if conf is not None:
            parts.append(f"confidence/score: {conf}")
        parts.append("(behavior lead, not confirmed malware)")
        sev = "medium"
        try:
            if conf is not None and float(conf) >= 80:
                sev = "high"
        except (TypeError, ValueError):
            pass
        findings.append({
            "rule_id": "plugin-quark-behavior",
            "severity": sev,
            "message": " — ".join(parts),
            "location": {"file": str(apk_path), "line": None},
            "source": "quark",
            "masvs_id": "MASVS-RESILIENCE-1",
            "evidence": {"quark": entry},
        })

    if not findings and isinstance(data, dict):
        findings.append({
            "rule_id": "plugin-quark-score",
            "severity": "info",
            "message": "Quark ran but returned no crimes/score keys to map (see evidence).",
            "location": {"file": str(apk_path), "line": None},
            "source": "quark",
            "masvs_id": "MASVS-RESILIENCE-1",
            "evidence": {"quark_keys": list(data.keys())[:30]},
        })
    return findings
