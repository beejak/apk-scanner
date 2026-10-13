"""
Optional jadx → nuclei file/android plugin.

When `jadx` and `nuclei` are on PATH: decompile APK to temp, run nuclei -t file/android,
merge findings, purge temp. Skip cleanly if either tool is missing.
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


def run_nuclei(apk_path: Path, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    _ = metadata
    if not shutil.which("jadx"):
        logger.info("jadx not on PATH; skip --nuclei for %s", apk_path.name)
        return []
    if not shutil.which("nuclei"):
        logger.info("nuclei not on PATH; skip --nuclei for %s", apk_path.name)
        return []

    tmp = Path(tempfile.mkdtemp(prefix="apk-scanner-nuclei-"))
    decomp = tmp / "src"
    out_jsonl = tmp / "nuclei.jsonl"
    try:
        decomp.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.run(
                ["jadx", "-d", str(decomp), "--quiet", str(apk_path)],
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.info("jadx failed: %s", e)
            return []

        if not any(decomp.rglob("*")):
            logger.info("jadx produced empty tree for %s; skip nuclei", apk_path.name)
            return []

        try:
            proc = subprocess.run(
                [
                    "nuclei",
                    "-t",
                    "file/android",
                    "-u",
                    str(decomp),
                    "-jsonl",
                    "-silent",
                    "-o",
                    str(out_jsonl),
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.info("nuclei failed: %s", e)
            return []

        lines: List[str] = []
        if out_jsonl.is_file():
            lines = out_jsonl.read_text(encoding="utf-8", errors="replace").splitlines()
        if not lines and (proc.stdout or "").strip():
            lines = proc.stdout.splitlines()

        findings: List[Dict[str, Any]] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = row.get("info") or {}
            name = info.get("name") or row.get("template-id") or "nuclei"
            sev = (info.get("severity") or "info").lower()
            if sev not in ("critical", "high", "medium", "low", "info"):
                sev = "info"
            findings.append({
                "rule_id": "plugin-nuclei-android",
                "severity": sev,
                "message": f"Nuclei {name}: {(info.get('description') or row.get('matched-at') or '')[:200]}",
                "location": {"file": str(apk_path), "line": None},
                "source": "nuclei",
                "masvs_id": "MASVS-PLATFORM-1",
                "evidence": {
                    "template_id": row.get("template-id") or row.get("templateID"),
                    "matched_at": row.get("matched-at"),
                },
            })
        return findings
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
