"""
Optional Semgrep subprocess backend. Merges JSON results into scanner findings.

Requires `semgrep` on PATH. Uses p/security-audit if no config given.
Graceful skip if missing. Not a substitute for built-in pattern SAST.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


def run_semgrep(
    path: Path,
    artifact_type: str,
    metadata: Dict[str, Any],
) -> List[Dict[str, Any]]:
    _ = metadata
    if not shutil.which("semgrep"):
        logger.info("semgrep not on PATH; skip --semgrep for %s", path.name)
        return []

    # Semgrep needs source-like trees; for APK/JAR we scan extracted text crumbs in a temp dir
    # when the path is a single archive — otherwise scan directory as-is.
    scan_target = path
    tmp: Path | None = None
    try:
        if path.is_file() and artifact_type in ("apk", "jar"):
            tmp = Path(tempfile.mkdtemp(prefix="apk-scanner-semgrep-"))
            _extract_textish(path, tmp)
            scan_target = tmp
        config = os.environ.get("APK_SCANNER_SEMGREP_CONFIG", "p/security-audit")
        proc = subprocess.run(
            [
                "semgrep",
                "--config",
                config,
                "--json",
                "--quiet",
                "--timeout",
                "30",
                str(scan_target),
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.info("Semgrep failed: %s", e)
        return []
    finally:
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)

    if not proc.stdout.strip():
        logger.info("Semgrep produced no JSON for %s (exit %s)", path.name, proc.returncode)
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        logger.info("Semgrep JSON parse failed for %s", path.name)
        return []

    findings: List[Dict[str, Any]] = []
    for r in data.get("results") or []:
        check_id = r.get("check_id") or "semgrep"
        msg = (r.get("extra") or {}).get("message") or r.get("message") or check_id
        sev = ((r.get("extra") or {}).get("severity") or "WARNING").lower()
        severity = {"error": "high", "warning": "medium", "info": "info"}.get(sev, "medium")
        if sev in ("critical", "high", "medium", "low", "info"):
            severity = sev
        start = (r.get("start") or {})
        findings.append({
            "rule_id": "plugin-semgrep",
            "severity": severity,
            "message": f"Semgrep {check_id}: {msg}",
            "location": {
                "file": str(path),
                "line": start.get("line"),
            },
            "source": "plugin",
            "masvs_id": "MASVS-CODE-1",
            "evidence": {"semgrep_check_id": check_id, "path": r.get("path")},
        })
    return findings


def _extract_textish(archive: Path, dest: Path) -> None:
    import zipfile

    try:
        with zipfile.ZipFile(archive, "r") as zf:
            for name in zf.namelist()[:200]:
                lower = name.lower()
                if not any(lower.endswith(ext) for ext in (
                    ".xml", ".properties", ".json", ".txt", ".smali", ".java", ".kt",
                )):
                    continue
                try:
                    data = zf.read(name)
                except Exception:
                    continue
                if b"\x00" in data[:64]:
                    continue
                out = dest / Path(name).name
                try:
                    out.write_bytes(data[:200_000])
                except OSError:
                    pass
    except Exception as e:
        logger.debug("Semgrep extract failed: %s", e)
