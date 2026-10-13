"""
Optional external SAST backends (off by default).

Each plugin merges findings into the same schema. Missing tools → log + skip
(never fail the scan).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


def run_plugins(
    path: Path,
    artifact_type: str,
    metadata: Dict[str, Any],
    *,
    apkid: bool = False,
    semgrep: bool = False,
    mobsfscan: bool = False,
) -> List[Dict[str, Any]]:
    """Run enabled plugins for one artifact; return merged finding list."""
    out: List[Dict[str, Any]] = []
    path = Path(path)
    if apkid and artifact_type == "apk":
        try:
            from .apkid_plugin import run_apkid

            out.extend(run_apkid(path, metadata))
        except Exception as e:
            logger.info("APKiD plugin skipped: %s", e)
    if semgrep and artifact_type in ("apk", "jar", "sdk"):
        try:
            from .semgrep_plugin import run_semgrep

            out.extend(run_semgrep(path, artifact_type, metadata))
        except Exception as e:
            logger.info("Semgrep plugin skipped: %s", e)
    if mobsfscan and artifact_type in ("apk", "ipa"):
        try:
            from .mobsfscan_plugin import run_mobsfscan

            out.extend(run_mobsfscan(path, artifact_type, metadata))
        except Exception as e:
            logger.info("mobsfscan plugin skipped: %s", e)
    for f in out:
        f.setdefault("source", "plugin")
    return out
