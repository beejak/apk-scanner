"""
DAST: dynamic analysis (emulator/simulator + Frida).
Contract: run_dast(path, artifact_type, metadata) -> list of finding dicts.
Finding: { rule_id, severity, message, location?, evidence?, source: "dynamic" }
Only runs for artifact_type in ("apk", "ipa"); otherwise returns [].
"""

import logging
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


def run_dast(
    path: Path,
    artifact_type: str,
    metadata: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Run DAST for one artifact (APK or IPA). Returns list of runtime findings.
    When environment is unavailable (no emulator, no Frida), returns [] and logs.
    """
    path = Path(path) if not isinstance(path, Path) else path
    if artifact_type == "apk":
        return _run_android(path, metadata)
    if artifact_type == "ipa":
        return _run_ios(path, metadata)
    return []


def _run_android(path: Path, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Android: AVD + adb install + Frida hooks. Returns runtime findings or []."""
    try:
        from .android import run_android_dast
        findings = run_android_dast(path, metadata)
        for f in findings:
            f.setdefault("source", "dynamic")
        return findings
    except ImportError as e:
        logger.debug("DAST Android module unavailable: %s", e)
        return []


def _run_ios(path: Path, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    """iOS: simulator + Frida (macOS only). Returns runtime findings or []."""
    try:
        from .ios import run_ios_dast
        findings = run_ios_dast(path, metadata)
        for f in findings:
            f.setdefault("source", "dynamic")
        return findings
    except ImportError as e:
        logger.debug("DAST iOS module unavailable: %s", e)
        return []
