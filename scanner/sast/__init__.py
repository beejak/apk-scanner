"""
SAST: static analysis findings per artifact type.
Contract: run_sast(path, artifact_type, metadata) -> list of finding dicts.
Finding: { rule_id, severity, message, location?: { file, line? }, masvs_id?, source: "sast" }
"""

from pathlib import Path
from typing import Any, Dict, List, Optional


def run_sast(
    path: Path,
    artifact_type: str,
    metadata: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Run SAST for one artifact. Returns list of findings.
    """
    findings: List[Dict[str, Any]] = []
    path = Path(path) if not isinstance(path, Path) else path

    # Metadata-based rules (APK, etc.)
    findings.extend(_metadata_rules(artifact_type, metadata, path))

    # Type-specific analysis
    if artifact_type == "apk":
        findings.extend(_apk_sast(path, metadata))
    elif artifact_type == "so":
        findings.extend(_so_sast(path, metadata))
    elif artifact_type == "jar":
        findings.extend(_jar_sast(path))
    elif artifact_type == "ipa":
        findings.extend(_ipa_sast(path, metadata))
    elif artifact_type == "sdk":
        findings.extend(_sdk_sast(path, metadata))

    return findings


def _metadata_rules(
    artifact_type: str,
    metadata: Dict[str, Any],
    artifact_path: Path,
) -> List[Dict[str, Any]]:
    """Rules that only need metadata (no DEX/binary parsing)."""
    out: List[Dict[str, Any]] = []
    if artifact_type != "apk":
        return out
    err = metadata.get("error")
    if err:
        return out

    # MASVS-RESILIENCE: debuggable in release
    if metadata.get("debuggable") is True:
        out.append({
            "rule_id": "apk-debuggable",
            "severity": "high",
            "message": "Application is debuggable; increases reverse-engineering risk.",
            "location": {"file": str(artifact_path), "line": None},
            "masvs_id": "MASVS-RESILIENCE-1",
            "source": "sast",
        })

    # MASVS-STORAGE: allowBackup can leak data
    if metadata.get("allow_backup") is True:
        out.append({
            "rule_id": "apk-allow-backup",
            "severity": "medium",
            "message": "allowBackup is true; app data may be backed up unencrypted.",
            "location": {"file": str(artifact_path), "line": None},
            "masvs_id": "MASVS-STORAGE-2",
            "source": "sast",
        })

    # Exported components without permission (simplified: we only flag if we have components)
    for comp_list, comp_type in [(metadata.get("activities"), "activity"), (metadata.get("services"), "service")]:
        if not isinstance(comp_list, list):
            continue
        for c in comp_list:
            if isinstance(c, dict) and c.get("exported") is True:
                name = c.get("name", "?")
                out.append({
                    "rule_id": "apk-exported-component",
                    "severity": "medium",
                    "message": f"Exported {comp_type}: {name} (ensure proper permission or intent-filter).",
                    "location": {"file": str(artifact_path), "line": None},
                    "masvs_id": "MASVS-PLATFORM-1",
                    "source": "sast",
                })

    return out


def _apk_sast(path: Path, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    """DEX-based and APK-specific SAST (androguard if available)."""
    try:
        from .dex import run_dex_rules
        return run_dex_rules(path)
    except ImportError:
        return []


def _so_sast(path: Path, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Native .so string/symbol pattern checks."""
    try:
        from .native import run_native_rules
        return run_native_rules(path, metadata)
    except Exception:
        return []


def _jar_sast(path: Path) -> List[Dict[str, Any]]:
    """JAR (Java) string/pattern scan."""
    try:
        from .jar import run_jar_rules
        return run_jar_rules(path)
    except Exception:
        return []


def _ipa_sast(path: Path, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    """IPA plist and binary pattern checks."""
    try:
        from .ipa import run_ipa_rules
        return run_ipa_rules(path, metadata)
    except Exception:
        return []


def _sdk_sast(path: Path, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    """SDK directory sensitive files and credential patterns."""
    try:
        from .sdk import run_sdk_rules
        return run_sdk_rules(path, metadata)
    except Exception:
        return []
