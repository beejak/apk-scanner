"""
SAST: static analysis findings per artifact type.
Contract: run_sast(path, artifact_type, metadata) -> list of finding dicts.
Finding: { rule_id, severity, message, location?: { file, line? }, masvs_id?, source: "sast" }

Pattern scan with constrained detectors (not full decompilation / confirmed triage).
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


def _as_bool(value: Any) -> Optional[bool]:
    """Normalize apk-info / XML-ish bools (True, 'true', '1', False, 'false')."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        s = value.strip().lower()
        if s in ("true", "1", "yes"):
            return True
        if s in ("false", "0", "no"):
            return False
        return None
    return None


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

    if _as_bool(metadata.get("debuggable")) is True:
        out.append({
            "rule_id": "apk-debuggable",
            "severity": "high",
            "message": "Application is debuggable; increases reverse-engineering risk.",
            "location": {"file": str(artifact_path), "line": None},
            "masvs_id": "MASVS-RESILIENCE-1",
            "source": "sast",
        })

    if _as_bool(metadata.get("allow_backup")) is True:
        out.append({
            "rule_id": "apk-allow-backup",
            "severity": "medium",
            "message": "allowBackup is true; app data may be backed up unencrypted.",
            "location": {"file": str(artifact_path), "line": None},
            "masvs_id": "MASVS-STORAGE-2",
            "source": "sast",
        })

    if _as_bool(metadata.get("uses_cleartext_traffic")) is True:
        out.append({
            "rule_id": "apk-cleartext-traffic",
            "severity": "high",
            "message": "usesCleartextTraffic is true; cleartext HTTP may be allowed.",
            "location": {"file": str(artifact_path), "line": None},
            "masvs_id": "MASVS-NETWORK-1",
            "source": "sast",
        })

    # Exported components without a protecting permission (when permission field present)
    for comp_list, comp_type in (
        (metadata.get("activities"), "activity"),
        (metadata.get("services"), "service"),
        (metadata.get("receivers"), "receiver"),
        (metadata.get("providers"), "provider"),
    ):
        if not isinstance(comp_list, list):
            continue
        for c in comp_list:
            if not isinstance(c, dict):
                continue
            if _as_bool(c.get("exported")) is not True:
                continue
            name = c.get("name", "?")
            perm = c.get("permission")
            # Flag only when we know permission is missing/empty (apk-info path).
            # If permission key absent entirely (legacy metadata), still flag as medium lead.
            if perm:
                continue
            out.append({
                "rule_id": "apk-exported-unprotected",
                "severity": "medium",
                "message": (
                    f"Exported {comp_type} without permission: {name}"
                    if "permission" in c
                    else f"Exported {comp_type}: {name} (permission unknown; verify protection)."
                ),
                "location": {"file": str(artifact_path), "line": None},
                "masvs_id": "MASVS-PLATFORM-1",
                "source": "sast",
            })

    return out


def _apk_sast(path: Path, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    """APK pattern-scan SAST (DEX string/metadata rules; androguard optional for strings)."""
    try:
        from .dex import run_dex_rules
        return run_dex_rules(path, metadata)
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
