"""APK metadata via apk-info."""

import zipfile
from pathlib import Path


def extract_apk(path: Path) -> dict:
    try:
        from apk_info import APK
    except ImportError:
        return _extract_apk_fallback(path)

    apk = APK(str(path))
    meta = {
        "package": apk.get_package_name(),
        "version_code": apk.get_version_code(),
        "version_name": apk.get_version_name(),
        "min_sdk": apk.get_min_sdk_version(),
        "target_sdk": apk.get_target_sdk_version(),
        "permissions": list(apk.get_permissions()) if apk.get_permissions() else [],
        "main_activity": apk.get_main_activity(),
        "main_activities": apk.get_main_activities() or [],
        "debuggable": apk.get_application_debuggable(),
        "allow_backup": apk.get_application_allow_backup(),
        "multidex": apk.is_multidex(),
    }
    try:
        meta["activities"] = [
            {"name": a.name, "exported": a.exported} for a in (apk.get_activities() or [])
        ]
    except Exception:
        meta["activities"] = []
    try:
        meta["services"] = [
            {"name": s.name, "exported": s.exported} for s in (apk.get_services() or [])
        ]
    except Exception:
        meta["services"] = []
    try:
        sigs = apk.get_signatures()
        meta["signatures"] = []
        for s in sigs or []:
            if hasattr(s, "certificates") and s.certificates:
                for c in s.certificates:
                    meta["signatures"].append(
                        {"subject": c.subject, "issuer": c.issuer, "valid_until": c.valid_until}
                    )
    except Exception:
        meta["signatures"] = []
    return meta


def _extract_apk_fallback(path: Path) -> dict:
    """No apk-info: use ZIP only (file count, manifest presence)."""
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = zf.namelist()
            meta = {"file_count": len(names)}
            if "AndroidManifest.xml" in names:
                meta["has_android_manifest"] = True
            if "META-INF/MANIFEST.MF" in names:
                meta["has_manifest_mf"] = True
            return meta
    except Exception as e:
        return {"error": str(e)}
