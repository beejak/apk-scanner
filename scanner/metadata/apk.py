"""APK metadata via apk-info; ZIP crumbs when apk-info is missing."""

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

    # usesCleartextTraffic when apk-info exposes it
    cleartext = None
    for meth_name in (
        "get_application_uses_cleartext_traffic",
        "get_uses_cleartext_traffic",
        "uses_cleartext_traffic",
    ):
        meth = getattr(apk, meth_name, None)
        if callable(meth):
            try:
                cleartext = meth()
                break
            except Exception:
                pass
        elif meth is not None and not callable(meth):
            cleartext = meth
            break
    if cleartext is not None:
        meta["uses_cleartext_traffic"] = bool(cleartext)

    meta["activities"] = _components(apk, "get_activities")
    meta["services"] = _components(apk, "get_services")
    meta["receivers"] = _components(apk, "get_receivers")
    meta["providers"] = _components(apk, "get_providers")

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


def _components(apk, method_name: str) -> list:
    """Return list of {name, exported, permission} for a component getter."""
    try:
        getter = getattr(apk, method_name, None)
        if not callable(getter):
            return []
        items = getter() or []
        out = []
        for c in items:
            perm = getattr(c, "permission", None)
            # Normalize empty string to None
            if isinstance(perm, str) and not perm.strip():
                perm = None
            exported = getattr(c, "exported", None)
            if isinstance(exported, str):
                el = exported.strip().lower()
                if el in ("true", "1", "yes"):
                    exported = True
                elif el in ("false", "0", "no"):
                    exported = False
            out.append({
                "name": getattr(c, "name", None) or getattr(c, "get_name", lambda: "?")(),
                "exported": exported,
                "permission": perm,
            })
        return out
    except Exception:
        return []


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
            # Best-effort: scan UTF-8 XML resources for cleartext flags (binary AXML won't match)
            for name in names:
                ln = name.lower()
                if not (ln.endswith(".xml") or "network_security" in ln):
                    continue
                try:
                    raw = zf.read(name)
                except Exception:
                    continue
                if b"\x00" in raw[:64]:
                    continue
                try:
                    text = raw.decode("utf-8", errors="ignore").lower()
                except Exception:
                    continue
                if "usescleartexttraffic" in text and "true" in text:
                    meta["uses_cleartext_traffic"] = True
                if "cleartexttraffickermitted" in text and "true" in text:
                    meta["uses_cleartext_traffic"] = True
            return meta
    except Exception as e:
        return {"error": str(e)}
