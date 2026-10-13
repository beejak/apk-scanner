"""IPA metadata via ZIP + plistlib (Info.plist)."""

import zipfile
import plistlib
from pathlib import Path


def extract_ipa(path: Path) -> dict:
    with zipfile.ZipFile(path, "r") as zf:
        names = zf.namelist()
        plist_path = None
        for n in names:
            if "Payload/" in n and n.endswith("Info.plist"):
                plist_path = n
                break
        if not plist_path:
            return {"error": "Info.plist not found in IPA"}
        data = zf.read(plist_path)
    info = plistlib.loads(data)
    return {
        "bundle_id": info.get("CFBundleIdentifier"),
        "version": info.get("CFBundleShortVersionString"),
        "build": info.get("CFBundleVersion"),
        "display_name": info.get("CFBundleDisplayName") or info.get("CFBundleName"),
        "min_os_version": info.get("MinimumOSVersion"),
        "file_count": len(names),
    }
