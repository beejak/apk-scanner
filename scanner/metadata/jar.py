"""JAR metadata via ZIP + META-INF/MANIFEST.MF."""

import zipfile
from pathlib import Path


def _parse_manifest(data: bytes) -> dict:
    text = data.decode("utf-8", errors="replace")
    attrs = {}
    current = None
    for line in text.splitlines():
        if line.startswith(" "):
            if current is not None:
                attrs[current] = (attrs.get(current) or "") + line.strip()
            continue
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            if key:
                current = key
                attrs[key] = val
    return attrs


def extract_jar(path: Path) -> dict:
    with zipfile.ZipFile(path, "r") as zf:
        names = zf.namelist()
        if "META-INF/MANIFEST.MF" not in names:
            return {"file_count": len(names), "error": "MANIFEST.MF not found"}
        data = zf.read("META-INF/MANIFEST.MF")
    manifest = _parse_manifest(data)
    return {
        "file_count": len(names),
        "manifest_version": manifest.get("Manifest-Version"),
        "main_class": manifest.get("Main-Class"),
        "created_by": manifest.get("Created-By"),
        **{k: v for k, v in manifest.items() if k not in ("Manifest-Version", "Main-Class", "Created-By")},
    }
