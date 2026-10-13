#!/usr/bin/env python3
"""
APK, IPA, JAR, and SDK scanner.
Finds and reports these file types; extracts basic metadata where possible.
"""

import argparse
import json
import os
import zipfile
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ScanResult:
    path: str
    type: str  # apk, ipa, jar, sdk
    size_bytes: int
    metadata: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)


def is_apk(path: Path) -> bool:
    return path.suffix.lower() == ".apk"


def is_ipa(path: Path) -> bool:
    return path.suffix.lower() == ".ipa"


def is_jar(path: Path) -> bool:
    return path.suffix.lower() == ".jar"


def looks_like_sdk(path: Path) -> bool:
    """Heuristic: dirs named *sdk*, *SDK*, or containing typical SDK layout."""
    name = path.name.lower()
    if "sdk" in name and path.is_dir():
        return True
    if path.is_dir():
        # Common SDK indicators
        indicators = ("include", "lib", "bin", "samples", "docs", "framework")
        children = [p.name.lower() for p in path.iterdir() if p.is_dir()]
        if sum(1 for i in indicators if i in children) >= 2:
            return True
    return False


def read_zip_metadata(zip_path: Path) -> dict:
    meta = {}
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            meta["file_count"] = len(zf.namelist())
            # JAR/APK: look for MANIFEST or AndroidManifest
            for name in ("META-INF/MANIFEST.MF", "AndroidManifest.xml"):
                if name in zf.namelist():
                    meta["has_" + name.replace("/", "_").replace(".", "_").lower()] = True
            # IPA: Payload/*.app
            names = zf.namelist()
            if any(n.startswith("Payload/") and n.endswith(".app/") for n in names):
                meta["ipa_app_bundle"] = True
    except (zipfile.BadZipFile, OSError) as e:
        meta["error"] = str(e)
    return meta


def scan_file(path: Path) -> Optional[ScanResult]:
    if not path.is_file():
        return None
    suffix = path.suffix.lower()
    size = path.stat().st_size
    meta = {}
    notes = []

    if is_apk(path):
        meta = read_zip_metadata(path)
        return ScanResult(str(path), "apk", size, meta, notes)
    if is_ipa(path):
        meta = read_zip_metadata(path)
        return ScanResult(str(path), "ipa", size, meta, notes)
    if is_jar(path):
        meta = read_zip_metadata(path)
        return ScanResult(str(path), "jar", size, meta, notes)

    return None


def scan_directory(root: Path, recursive: bool = True) -> list[ScanResult]:
    results = []
    walk = root.rglob("*") if recursive else root.iterdir()

    for p in walk:
        if p.is_file():
            res = scan_file(p)
            if res:
                results.append(res)
        elif p.is_dir() and looks_like_sdk(p):
            size = sum(f.stat().st_size for f in p.rglob("*") if f.is_file())
            results.append(
                ScanResult(
                    str(p),
                    "sdk",
                    size,
                    {"directory": True, "entries": len(list(p.rglob("*")))},
                    [],
                )
            )

    return results


def format_size(n: int) -> str:
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n} {u}"
        n //= 1024
    return f"{n} TB"


def main():
    parser = argparse.ArgumentParser(description="Scan for APK, IPA, JAR, and SDK files")
    parser.add_argument("path", nargs="?", default=".", type=Path, help="Path to scan")
    parser.add_argument("-r", "--recursive", action="store_true", default=True, help="Recurse into directories")
    parser.add_argument("--no-recursive", action="store_false", dest="recursive", help="Do not recurse")
    parser.add_argument("-o", "--output", choices=("text", "json"), default="text", help="Output format")
    parser.add_argument("--types", nargs="+", default=["apk", "ipa", "jar", "sdk"], help="Types to include")
    args = parser.parse_args()

    root = args.path.resolve()
    if not root.exists():
        print(f"Error: path does not exist: {root}")
        return 1

    results = scan_directory(root, recursive=args.recursive)
    results = [r for r in results if r.type in args.types]

    if args.output == "json":
        out = [
            {
                "path": r.path,
                "type": r.type,
                "size_bytes": r.size_bytes,
                "metadata": r.metadata,
                "notes": r.notes,
            }
            for r in results
        ]
        print(json.dumps(out, indent=2))
    else:
        by_type = {}
        for r in results:
            by_type.setdefault(r.type, []).append(r)
        for t in ("apk", "ipa", "jar", "sdk"):
            if t not in by_type:
                continue
            print(f"\n=== {t.upper()} ({len(by_type[t])}) ===")
            for r in by_type[t]:
                print(f"  {r.path}")
                print(f"    size: {format_size(r.size_bytes)}")
                if r.metadata:
                    for k, v in r.metadata.items():
                        print(f"    {k}: {v}")

    print(f"\nTotal: {len(results)} item(s)")
    return 0


if __name__ == "__main__":
    exit(main())
