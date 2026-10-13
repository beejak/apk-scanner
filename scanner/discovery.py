"""
Discovery: walk path with os.scandir, classify by type (apk, ipa, jar, so, sdk).
Returns list of (path: Path, type: str).
"""

import os
from pathlib import Path
from typing import List, Optional, Set, Tuple


def _looks_like_sdk(path: Path) -> bool:
    name = path.name.lower()
    if "sdk" in name and path.is_dir():
        return True
    if path.is_dir():
        try:
            children = [p.name.lower() for p in path.iterdir() if p.is_dir()]
        except OSError:
            return False
        indicators = ("include", "lib", "bin", "samples", "docs", "framework")
        if sum(1 for i in indicators if i in children) >= 2:
            return True
    return False


def classify(path: Path, is_file: bool) -> Optional[str]:
    """Return type string (apk, ipa, jar, so, sdk) or None if not a scan target."""
    if is_file:
        suffix = path.suffix.lower()
        if suffix == ".apk":
            return "apk"
        if suffix == ".ipa":
            return "ipa"
        if suffix == ".jar":
            return "jar"
        if suffix == ".so":
            return "so"
        return None
    if path.is_dir() and _looks_like_sdk(path):
        return "sdk"
    return None


def discover(root: Path, recursive: bool = True, types: Optional[Set[str]] = None, _recurse: bool = False) -> List[Tuple[Path, str]]:
    """
    Walk root with os.scandir; yield (path, type) for each scan target.
    types: if set, only include these (e.g. {"apk", "ipa"}). Default all.
    """
    if types is None:
        types = {"apk", "ipa", "jar", "so", "sdk"}
    results: List[Tuple[Path, str]] = []

    if root.is_file():
        t = classify(root, is_file=True)
        if t and t in types:
            results.append((root, t))
        return results

    if not root.is_dir():
        return results

    # Only add root as SDK when it's the top-level root (not when recursing), so we don't duplicate
    if not _recurse and "sdk" in types and _looks_like_sdk(root):
        results.append((root, "sdk"))

    try:
        with os.scandir(root) as it:
            for entry in it:
                p = Path(entry.path)
                try:
                    is_file = entry.is_file(follow_symlinks=False)
                except OSError:
                    continue
                t = classify(p, is_file)
                if t and t in types:
                    results.append((p, t))
                if recursive and entry.is_dir(follow_symlinks=False):
                    results.extend(discover(p, recursive=True, types=types, _recurse=True))
    except OSError:
        pass
    return results
