"""
Extract (name, version, ecosystem) candidates from artifacts.

Only emit pairs when both name and version look real — never guess CVEs without versions.
"""

from __future__ import annotations

import re
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# name-version.jar / name-version.aar
_JAR_VER = re.compile(
    r"^(?P<name>[a-zA-Z0-9_.@+-]+?)-(?P<version>\d+\.\d+(?:\.\d+)?(?:[-.][a-zA-Z0-9]+)?)\.(?:jar|aar)$",
    re.I,
)

# Known Android/Java libs often embedded with version in path or properties
_KNOWN = re.compile(
    r"(?P<name>okhttp|okio|gson|guava|protobuf-java|commons-lang3|commons-codec|"
    r"slf4j-api|jackson-databind|kotlin-stdlib|androidx\.[a-z0-9_.]+)"
    r"[/:_-](?P<version>\d+\.\d+(?:\.\d+)?(?:[-.][A-Za-z0-9]+)?)",
    re.I,
)

_GRADLE = re.compile(
    r"""['"](?P<group>[a-zA-Z0-9_.-]+):(?P<name>[a-zA-Z0-9_.-]+):(?P<version>\d+\.\d[^'"]*)['"]"""
)


def extract_components(
    path: Path,
    artifact_type: str,
    metadata: Dict[str, Any],
) -> List[Dict[str, str]]:
    path = Path(path)
    seen: Set[Tuple[str, str]] = set()
    out: List[Dict[str, str]] = []

    def add(name: str, version: str, ecosystem: str = "Maven") -> None:
        name = (name or "").strip()
        version = (version or "").strip()
        if not name or not version:
            return
        if len(name) < 2 or len(version) < 3:
            return
        key = (name.lower(), version)
        if key in seen:
            return
        seen.add(key)
        out.append({"name": name, "version": version, "ecosystem": ecosystem})

    # Filename itself
    m = _JAR_VER.match(path.name)
    if m:
        add(m.group("name"), m.group("version"))

    # Metadata hints
    for key in ("Implementation-Version", "Bundle-Version", "version", "version_name"):
        ver = None
        if isinstance(metadata, dict):
            ver = metadata.get(key) or (metadata.get("metadata") or {}).get(key)
        name_hint = path.stem
        if ver and re.match(r"^\d+\.\d+", str(ver)):
            add(name_hint, str(ver))

    if artifact_type in ("jar", "apk", "sdk") and path.is_file():
        _scan_zip(path, add)
    elif artifact_type == "sdk" and path.is_dir():
        for p in list(path.rglob("*.jar"))[:40]:
            m = _JAR_VER.match(p.name)
            if m:
                add(m.group("name"), m.group("version"))
        for p in list(path.rglob("*.gradle"))[:20] + list(path.rglob("*.txt"))[:20]:
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")[:50_000]
            except OSError:
                continue
            for gm in _GRADLE.finditer(text):
                add(gm.group("name"), gm.group("version"))
            for km in _KNOWN.finditer(text):
                add(km.group("name"), km.group("version"))

    return out[:30]  # polite cap per artifact


def _scan_zip(path: Path, add) -> None:
    try:
        with zipfile.ZipFile(path, "r") as zf:
            for name in zf.namelist()[:400]:
                base = Path(name).name
                m = _JAR_VER.match(base)
                if m:
                    add(m.group("name"), m.group("version"))
                lower = name.lower()
                if lower.endswith((".properties", ".gradle", "pom.properties", "meta-inf/maven/")):
                    try:
                        raw = zf.read(name)
                    except Exception:
                        continue
                    if b"\x00" in raw[:32]:
                        continue
                    text = raw.decode("utf-8", errors="ignore")[:20_000]
                    # Maven pom.properties: version= / artifactId=
                    art = re.search(r"^artifactId=(.+)$", text, re.M)
                    ver = re.search(r"^version=(.+)$", text, re.M)
                    if art and ver:
                        add(art.group(1).strip(), ver.group(1).strip())
                    for gm in _GRADLE.finditer(text):
                        add(gm.group("name"), gm.group("version"))
                    for km in _KNOWN.finditer(text):
                        add(km.group("name"), km.group("version"))
    except Exception:
        pass
