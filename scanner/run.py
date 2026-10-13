"""
Main pipeline: discover -> extract metadata -> [SAST] -> report.
"""

import logging
from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import List, Optional

from .discovery import discover
from .metadata import extract
from .report import aggregate
from .sast import run_sast
from .taxonomy import enrich_finding

logger = logging.getLogger(__name__)


def _extract_one(item: tuple) -> dict:
    """Worker: (path_str, type) -> metadata item dict. Used for ProcessPoolExecutor."""
    path_str, artifact_type = item
    path = Path(path_str)
    try:
        size = path.stat().st_size if path.is_file() else 0
        if path.is_dir():
            size = sum(p.stat().st_size for p in path.rglob("*") if p.is_file())
    except OSError:
        size = 0
    try:
        meta = extract(path, artifact_type)
    except Exception as e:
        meta = {"error": str(e)}
    return {
        "path": str(path),
        "type": artifact_type,
        "size_bytes": size,
        "metadata": meta,
    }


def run(
    root: Path,
    *,
    recursive: bool = True,
    types: Optional[set] = None,
    jobs: int = 1,
    sast: bool = False,
    dynamic: bool = False,
) -> dict:
    """
    Discover artifacts under root, extract metadata, optionally run SAST and/or DAST, return report dict.
    jobs: parallel workers (1 = sequential). Use ProcessPoolExecutor.map for spawn safety on Windows.
    sast: if True, run static analysis and add findings to report.
    dynamic: if True, run DAST on APK/IPA (emulator + Frida when available); add runtime findings.
    """
    logger.info("Scanning directory: %s", root)
    items = discover(root, recursive=recursive, types=types)
    if not items:
        logger.info("No artifacts found")
        return aggregate([], [])

    logger.info("Discovered %d artifact(s): %s", len(items), _count_by_type(items))

    metadata_list: List[dict] = []
    if jobs <= 1:
        for i, (path, typ) in enumerate(items):
            logger.info("Parsing %s (%d/%d): %s", typ, i + 1, len(items), path.name)
            one = _extract_one((str(path), typ))
            if one.get("metadata", {}).get("error"):
                logger.warning("Skip %s: %s", path, one["metadata"]["error"])
            else:
                logger.debug("OK %s", path)
            metadata_list.append(one)
    else:
        with ProcessPoolExecutor(max_workers=jobs) as executor:
            futures = {executor.submit(_extract_one, (str(p), t)): (p, t) for p, t in items}
            for i, future in enumerate(as_completed(futures)):
                path, typ = futures[future]
                try:
                    one = future.result()
                    metadata_list.append(one)
                    if one.get("metadata", {}).get("error"):
                        logger.warning("Skip %s: %s", path, one["metadata"]["error"])
                    else:
                        logger.debug("OK %s", path)
                    logger.info("Parsing (%d/%d) done: %s", i + 1, len(items), path.name)
                except Exception as e:
                    logger.warning("Error %s: %s", path, e)
                    metadata_list.append({
                        "path": str(path),
                        "type": typ,
                        "size_bytes": 0,
                        "metadata": {"error": str(e)},
                    })

    findings: List[dict] = []
    if sast:
        logger.info("Running SAST on %d artifact(s)", len(metadata_list))
        for item in metadata_list:
            path_str = item.get("path", "")
            typ = item.get("type", "")
            meta = item.get("metadata", {})
            try:
                for f in run_sast(Path(path_str), typ, meta):
                    f.setdefault("source", "sast")
                    findings.append(f)
            except Exception as e:
                logger.warning("SAST error for %s: %s", path_str, e)
        logger.info("SAST found %d finding(s)", len(findings))

    if dynamic:
        apk_ipa = [item for item in metadata_list if item.get("type") in ("apk", "ipa")]
        logger.info("Running DAST on %d APK/IPA artifact(s)", len(apk_ipa))
        for item in apk_ipa:
            path_str = item.get("path", "")
            typ = item.get("type", "")
            meta = item.get("metadata", {})
            if meta.get("error"):
                continue
            try:
                from .dast import run_dast
                for f in run_dast(Path(path_str), typ, meta):
                    f.setdefault("source", "dynamic")
                    findings.append(f)
            except Exception as e:
                logger.warning("DAST error for %s: %s", path_str, e)
        logger.info("DAST found %d runtime finding(s)", sum(1 for f in findings if f.get("source") == "dynamic"))

    for f in findings:
        enrich_finding(f)

    scan_timestamp = datetime.now(timezone.utc).isoformat()
    report = aggregate(metadata_list, findings, scan_timestamp=scan_timestamp)
    logger.info("Scan complete: %d artifact(s)", len(metadata_list))
    return report


def _count_by_type(items: list) -> dict:
    c = {}
    for _, t in items:
        c[t] = c.get(t, 0) + 1
    return c
