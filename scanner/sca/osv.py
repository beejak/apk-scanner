"""
OSV API client with on-disk cache. Never invents CVE IDs.

API: https://api.osv.dev/v1/query
Rate limits: be polite (cache, small batches). Offline → caller skips.
Docs: https://google.github.io/osv.dev/
Optional NVD: not queried by default (API key / rate limits); OSV aliases include CVE-*.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

OSV_URL = "https://api.osv.dev/v1/query"
_cache_env = (os.environ.get("APK_SCANNER_SCA_CACHE") or "").strip()
DEFAULT_CACHE = (
    Path(_cache_env) if _cache_env else (Path.home() / ".cache" / "apk-scanner" / "osv")
)
# Polite delay between live queries (seconds)
_MIN_INTERVAL = float(os.environ.get("APK_SCANNER_OSV_DELAY", "0.35"))
_last_query = 0.0


def query_osv(
    name: str,
    version: str,
    *,
    ecosystem: Optional[str] = "Maven",
    cache_dir: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """
    Query OSV for package@version. Returns list of vuln dicts from OSV (may be empty).
    On network error, returns [] and logs (offline skip).
    """
    cache_dir = Path(cache_dir) if cache_dir else DEFAULT_CACHE
    cache_dir.mkdir(parents=True, exist_ok=True)
    key = hashlib.sha256(f"{ecosystem}:{name}:{version}".encode()).hexdigest()
    cache_path = cache_dir / f"{key}.json"
    if cache_path.is_file():
        try:
            cached = json.loads(cache_path.read_text(encoding="utf-8"))
            return list(cached.get("vulns") or [])
        except (OSError, json.JSONDecodeError):
            pass

    payload = {
        "package": {"name": name, "ecosystem": ecosystem or "Maven"},
        "version": version,
    }
    # Also try without ecosystem if Maven misses (OSV accepts package name only)
    vulns = _post(payload)
    if not vulns and ecosystem:
        vulns = _post({"package": {"name": name}, "version": version})

    try:
        cache_path.write_text(json.dumps({"vulns": vulns}, indent=2), encoding="utf-8")
    except OSError:
        pass
    return vulns


def _post(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    global _last_query
    now = time.time()
    wait = _MIN_INTERVAL - (now - _last_query)
    if wait > 0:
        time.sleep(wait)
    _last_query = time.time()
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        OSV_URL,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "apk-scanner/0.2 (OSV SCA)"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = resp.read().decode("utf-8", errors="replace")
        parsed = json.loads(body)
        return list(parsed.get("vulns") or [])
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError) as e:
        logger.info("OSV query failed for %s: %s (offline skip)", payload, e)
        return []
