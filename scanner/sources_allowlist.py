"""
Allowlist loader, scan-history dedupe, and artifact materialization.

Used by scripts/weekly_sandbox_scan.py and scripts/capability_retest.py.
Never crawls arbitrary URLs — only entries from tests/fixtures/sources.json.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import shutil
import tempfile
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

ALLOWED_TYPES = frozenset({"apk", "ipa", "jar", "so", "sdk"})
DEFAULT_HISTORY_REL = Path("tests/fixtures/scan_history.json")
DEFAULT_SOURCES_REL = Path("tests/fixtures/sources.json")
USER_AGENT = "apk-scanner-allowlist/0.3"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_today_str(now: datetime | None = None) -> str:
    return (now or utc_now()).strftime("%Y-%m-%d")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def load_sources(path: Path) -> dict[str, Any]:
    data = load_json(path)
    if not isinstance(data, dict):
        raise ValueError("sources.json must be an object")
    return data


def primary_entries(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Backward compatible: primary → sources → artifacts."""
    for key in ("primary", "sources", "artifacts"):
        items = data.get(key)
        if isinstance(items, list):
            return [dict(x) for x in items if isinstance(x, dict)]
    return []


def fallback_entries(data: dict[str, Any]) -> list[dict[str, Any]]:
    items = data.get("fallback")
    if isinstance(items, list):
        return [dict(x) for x in items if isinstance(x, dict)]
    return []


def max_artifacts(data: dict[str, Any], default: int = 15) -> int:
    try:
        n = int(data.get("max_artifacts") or default)
    except (TypeError, ValueError):
        n = default
    return max(0, min(n, 15 if default == 15 else n))


def entry_id(entry: dict[str, Any]) -> str:
    if entry.get("id"):
        return str(entry["id"])
    name = entry.get("name") or "unnamed"
    typ = (entry.get("type") or "bin").lower()
    return f"{typ}:{name}"


def entry_urls(entry: dict[str, Any]) -> list[str]:
    urls: list[str] = []
    if entry.get("url"):
        urls.append(str(entry["url"]))
    for u in entry.get("urls") or []:
        if u:
            urls.append(str(u))
    extract = entry.get("extract_from_apk") or {}
    if isinstance(extract, dict) and extract.get("url"):
        urls.append(str(extract["url"]))
    return urls


def entry_version_hint(entry: dict[str, Any]) -> str | None:
    if entry.get("version"):
        return str(entry["version"])
    if entry.get("content_fingerprint"):
        return str(entry["content_fingerprint"])
    url = (entry.get("url") or (entry_urls(entry)[0] if entry_urls(entry) else "")) or ""
    # Prefer version-like segments in URL path (e.g. junit-4.13.2.jar, /v1.0/)
    m = re.search(r"/v?(\d+\.\d+(?:\.\d+)?)/", url)
    if m:
        return m.group(1)
    name = Path(urlparse(url).path).name or str(entry.get("name") or "")
    m2 = re.search(r"(\d+\.\d+(?:\.\d+)?)", name)
    if m2:
        return m2.group(1)
    return None


def validate_entry(entry: dict[str, Any], *, require_https: bool = True) -> list[str]:
    """Return list of validation errors (empty if OK)."""
    errs: list[str] = []
    typ = (entry.get("type") or "").lower()
    if typ not in ALLOWED_TYPES:
        errs.append(f"invalid type {typ!r}")
    if not entry.get("name") and not entry.get("generate"):
        errs.append("missing name")

    def _https(u: str, label: str) -> None:
        if require_https and u and not str(u).startswith("https://"):
            errs.append(f"{label} must be https: {u}")

    if entry.get("generate"):
        if typ != "sdk":
            errs.append("generate only allowed for type=sdk")
        if not isinstance(entry.get("files"), list) or not entry["files"]:
            errs.append("generate sdk requires non-empty files[]")
        return errs

    if entry.get("extract_from_apk"):
        if typ != "so":
            errs.append("extract_from_apk only allowed for type=so")
        ex = entry["extract_from_apk"]
        if not isinstance(ex, dict) or not ex.get("url") or not ex.get("member"):
            errs.append("extract_from_apk needs url + member")
        else:
            _https(str(ex["url"]), "extract_from_apk.url")
        return errs

    check: list[str] = []
    if entry.get("url"):
        check.append(str(entry["url"]))
    check.extend(str(x) for x in (entry.get("urls") or []) if x)
    if not check:
        errs.append("missing url/urls (or generate / extract_from_apk)")
    for u in check:
        _https(u, "url")
    return errs


def validate_sources(data: dict[str, Any]) -> list[str]:
    errs: list[str] = []
    max_n = max_artifacts(data)
    if max_n > 15:
        errs.append("max_artifacts must be ≤ 15")
    primary = primary_entries(data)
    fallback = fallback_entries(data)
    if not primary and not fallback:
        errs.append("no primary/sources/artifacts or fallback entries")
    seen_ids: set[str] = set()
    for label, items in (("primary", primary), ("fallback", fallback)):
        for i, item in enumerate(items):
            eid = entry_id(item)
            if eid in seen_ids:
                errs.append(f"duplicate id across lists: {eid}")
            seen_ids.add(eid)
            for e in validate_entry(item):
                errs.append(f"{label}[{i}] ({eid}): {e}")
    return errs


def load_history(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"version": 1, "entries": {}}
    data = load_json(path)
    if not isinstance(data, dict):
        return {"version": 1, "entries": {}}
    entries = data.get("entries")
    if not isinstance(entries, dict):
        data["entries"] = {}
    data.setdefault("version", 1)
    return data


def save_history(path: Path, history: dict[str, Any]) -> None:
    history.setdefault("version", 1)
    history.setdefault("entries", {})
    save_json(path, history)


def _parse_date(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        if len(s) == 10:
            return datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def history_record(history: dict[str, Any], eid: str) -> dict[str, Any] | None:
    entries = history.get("entries") or {}
    rec = entries.get(eid)
    return rec if isinstance(rec, dict) else None


def should_skip_entry(
    entry: dict[str, Any],
    history: dict[str, Any],
    *,
    now: datetime | None = None,
    remote_etag: str | None = None,
    remote_sha256: str | None = None,
) -> tuple[bool, str]:
    """
    Skip if same id+version (or same sha256) was already scanned, unless:
    - force: true
    - version / url changed vs history
    - remote ETag or sha256 differs from history (publisher content change)
    Optional min_interval_days: skip when unchanged (even after interval elapses,
    still skip until version/etag/sha changes — interval only blocks early rescans
    when used with force workflows; same-version remains skipped).
    """
    now = now or utc_now()
    if entry.get("force") is True:
        return False, "force=true"

    eid = entry_id(entry)
    rec = history_record(history, eid)
    if not rec:
        return False, "not in history"

    cur_version = entry_version_hint(entry)
    hist_version = rec.get("version")
    hist_url = rec.get("url")
    cur_url = entry.get("url") or (entry_urls(entry)[0] if entry_urls(entry) else None)

    if cur_version and hist_version and str(cur_version) != str(hist_version):
        return False, "version changed"
    if cur_url and hist_url and str(cur_url) != str(hist_url):
        return False, "url changed"
    if remote_etag and rec.get("etag") and str(remote_etag) != str(rec.get("etag")):
        return False, "etag changed"
    if remote_sha256 and rec.get("sha256") and str(remote_sha256) != str(rec.get("sha256")):
        return False, "sha256 changed"

    same_identity = False
    if cur_version and hist_version and str(cur_version) == str(hist_version):
        same_identity = True
    elif remote_sha256 and rec.get("sha256") and str(remote_sha256) == str(rec.get("sha256")):
        same_identity = True
    elif cur_url and hist_url and str(cur_url) == str(hist_url):
        if not cur_version or not hist_version or str(cur_version) == str(hist_version):
            same_identity = True
    elif hist_version and not cur_version:
        # History has version; entry relies on URL/fingerprint — treat as same if URL matches
        same_identity = bool(cur_url and hist_url and str(cur_url) == str(hist_url))
    elif rec.get("sha256") and not remote_sha256 and hist_version and cur_version:
        same_identity = str(hist_version) == str(cur_version)

    if not same_identity:
        return False, "history present but identity unclear — scan"

    min_days = entry.get("min_interval_days")
    if min_days is not None:
        try:
            min_days_i = int(min_days)
        except (TypeError, ValueError):
            min_days_i = 0
        last = _parse_date(rec.get("last_scan_date"))
        if last and min_days_i > 0:
            delta = (now - last).total_seconds() / 86400.0
            if delta < min_days_i:
                return True, f"min_interval_days ({delta:.1f}<{min_days_i})"

    return True, "already scanned at same version"


def select_entries(
    data: dict[str, Any],
    history: dict[str, Any],
    *,
    now: datetime | None = None,
    max_n: int | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Pick entries from primary (skipping duplicates), then fallback until max_artifacts.

    Returns (selected, skipped) where skipped items include _skip_reason.
    """
    now = now or utc_now()
    cap = max_n if max_n is not None else max_artifacts(data)
    selected: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    selected_ids: set[str] = set()

    def consider(items: list[dict[str, Any]], pool: str) -> None:
        nonlocal selected
        for raw in items:
            if len(selected) >= cap:
                return
            item = dict(raw)
            item["_pool"] = pool
            eid = entry_id(item)
            if eid in selected_ids:
                skipped.append({**item, "_skip_reason": "duplicate id in selection"})
                continue
            skip, reason = should_skip_entry(item, history, now=now)
            if skip:
                skipped.append({**item, "_skip_reason": reason})
                continue
            selected_ids.add(eid)
            selected.append(item)

    consider(primary_entries(data), "primary")
    if len(selected) < cap:
        consider(fallback_entries(data), "fallback")
    return selected, skipped


def record_scan(
    history: dict[str, Any],
    entry: dict[str, Any],
    *,
    version: str | None = None,
    etag: str | None = None,
    sha256: str | None = None,
    url: str | None = None,
    last_report_dir: str | None = None,
    last_scan_date: str | None = None,
) -> None:
    eid = entry_id(entry)
    entries = history.setdefault("entries", {})
    prev = entries.get(eid) if isinstance(entries.get(eid), dict) else {}
    rec = {
        "id": eid,
        "type": (entry.get("type") or "").lower(),
        "name": entry.get("name"),
        "version": version or entry_version_hint(entry) or prev.get("version"),
        "etag": etag if etag is not None else prev.get("etag"),
        "sha256": sha256 if sha256 is not None else prev.get("sha256"),
        "url": url or entry.get("url") or prev.get("url"),
        "last_scan_date": last_scan_date or utc_today_str(),
        "last_report_dir": last_report_dir or prev.get("last_report_dir"),
        "publisher": entry.get("publisher") or prev.get("publisher"),
    }
    entries[eid] = rec


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _filename_from_cd(cd: str | None) -> str | None:
    if not cd:
        return None
    m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', cd, re.I)
    if m:
        return unquote(m.group(1).strip())
    return None


def download_url(
    url: str,
    dest: Path,
    *,
    timeout: int = 120,
    user_agent: str = USER_AGENT,
    min_bytes: int = 200,
) -> dict[str, Any]:
    """
    Download https URL to dest. Returns metadata dict with ok, etag, sha256, version_guess, error.
    """
    meta: dict[str, Any] = {
        "ok": False,
        "url": url,
        "etag": None,
        "sha256": None,
        "version_guess": None,
        "bytes": 0,
        "error": None,
    }
    if not url.startswith("https://"):
        meta["error"] = "non-https"
        return meta
    try:
        req = urllib.request.Request(url, headers={"User-Agent": user_agent})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
            etag = resp.headers.get("ETag") or resp.headers.get("etag")
            cd = resp.headers.get("Content-Disposition")
        if len(data) < min_bytes:
            meta["error"] = f"too small ({len(data)} bytes)"
            return meta
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        meta["ok"] = True
        meta["etag"] = etag.strip('"') if etag else None
        meta["sha256"] = sha256_bytes(data)
        meta["bytes"] = len(data)
        fname = _filename_from_cd(cd) or Path(urlparse(url).path).name
        m = re.search(r"(\d+\.\d+(?:\.\d+)?)", fname or "")
        if m:
            meta["version_guess"] = m.group(1)
        return meta
    except Exception as e:
        meta["error"] = str(e)
        return meta


def generate_sdk(entry: dict[str, Any], dest_dir: Path) -> Path:
    """Create a tiny sample SDK tree from entry['files'] under dest_dir."""
    name = entry.get("name") or entry_id(entry)
    root = dest_dir / name
    if root.exists():
        shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True)
    for spec in entry.get("files") or []:
        if not isinstance(spec, dict):
            continue
        rel = spec.get("path") or ""
        if not rel or ".." in Path(rel).parts:
            continue
        content = spec.get("content")
        if content is None:
            content = ""
        if isinstance(content, str):
            raw = content.encode("utf-8")
        else:
            raw = bytes(content)
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    # Ensure SDK-like layout markers exist
    for sub in ("include", "lib", "config"):
        (root / sub).mkdir(exist_ok=True)
    return root


def extract_so_from_apk(
    apk_url: str,
    member: str,
    dest: Path,
    *,
    timeout: int = 120,
    user_agent: str = USER_AGENT,
) -> dict[str, Any]:
    """Download APK to temp, extract one .so member, delete APK. Never keeps the APK."""
    meta: dict[str, Any] = {
        "ok": False,
        "url": apk_url,
        "etag": None,
        "sha256": None,
        "version_guess": None,
        "bytes": 0,
        "error": None,
    }
    tmp_apk = None
    try:
        td = Path(tempfile.mkdtemp(prefix="apk-scanner-so-extract-"))
        tmp_apk = td / "source.apk"
        dl = download_url(apk_url, tmp_apk, timeout=timeout, user_agent=user_agent, min_bytes=200)
        meta["etag"] = dl.get("etag")
        if not dl.get("ok"):
            meta["error"] = dl.get("error") or "apk download failed"
            return meta
        with zipfile.ZipFile(tmp_apk, "r") as zf:
            # Exact member, suffix match, or first lib/*.so as last resort
            names = zf.namelist()
            chosen = member if member in names else None
            if not chosen:
                for n in names:
                    if n.endswith(member) or n.endswith("/" + member.lstrip("/")):
                        chosen = n
                        break
            if not chosen:
                for n in names:
                    if n.endswith(".so") and ("lib/" in n or n.startswith("lib")):
                        chosen = n
                        break
            if not chosen:
                meta["error"] = f"member not found: {member}"
                return meta
            data = zf.read(chosen)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        meta["ok"] = True
        meta["sha256"] = sha256_bytes(data)
        meta["bytes"] = len(data)
        meta["version_guess"] = dl.get("version_guess")
        return meta
    except Exception as e:
        meta["error"] = str(e)
        return meta
    finally:
        if tmp_apk and tmp_apk.exists():
            try:
                tmp_apk.unlink()
            except OSError:
                pass
        if tmp_apk:
            shutil.rmtree(tmp_apk.parent, ignore_errors=True)


def materialize_entry(
    entry: dict[str, Any],
    sandbox: Path,
    *,
    timeout: int = 120,
    user_agent: str = USER_AGENT,
) -> dict[str, Any]:
    """
    Download / generate / extract entry into sandbox.
    Returns {ok, path, etag, sha256, version, error, pool}.
    """
    typ = (entry.get("type") or "bin").lower()
    name = entry.get("name") or entry_id(entry)
    result: dict[str, Any] = {
        "ok": False,
        "path": None,
        "etag": None,
        "sha256": None,
        "version": entry_version_hint(entry),
        "error": None,
        "id": entry_id(entry),
        "type": typ,
        "pool": entry.get("_pool"),
    }

    if entry.get("generate") and typ == "sdk":
        # Parent must not contain "sdk" alone as confusing discovery — use modules/
        dest_parent = sandbox / "modules"
        dest_parent.mkdir(parents=True, exist_ok=True)
        root = generate_sdk(entry, dest_parent)
        # Fingerprint from concatenated file contents
        parts: list[bytes] = []
        for p in sorted(root.rglob("*")):
            if p.is_file():
                parts.append(p.read_bytes())
        digest = sha256_bytes(b"\0".join(parts)) if parts else sha256_bytes(b"")
        result.update(ok=True, path=root, sha256=digest, version=result["version"] or digest[:12])
        return result

    if typ == "so" and entry.get("extract_from_apk"):
        ex = entry["extract_from_apk"]
        dest = sandbox / "so" / name
        meta = extract_so_from_apk(
            str(ex["url"]),
            str(ex["member"]),
            dest,
            timeout=timeout,
            user_agent=user_agent,
        )
        result.update(
            ok=bool(meta.get("ok")),
            path=dest if meta.get("ok") else None,
            etag=meta.get("etag"),
            sha256=meta.get("sha256"),
            version=result["version"] or meta.get("version_guess"),
            error=meta.get("error"),
        )
        return result

    url = entry.get("url") or ((entry.get("urls") or [None])[0])
    if not url:
        result["error"] = "no url"
        return result

    if typ == "sdk" and str(url).endswith(".zip"):
        dest_zip = sandbox / "sdk_zips" / f"{name}.zip"
        meta = download_url(str(url), dest_zip, timeout=timeout, user_agent=user_agent)
        if not meta.get("ok"):
            result["error"] = meta.get("error")
            return result
        dest_dir = sandbox / "modules" / name
        if dest_dir.exists():
            shutil.rmtree(dest_dir, ignore_errors=True)
        dest_dir.mkdir(parents=True)
        with zipfile.ZipFile(dest_zip, "r") as zf:
            zf.extractall(dest_dir)
        dest_zip.unlink(missing_ok=True)
        result.update(
            ok=True,
            path=dest_dir,
            etag=meta.get("etag"),
            sha256=meta.get("sha256"),
            version=result["version"] or meta.get("version_guess"),
        )
        return result

    dest = sandbox / typ / name
    meta = download_url(str(url), dest, timeout=timeout, user_agent=user_agent)
    result.update(
        ok=bool(meta.get("ok")),
        path=dest if meta.get("ok") else None,
        etag=meta.get("etag"),
        sha256=meta.get("sha256"),
        version=result["version"] or meta.get("version_guess"),
        error=meta.get("error"),
    )
    return result


def count_by_type(entries: list[dict[str, Any]]) -> dict[str, int]:
    from collections import Counter

    c: Counter[str] = Counter()
    for e in entries:
        c[(e.get("type") or "?").lower()] += 1
    return dict(c)
