#!/usr/bin/env python3
"""
Refresh auto-generated competitor metrics in docs/LANDSCAPE.md.

Reads allowlisted repos from docs/landscape_sources.json.
Fetches stars / pushed_at / latest release via GitHub API (urllib + GITHUB_TOKEN
or unauthenticated). Does NOT scrape features or invent capability text.

Updates only the block between:
  <!-- LANDSCAPE-AUTO:START -->
  <!-- LANDSCAPE-AUTO:END -->
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "docs" / "landscape_sources.json"
LANDSCAPE = ROOT / "docs" / "LANDSCAPE.md"
START = "<!-- LANDSCAPE-AUTO:START -->"
END = "<!-- LANDSCAPE-AUTO:END -->"
API = "https://api.github.com"


def _headers() -> dict:
    h = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "apk-scanner-landscape-refresh",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "").strip()
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _get_json(url: str) -> dict | list | None:
    req = urllib.request.Request(url, headers=_headers())
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=45, context=ctx) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"WARN HTTP {e.code} for {url}: {e.reason}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"WARN fetch failed {url}: {e}", file=sys.stderr)
        return None


def fetch_repo(owner: str, repo: str) -> dict:
    meta = _get_json(f"{API}/repos/{owner}/{repo}") or {}
    release = _get_json(f"{API}/repos/{owner}/{repo}/releases/latest")
    tag = ""
    published = ""
    if isinstance(release, dict):
        tag = release.get("tag_name") or ""
        published = (release.get("published_at") or "")[:10]
    return {
        "stars": meta.get("stargazers_count"),
        "pushed_at": (meta.get("pushed_at") or "")[:10],
        "archived": bool(meta.get("archived")),
        "tag": tag,
        "published_at": published,
    }


def render_table(rows: list[dict]) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"**Auto-refreshed:** {now} (stars / latest release / pushed_at from GitHub API; "
        "human narrative elsewhere in this file is unchanged).",
        "",
        "| Tool | Stars | Latest release | Last push | Archived? |",
        "|------|------:|----------------|-----------|-----------|",
    ]
    for r in rows:
        stars = r.get("stars")
        stars_s = f"{stars:,}" if isinstance(stars, int) else "—"
        rel = r.get("tag") or "—"
        if r.get("published_at"):
            rel = f"{rel} ({r['published_at']})" if rel != "—" else r["published_at"]
        push = r.get("pushed_at") or "—"
        arch = "yes" if r.get("archived") else "no"
        label = r.get("label") or f"{r.get('owner')}/{r.get('repo')}"
        url = r.get("url") or f"https://github.com/{r.get('owner')}/{r.get('repo')}"
        err = r.get("error")
        if err:
            lines.append(f"| [{label}]({url}) | — | fetch error | — | — |")
        else:
            lines.append(f"| [{label}]({url}) | {stars_s} | {rel} | {push} | {arch} |")
    lines.append("")
    lines.append(
        "_Source allowlist: `docs/landscape_sources.json`. Script: `scripts/refresh_landscape.py`._"
    )
    return "\n".join(lines)


def update_landscape(block: str) -> bool:
    text = LANDSCAPE.read_text(encoding="utf-8")
    if START not in text or END not in text:
        print(
            f"ERROR: markers {START!r} / {END!r} missing in {LANDSCAPE}",
            file=sys.stderr,
        )
        return False
    before, rest = text.split(START, 1)
    _, after = rest.split(END, 1)
    new_text = before + START + "\n\n" + block.strip() + "\n\n" + END + after
    if new_text == text:
        print("LANDSCAPE.md auto section unchanged")
        return True
    LANDSCAPE.write_text(new_text, encoding="utf-8")
    try:
        shown = LANDSCAPE.relative_to(ROOT)
    except ValueError:
        shown = LANDSCAPE
    print(f"Updated {shown}")
    return True


def main() -> int:
    if not SOURCES.is_file():
        print(f"Missing {SOURCES}", file=sys.stderr)
        return 1
    data = json.loads(SOURCES.read_text(encoding="utf-8"))
    repos = data.get("repos") or []
    rows = []
    for entry in repos:
        owner = entry.get("owner")
        repo = entry.get("repo")
        if not owner or not repo:
            continue
        print(f"Fetching {owner}/{repo}...")
        info = fetch_repo(owner, repo)
        row = {**entry, **info}
        if info.get("stars") is None and not info.get("pushed_at"):
            row["error"] = "fetch_failed"
        rows.append(row)
    block = render_table(rows)
    if not update_landscape(block):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
