#!/usr/bin/env python3
"""
Allowlist-only sandbox scan for GitHub Actions weekly job (and local dry-runs).

Reads tests/fixtures/sources.json — never crawls arbitrary URLs.
Downloads into a temp sandbox, runs --sast, writes docs/results/weekly_YYYYMMDD/,
then deletes all downloaded binaries. Soft-fail: always exit 0 unless fatal script error.
"""

from __future__ import annotations

import html
import io
import json
import os
import shutil
import sys
import tempfile
import urllib.request
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.report import reenrich_report, to_html, to_json, to_sarif, to_text  # noqa: E402
from scanner.run import run  # noqa: E402

SOURCES = ROOT / "tests" / "fixtures" / "sources.json"
BLOCKED_COMMIT_SUFFIXES = (".apk", ".ipa", ".aab", ".dex", ".so", ".xapk", ".apks")


def _load_sources() -> dict:
    data = json.loads(SOURCES.read_text(encoding="utf-8"))
    if not isinstance(data.get("artifacts"), list):
        raise SystemExit("sources.json missing artifacts list")
    return data


def _dl(url: str, dest: Path, timeout: int = 120) -> bool:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "apk-scanner-weekly/0.2"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
        if len(data) < 200:
            print(f"SKIP too small: {url}")
            return False
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        print(f"OK {dest.name} ({len(data)} bytes)")
        return True
    except Exception as e:
        print(f"SKIP download failed: {url} ({e})")
        return False


def _add_synthetics(sandbox: Path) -> None:
    jar_dir = sandbox / "jar"
    jar_dir.mkdir(parents=True, exist_ok=True)
    props = (
        b"url=http://evil.example.com/api\n"
        b'Cipher.getInstance("DES")\n'
        b"key=AKIAIOSFODNN7EXAMPLE\n"
        b"addJavascriptInterface(bridge)\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")
        zf.writestr("config.properties", props)
    (jar_dir / "edu-weekly-sample.jar").write_bytes(buf.getvalue())

    sdk = sandbox / "modules" / "weekly-training-sdk"
    (sdk / "include").mkdir(parents=True)
    (sdk / "lib").mkdir(parents=True)
    (sdk / "config").mkdir(parents=True)
    (sdk / "include" / "note.h").write_text("// weekly sdk\n", encoding="utf-8")
    (sdk / "lib" / "README.txt").write_text("no binaries\n", encoding="utf-8")
    (sdk / "config" / ".env").write_text("API_KEY=weekly-demo\n", encoding="utf-8")


def _sanitize(obj, sandbox: Path):
    s = str(sandbox).replace("\\", "/")
    if isinstance(obj, dict):
        return {k: _sanitize(v, sandbox) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize(v, sandbox) for v in obj]
    if isinstance(obj, str):
        return obj.replace(str(sandbox), "<sandbox>").replace(s, "<sandbox>").replace("\\", "/")
    return obj


def _manager_html(report: dict, summary: dict) -> str:
    by_sev = report.get("summary", {}).get("by_severity") or {}
    findings = report.get("findings") or []
    run_id = summary.get("run_id", "")
    ts = report.get("scan_timestamp", "")
    ordered = sorted(
        findings,
        key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
            (f.get("severity") or "").lower(), 5
        ),
    )[:60]
    rules = Counter(f.get("rule_id") for f in findings)
    top = "".join(
        f"<tr><td><code>{html.escape(str(r))}</code></td><td>{n}</td></tr>"
        for r, n in rules.most_common(12)
    )
    blocks = []
    for i, f in enumerate(ordered, 1):
        sev = html.escape((f.get("severity") or "info").lower())
        blocks.append(
            f"<div class='f'><span class='b {sev}'>{sev}</span> "
            f"<strong>{html.escape(str(f.get('rule_id')))}</strong> "
            f"score={html.escape(str(f.get('severity_score')))}<br>"
            f"{html.escape(str(f.get('message'))[:240])}<br>"
            f"<em>Fix:</em> {html.escape(str(f.get('remediation') or '')[:400])}<br>"
            f"<em>Revalidate:</em> {html.escape(str(f.get('revalidate') or '')[:300])}"
            f"</div>"
        )
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/>
<title>{html.escape(run_id)} weekly manager report</title>
<style>
body{{font-family:Segoe UI,Tahoma,sans-serif;margin:0;background:#eef2f5;color:#1c2430}}
main{{max-width:960px;margin:0 auto;padding:1.5rem}}
.k{{display:flex;flex-wrap:wrap;gap:.6rem}}.k div{{background:#fff;border:1px solid #cfd8e3;padding:.6rem .8rem;min-width:5.5rem}}
.b{{font-size:.75rem;font-weight:700;text-transform:uppercase;margin-right:.4rem}}
.critical,.b.critical{{color:#7f1d1d}}.high,.b.high{{color:#b91c1c}}
.f{{background:#fff;border:1px solid #cfd8e3;padding:.75rem;margin:.6rem 0}}
table{{border-collapse:collapse;width:100%;background:#fff}} td,th{{border:1px solid #dbe3ec;padding:.35rem .5rem;text-align:left}}
.note{{color:#64748b;font-size:.9rem}}
</style></head><body><main>
<h1>Weekly sandbox scan — manager summary</h1>
<p class="note">Allowlist-only educational downloads. Leads not confirmed vulns. Binaries purged. Run: <code>{html.escape(run_id)}</code> · {html.escape(str(ts))}</p>
<div class="k">
<div><strong>{report.get('summary',{}).get('artifacts',0)}</strong><br>Artifacts</div>
<div><strong>{report.get('summary',{}).get('findings',0)}</strong><br>Findings</div>
<div class="critical"><strong>{by_sev.get('critical',0)}</strong><br>Critical</div>
<div class="high"><strong>{by_sev.get('high',0)}</strong><br>High</div>
<div><strong>{by_sev.get('medium',0)}</strong><br>Medium</div>
<div><strong>{by_sev.get('info',0)}</strong><br>Info</div>
</div>
<p class="note">cvss_estimate is rule-based (not NVD CVE CVSS). CVE only from --sca/OSV when component+version extracted. Soft-fail: findings do not fail CI.</p>
<h2>Top rules</h2>
<table><tr><th>rule_id</th><th>count</th></tr>{top}</table>
<h2>Findings (Critical/High first, capped)</h2>
{''.join(blocks)}
<footer class="note">Generated by scripts/weekly_sandbox_scan.py · sources: tests/fixtures/sources.json</footer>
</main></body></html>
"""


def main() -> int:
    sources = _load_sources()
    max_n = int(sources.get("max_artifacts") or 15)
    artifacts = list(sources.get("artifacts") or [])[:max_n]

    out_date = datetime.now(timezone.utc).strftime("%Y%m%d")
    run_id = f"weekly_{out_date}"
    out_dir = ROOT / "docs" / "results" / run_id

    sandbox = Path(os.environ.get("RUNNER_TEMP") or tempfile.gettempdir()) / f"apk-scanner-{run_id}"
    if sandbox.exists():
        shutil.rmtree(sandbox, ignore_errors=True)
    sandbox.mkdir(parents=True)

    print(f"Sandbox: {sandbox}")
    print(f"Allowlist entries (capped {max_n}): {len(artifacts)}")

    downloaded = 0
    for item in artifacts:
        typ = (item.get("type") or "bin").lower()
        name = item.get("name") or "artifact.bin"
        url = item.get("url") or ""
        if not url.startswith("https://"):
            print(f"SKIP non-https URL for {name}")
            continue
        dest = sandbox / typ / name
        if _dl(url, dest):
            downloaded += 1

    if sources.get("local_synthetic", {}).get("enabled", True):
        _add_synthetics(sandbox)
        print("OK synthetic edu JAR + SDK dir")

    print(f"Downloaded {downloaded} allowlisted file(s); running SAST...")
    # Soft-fail scan: catch exceptions, still write what we can
    try:
        report = run(
            sandbox,
            recursive=True,
            types={"apk", "ipa", "jar", "so", "sdk"},
            jobs=1,
            sast=True,
            dynamic=False,
            apkid=False,
            semgrep=False,
            mobsfscan=False,
            sca=False,
        )
        reenrich_report(report)
        report = _sanitize(report, sandbox)
    except Exception as e:
        print(f"SCAN soft-fail: {e}")
        report = {
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "metadata": [],
            "findings": [],
            "summary": {
                "artifacts": 0,
                "findings": 0,
                "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                "max_severity_score": 0,
                "avg_severity_score": 0,
                "error": str(e),
            },
        }

    by_type = Counter(m.get("type") for m in report.get("metadata") or [])
    by_sev = report.get("summary", {}).get("by_severity") or {}
    summary = {
        "run_id": run_id,
        "scan_timestamp": report.get("scan_timestamp"),
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "allowlist": str(SOURCES.relative_to(ROOT)).replace("\\", "/"),
        "downloaded": downloaded,
        "artifacts": report.get("summary", {}).get("artifacts"),
        "findings": report.get("summary", {}).get("findings"),
        "by_type": dict(by_type),
        "by_severity": by_sev,
        "honesty": (
            "Allowlist-only educational sources. Pattern-scan leads. "
            "Binaries deleted from runner temp. Soft-fail on findings."
        ),
        "limits": {
            "max_artifacts": max_n,
            "runner_note": "Keep allowlist small (~10-15) for GitHub Actions disk/time reliability (~14GB disk, 6h job cap).",
        },
    }

    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    (out_dir / "report.json").write_text(to_json(report), encoding="utf-8")
    (out_dir / "report.html").write_text(to_html(report), encoding="utf-8")
    (out_dir / "report.txt").write_text(to_text(report), encoding="utf-8")
    (out_dir / "report.sarif.json").write_text(to_sarif(report), encoding="utf-8")
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (out_dir / "manager_report.html").write_text(_manager_html(report, summary), encoding="utf-8")

    # Safety: never leave binaries under docs/
    for p in out_dir.rglob("*"):
        if p.is_file() and p.suffix.lower() in BLOCKED_COMMIT_SUFFIXES:
            p.unlink(missing_ok=True)
            print(f"REMOVED blocked binary from reports dir: {p}")

    print(f"Wrote reports → {out_dir}")
    print("Purging sandbox binaries...")
    shutil.rmtree(sandbox, ignore_errors=True)
    if sandbox.exists():
        print(f"WARN: sandbox still present: {sandbox}")
    else:
        print("Sandbox purged.")

    # Always soft-success for Actions (findings are not a gate)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
