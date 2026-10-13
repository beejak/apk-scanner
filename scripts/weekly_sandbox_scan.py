#!/usr/bin/env python3
"""
Allowlist-only sandbox scan for GitHub Actions weekly job (and local dry-runs).

Reads tests/fixtures/sources.json — never crawls arbitrary URLs.
Uses primary then fallback with scan-history dedupe (same id+version skipped).
Downloads into a temp sandbox, runs --sast, writes docs/results/weekly_YYYYMMDD/,
updates tests/fixtures/scan_history.json, then deletes all downloaded binaries.
Soft-fail: always exit 0 unless fatal script error.
"""

from __future__ import annotations

import html
import io
import json
import os
import shutil
import sys
import tempfile
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.report import reenrich_report, to_html, to_json, to_sarif, to_text  # noqa: E402
from scanner.run import run  # noqa: E402
from scanner.sources_allowlist import (  # noqa: E402
    DEFAULT_HISTORY_REL,
    DEFAULT_SOURCES_REL,
    count_by_type,
    entry_id,
    fallback_entries,
    load_history,
    load_sources,
    materialize_entry,
    max_artifacts,
    record_scan,
    save_history,
    select_entries,
    should_skip_entry,
    utc_today_str,
    validate_sources,
)

SOURCES = ROOT / DEFAULT_SOURCES_REL
HISTORY = ROOT / DEFAULT_HISTORY_REL
BLOCKED_COMMIT_SUFFIXES = (".apk", ".ipa", ".aab", ".dex", ".so", ".xapk", ".apks")


def _add_edu_jar(sandbox: Path) -> None:
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
    sca_section = _sca_manager_section(report)
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
<p class="note">Allowlist-only educational downloads (primary + fallback, history dedupe). Leads not confirmed vulns. Binaries purged. Run: <code>{html.escape(run_id)}</code> · {html.escape(str(ts))}</p>
<div class="k">
<div><strong>{report.get('summary',{}).get('artifacts',0)}</strong><br>Artifacts</div>
<div><strong>{report.get('summary',{}).get('findings',0)}</strong><br>Findings</div>
<div class="critical"><strong>{by_sev.get('critical',0)}</strong><br>Critical</div>
<div class="high"><strong>{by_sev.get('high',0)}</strong><br>High</div>
<div><strong>{by_sev.get('medium',0)}</strong><br>Medium</div>
<div><strong>{by_sev.get('info',0)}</strong><br>Info</div>
</div>
<p class="note">cvss_estimate is rule-based (not NVD CVE CVSS). CVE only from --sca/OSV when component+version extracted. Soft-fail: findings do not fail CI.</p>
{sca_section}
<h2>Top rules</h2>
<table><tr><th>rule_id</th><th>count</th></tr>{top}</table>
<h2>Findings (Critical/High first, capped)</h2>
{''.join(blocks)}
<footer class="note">Generated by scripts/weekly_sandbox_scan.py · sources: tests/fixtures/sources.json · history: tests/fixtures/scan_history.json</footer>
</main></body></html>
"""


def _sca_manager_section(report: dict) -> str:
    sca = (report.get("summary") or {}).get("sca") or {}
    if not sca:
        return (
            "<h2>SCA / OSV board</h2>"
            "<p class='note'>No SCA summary (scan ran without extractable components or --sca skipped).</p>"
        )
    vulns = sca.get("vulnerabilities") or []
    rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(v.get('component')))}</td>"
        f"<td>{html.escape(str(v.get('version')))}</td>"
        f"<td>{html.escape(str(v.get('severity')))}</td>"
        f"<td>{html.escape(', '.join(v.get('cve') or []) or '—')}</td>"
        f"<td>{html.escape(str(v.get('osv_id') or ''))}</td>"
        "</tr>"
        for v in vulns[:40]
    ) or "<tr><td colspan='5'>No OSV vulnerabilities for extracted components</td></tr>"
    inv = sca.get("inventory") or []
    inv_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(c.get('component')))}</td>"
        f"<td>{html.escape(str(c.get('version')))}</td>"
        f"<td>{html.escape(str(c.get('ecosystem')))}</td>"
        "</tr>"
        for c in inv[:40]
    ) or "<tr><td colspan='3'>No components extracted</td></tr>"
    return f"""
<h2>SCA / OSV board</h2>
<p class="note">{html.escape(str(sca.get('honesty', '')))}
 Components checked: {sca.get('components_checked', 0)};
 OSV vulns: {sca.get('vuln_count', 0)}; CVE ids: {sca.get('cve_count', 0)}.</p>
<table><tr><th>Component</th><th>Version</th><th>Severity</th><th>CVE</th><th>OSV id</th></tr>
{rows}</table>
<h3>Component inventory</h3>
<table><tr><th>Component</th><th>Version</th><th>Ecosystem</th></tr>
{inv_rows}</table>
"""


def main() -> int:
    sources = load_sources(SOURCES)
    errs = validate_sources(sources)
    # Soft-warn on validation; only fatal if no usable entries at all
    for e in errs:
        print(f"WARN sources: {e}")

    max_n = max_artifacts(sources)
    history = load_history(HISTORY)

    selected, skipped = select_entries(sources, history, max_n=max_n)
    print(f"Selected {len(selected)} / max {max_n} (skipped {len(skipped)} via history/dedupe)")
    for s in skipped:
        print(f"  SKIP {s.get('id') or s.get('name')}: {s.get('_skip_reason')}")

    out_date = datetime.now(timezone.utc).strftime("%Y%m%d")
    run_id = f"weekly_{out_date}"
    out_dir = ROOT / "docs" / "results" / run_id
    report_rel = str(out_dir.relative_to(ROOT)).replace("\\", "/")

    sandbox = Path(os.environ.get("RUNNER_TEMP") or tempfile.gettempdir()) / f"apk-scanner-{run_id}"
    if sandbox.exists():
        shutil.rmtree(sandbox, ignore_errors=True)
    sandbox.mkdir(parents=True)

    print(f"Sandbox: {sandbox}")
    print(f"By type selected: {count_by_type(selected)}")

    materialized = 0
    materialize_log: list[dict] = []
    for item in selected:
        meta = materialize_entry(item, sandbox)
        materialize_log.append(
            {
                "id": meta.get("id"),
                "type": meta.get("type"),
                "pool": meta.get("pool"),
                "ok": meta.get("ok"),
                "version": meta.get("version"),
                "error": meta.get("error"),
            }
        )
        if meta.get("ok"):
            materialized += 1
            print(f"OK {meta.get('id')} ({meta.get('type')}) pool={meta.get('pool')}")
            record_scan(
                history,
                item,
                version=meta.get("version"),
                etag=meta.get("etag"),
                sha256=meta.get("sha256"),
                url=item.get("url"),
                last_report_dir=report_rel,
                last_scan_date=utc_today_str(),
            )
        else:
            print(f"SKIP materialize {meta.get('id')}: {meta.get('error')}")

    # If primary+fallback selection left us short after failures, try remaining fallback not selected
    if materialized < max_n:
        already = {entry_id(x) for x in selected}
        for item in fallback_entries(sources):
            if materialized >= max_n:
                break
            eid = entry_id(item)
            if eid in already:
                continue
            skip, reason = should_skip_entry(item, history)
            if skip:
                print(f"  SKIP fallback refill {eid}: {reason}")
                continue
            item = dict(item)
            item["_pool"] = "fallback-refill"
            meta = materialize_entry(item, sandbox)
            if meta.get("ok"):
                materialized += 1
                already.add(eid)
                print(f"OK refill {eid}")
                record_scan(
                    history,
                    item,
                    version=meta.get("version"),
                    etag=meta.get("etag"),
                    sha256=meta.get("sha256"),
                    url=item.get("url"),
                    last_report_dir=report_rel,
                    last_scan_date=utc_today_str(),
                )
            else:
                print(f"SKIP refill {eid}: {meta.get('error')}")

    if sources.get("local_synthetic", {}).get("enabled", True):
        _add_edu_jar(sandbox)
        print("OK synthetic edu JAR")

    print(f"Materialized {materialized} allowlisted artifact(s); running SAST + SCA...")
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
            sca=True,
            sca_offline=False,
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
        "history": str(HISTORY.relative_to(ROOT)).replace("\\", "/"),
        "selected": len(selected),
        "skipped_dedupe": len(skipped),
        "materialized": materialized,
        "materialize_log": materialize_log,
        "by_type_selected": count_by_type(selected),
        "artifacts": report.get("summary", {}).get("artifacts"),
        "findings": report.get("summary", {}).get("findings"),
        "by_type": dict(by_type),
        "by_severity": by_sev,
        "honesty": (
            "Allowlist-only educational sources (primary + fallback). Pattern-scan leads. "
            "History dedupe skips same id+version. Binaries deleted from runner temp. Soft-fail on findings."
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

    # Persist history (small JSON, no binaries)
    save_history(HISTORY, history)
    print(f"Updated history → {HISTORY}")

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

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
