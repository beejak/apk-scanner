#!/usr/bin/env python3
"""
Disposable 5× capability retest: download → SAST → reports → copy sanitized → purge.

Never commits APKs/IPAs. Intended for local/agent runs, not CI default.
"""

from __future__ import annotations

import html
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.report import reenrich_report, to_csv, to_html, to_json, to_sarif, to_text  # noqa: E402
from scanner.run import run  # noqa: E402
from scanner.sources_allowlist import (  # noqa: E402
    DEFAULT_HISTORY_REL,
    DEFAULT_SOURCES_REL,
    entry_id,
    load_history,
    load_sources,
    materialize_entry,
    record_scan,
    save_history,
    select_entries,
    utc_today_str,
)

# Prefer local calendar date for run folder naming (showcase id).
RUN_ID = f"capability_run_{datetime.now().strftime('%Y%m%d')}"
SOURCES = ROOT / DEFAULT_SOURCES_REL
HISTORY = ROOT / DEFAULT_HISTORY_REL


def _make_edu_jar(path: Path) -> None:
    props = (
        "url=http://evil.example.com/api\n"
        'Cipher.getInstance("DES")\n'
        "key=AKIAIOSFODNN7EXAMPLE\n"
        "Runtime.getRuntime().exec(\"id\")\n"
        "addJavascriptInterface(bridge)\n"
    ).encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("config.properties", props)
        zf.writestr("Dummy.class", props)
    path.write_bytes(buf.getvalue())


def _extract_sos(apk_dir: Path, so_dir: Path, limit: int = 5) -> int:
    so_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for apk in sorted(apk_dir.glob("*.apk")):
        try:
            with zipfile.ZipFile(apk, "r") as zf:
                for name in zf.namelist():
                    if name.endswith(".so") and ("lib/" in name or name.startswith("lib")):
                        base = Path(name).name
                        out = so_dir / f"{apk.stem}_{base}"
                        if out.exists():
                            continue
                        out.write_bytes(zf.read(name))
                        count += 1
                        if count >= limit:
                            return count
        except Exception:
            continue
    return count


def _make_sdks(sdk_root: Path) -> None:
    # No .so/.apk/.jar/.ipa inside SDK dirs (avoid double-counting by discovery).
    d1 = sdk_root / "hello-jni-sdk"
    (d1 / "include").mkdir(parents=True)
    (d1 / "lib").mkdir(parents=True)
    (d1 / "include" / "hello.h").write_text("// hello\n", encoding="utf-8")
    (d1 / "lib" / "README.txt").write_text("native libs omitted from sandbox sdk\n", encoding="utf-8")
    d2 = sdk_root / "gson-sdk"
    (d2 / "src").mkdir(parents=True)
    (d2 / "src" / "Gson.java").write_text("package com.google.gson;\n", encoding="utf-8")
    d3 = sdk_root / "slf4j-sdk"
    (d3 / "docs").mkdir(parents=True)
    (d3 / "docs" / "README.md").write_text("slf4j demo sdk\n", encoding="utf-8")
    d4 = sdk_root / "training-sdk"
    (d4 / "config").mkdir(parents=True)
    (d4 / "config" / ".env").write_text("API_KEY=demo\npassword=test\n", encoding="utf-8")
    (d4 / "include").mkdir(exist_ok=True)
    d5 = sdk_root / "vuln-config-sdk"
    (d5 / "lib").mkdir(parents=True)
    (d5 / "secrets.pem").write_text(
        "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n", encoding="utf-8"
    )
    (d5 / "lib" / "note.txt").write_text("sdk\n", encoding="utf-8")


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
    run_id = summary.get("run_id", RUN_ID)
    ts = report.get("scan_timestamp", "")
    crit = by_sev.get("critical", 0)
    high = by_sev.get("high", 0)
    med = by_sev.get("medium", 0)
    low = by_sev.get("low", 0)
    info = by_sev.get("info", 0)
    arts = report.get("summary", {}).get("artifacts", 0)
    nfind = report.get("summary", {}).get("findings", 0)
    max_s = report.get("summary", {}).get("max_severity_score", 0)
    avg_s = report.get("summary", {}).get("avg_severity_score", 0)
    pytest_s = summary.get("pytest", {}).get("result", "?")
    dast = summary.get("dast", {})
    dast_note = "ran" if dast.get("ran") else f"skipped — {dast.get('reason', 'n/a')}"

    # Prioritize critical/high in display (cap for page size)
    ordered = sorted(
        findings,
        key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
            (f.get("severity") or "").lower(), 5
        ),
    )
    show = ordered[:80]

    def esc(x):
        return html.escape(str(x if x is not None else ""))

    blocks = []
    for i, f in enumerate(show, 1):
        sev = (f.get("severity") or "info").lower()
        cls = f.get("classification") or {}
        tax_items = []
        for db, label in (
            ("cwe", "CWE"),
            ("maswe", "MASWE"),
            ("owasp_mobile", "OWASP Mobile 2024"),
            ("owasp", "OWASP"),
            ("nist", "NIST"),
        ):
            ents = cls.get(db) or []
            if ents:
                tax_items.append(
                    f"<li><strong>{label}:</strong> "
                    + "; ".join(f"{esc(e.get('id'))} ({esc(e.get('label'))})" for e in ents[:2])
                    + "</li>"
                )
        cvss = f.get("cvss_estimate") or {}
        blocks.append(
            f"""
<div class="finding">
  <div class="fhdr">
    <span class="badge sev-{esc(sev)}">{esc(sev)}</span>
    <span class="score">score {esc(f.get('severity_score'))}</span>
    <h3>{esc(f.get('rule_id'))}</h3>
    <span class="fnum">#{i}</span>
  </div>
  <p class="msg">{esc(f.get('message'))}</p>
  <p class="path">{esc((f.get('location') or {}).get('file', ''))}</p>
  <div class="tax"><h4>Taxonomy &amp; scoring</h4><ul>
    <li><strong>Severity score:</strong> {esc(f.get('severity_score'))} / 10</li>
    <li><strong>CVSS-estimate:</strong> {esc(cvss.get('score'))} <code>{esc(cvss.get('vector'))}</code>
      <br><span class="note">{esc(cvss.get('note'))}</span></li>
    <li><strong>CVE:</strong> {esc(f.get('cve') if f.get('cve') is not None else 'null (only from --sca/OSV when component+version extracted)')}</li>
    {''.join(tax_items)}
  </ul></div>
  <div class="fix"><strong>How to fix</strong><br>{esc(f.get('remediation'))}</div>
  <div class="fix revalidate"><strong>How to revalidate</strong><br>{esc(f.get('revalidate'))}</div>
</div>"""
        )

    rules = Counter(f.get("rule_id") for f in findings)
    top_rules = "".join(
        f"<tr><td><code>{esc(r)}</code></td><td class='num'>{n}</td></tr>"
        for r, n in rules.most_common(15)
    )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>APK Scanner — {esc(run_id)} Manager Report</title>
<style>
:root {{ --ink:#1c1c1c; --muted:#5c5c5c; --line:#d0d0d0; --bg:#f3f1ec; --panel:#fffcf7; --accent:#0a4d8c; --ok:#1b6b3a; --warn:#8a5a00; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; font-family:"IBM Plex Sans","Segoe UI",Tahoma,sans-serif; color:var(--ink);
  background:radial-gradient(1200px 500px at 10% -10%,#dfe9f5 0%,transparent 55%),linear-gradient(180deg,#ebe6dc 0%,var(--bg) 35%,#e8eef5 100%); line-height:1.45; }}
main {{ max-width:1100px; margin:0 auto; padding:2rem 1.25rem 3.5rem; }}
h1 {{ font-size:1.85rem; margin:0 0 0.25rem; }} h2 {{ font-size:1.2rem; margin:2rem 0 0.55rem; border-bottom:1px solid var(--line); padding-bottom:0.3rem; }}
h3 {{ font-size:1.02rem; margin:0; }} h4 {{ font-size:0.92rem; margin:0.65rem 0 0.3rem; color:#334155; }}
.lead {{ color:var(--muted); max-width:46rem; }} .meta {{ font-size:0.92rem; color:var(--muted); margin-bottom:1.25rem; }}
.kpis {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:0.75rem; margin:1rem 0 1.5rem; }}
.kpi {{ background:var(--panel); border:1px solid var(--line); padding:0.85rem 0.9rem; }}
.kpi .label {{ font-size:0.78rem; text-transform:uppercase; letter-spacing:0.04em; color:var(--muted); }}
.kpi .value {{ font-size:1.55rem; font-weight:650; margin-top:0.15rem; }}
table {{ width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--line); font-size:0.9rem; }}
th,td {{ text-align:left; padding:0.42rem 0.6rem; border-bottom:1px solid var(--line); }} th {{ background:#ebe4d6; }}
.num {{ text-align:right; }} .ok {{ color:var(--ok); font-weight:650; }} .skip {{ color:var(--warn); font-weight:650; }}
.finding {{ background:var(--panel); border:1px solid var(--line); padding:1rem; margin:0.85rem 0; }}
.fhdr {{ display:flex; flex-wrap:wrap; gap:0.45rem 0.85rem; align-items:baseline; }}
.badge {{ font-size:0.75rem; font-weight:700; text-transform:uppercase; padding:0.12rem 0.4rem; border:1px solid var(--line); }}
.sev-critical,.badge.sev-critical {{ color:#7f1d1d; }} .sev-high {{ color:#b33; }} .sev-medium {{ color:#c27803; }}
.sev-low {{ color:#5a6a7a; }} .sev-info {{ color:#3a6ea5; }}
.score {{ font-weight:700; color:var(--accent); }} .path {{ font-family:Consolas,monospace; font-size:0.82rem; color:#475569; word-break:break-all; }}
.fix {{ background:#f0f7ff; border-left:4px solid #0b5fff; padding:0.65rem 0.85rem; margin:0.65rem 0; }}
.fix.revalidate {{ background:#f3faf3; border-left-color:#15803d; }}
.callout {{ border-left:4px solid var(--accent); background:rgba(255,255,255,0.7); padding:0.85rem 1rem; margin:1rem 0; color:var(--muted); }}
.note {{ font-size:0.85rem; color:var(--muted); }} code {{ font-family:Consolas,monospace; font-size:0.86em; }}
footer {{ margin-top:2rem; font-size:0.85rem; color:var(--muted); }}
</style></head><body><main>
<h1>Capability run — manager report</h1>
<p class="lead">End-to-end discovery + metadata + pattern-scan SAST across APK/IPA/JAR/.so/SDK.
<strong>Leads</strong>, not confirmed vulns. Includes Critical/High, scores, taxonomy (MASWE / Mobile Top 10 2024), fix/revalidate.</p>
<p class="meta">Run ID: <code>{esc(run_id)}</code> · Scan: <code>{esc(ts)}</code> ·
Repo: <a href="https://github.com/beejak/apk-scanner">beejak/apk-scanner</a></p>
<div class="kpis">
  <div class="kpi"><div class="label">Artifacts</div><div class="value">{arts}</div></div>
  <div class="kpi"><div class="label">Findings</div><div class="value">{nfind}</div></div>
  <div class="kpi"><div class="label">Critical</div><div class="value">{crit}</div></div>
  <div class="kpi"><div class="label">High</div><div class="value">{high}</div></div>
  <div class="kpi"><div class="label">Medium</div><div class="value">{med}</div></div>
  <div class="kpi"><div class="label">Low</div><div class="value">{low}</div></div>
  <div class="kpi"><div class="label">Info</div><div class="value">{info}</div></div>
  <div class="kpi"><div class="label">Max score</div><div class="value">{esc(max_s)}</div></div>
  <div class="kpi"><div class="label">Avg score</div><div class="value">{esc(avg_s)}</div></div>
  <div class="kpi"><div class="label">Pytest</div><div class="value" style="font-size:1.1rem">{esc(pytest_s)}</div></div>
</div>
<div class="callout">
  Critical appears in the KPI grid above and on per-finding badges.
  cvss_estimate is rule-based (not NVD CVE CVSS). CVE IDs only from real OSV (--sca) when component+version extracted.
  DAST: <span class="{'ok' if dast.get('ran') else 'skip'}">{esc(dast_note)}</span>.
  Plugins: skipped unless tools on PATH. Vague password tokens are info-level noise.
</div>
<h2>Top rules</h2>
<table><thead><tr><th>rule_id</th><th class="num">count</th></tr></thead><tbody>{top_rules}</tbody></table>
<h2>Per-finding detail (Critical/High first; up to 80)</h2>
{''.join(blocks)}
<p class="note">Showing {len(show)} of {nfind} findings. Full data in report.json.</p>
<footer>Generated by scripts/capability_retest.py. Sandbox purged after copy. See docs/USAGE.md.</footer>
</main></body></html>
"""


def main() -> int:
    sandbox = Path(tempfile.mkdtemp(prefix="apk-scanner-capability-"))
    print("Sandbox:", sandbox)
    apk_dir = sandbox / "apk"
    ipa_dir = sandbox / "ipa"
    jar_dir = sandbox / "jar"
    so_dir = sandbox / "so"
    # Parent must NOT contain "sdk" in the name (discovery would count the parent too).
    sdk_dir = sandbox / "modules"
    for d in (apk_dir, ipa_dir, jar_dir, so_dir, sdk_dir):
        d.mkdir(parents=True)

    fixtures = ROOT / "tests" / "fixtures"
    out_dir = ROOT / "docs" / "results" / RUN_ID
    report_rel = str(out_dir.relative_to(ROOT)).replace("\\", "/")

    # Shared allowlist (primary → fallback) with history dedupe; force=True for showcase completeness
    print("Allowlist materialize (sources.json primary/fallback, history-aware)...")
    sources = load_sources(SOURCES)
    history = load_history(HISTORY)
    # Capability showcase: prefer fresh downloads — mark force on selection copy
    selected, skipped = select_entries(sources, {"version": 1, "entries": {}}, max_n=int(sources.get("max_artifacts") or 15))
    for s in skipped:
        print(f"  SKIP {s.get('id')}: {s.get('_skip_reason')}")
    for item in selected:
        forced = dict(item, force=True)
        meta = materialize_entry(forced, sandbox, user_agent="apk-scanner-capability/0.3")
        if meta.get("ok"):
            print(f"  OK {meta.get('id')} ({meta.get('type')}) pool={item.get('_pool')}")
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
            print(f"  FAIL {entry_id(item)}: {meta.get('error')}")

    apk_ok = len(list(apk_dir.glob("*.apk")))
    if fixtures.is_dir():
        for p in sorted(fixtures.glob("*.apk")):
            if apk_ok >= 5:
                break
            dest = apk_dir / p.name
            if not dest.exists():
                shutil.copy2(p, dest)
                apk_ok += 1
                print(f"  copied fixture {p.name}")
    if apk_ok < 5:
        print(f"WARN: only {apk_ok} APKs; continuing")

    ipa_ok = len(list(ipa_dir.glob("*.ipa")))
    # Pad IPAs with minimal synthetic plists if <5 public downloads
    while ipa_ok < 5:
        import plistlib
        n = ipa_ok + 1
        info = {
            "CFBundleIdentifier": f"com.example.synth{n}",
            "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
        }
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(f"Payload/Synth{n}.app/Info.plist", plistlib.dumps(info))
            zf.writestr(f"Payload/Synth{n}.app/Synth", b"XXXXXXhttp://evil.example.com/apiXXXXXX")
        (ipa_dir / f"synth-{n}.ipa").write_bytes(buf.getvalue())
        ipa_ok += 1
        print(f"  synthetic IPA synth-{n}.ipa")

    jar_ok = len(list(jar_dir.glob("*.jar")))
    _make_edu_jar(jar_dir / "edu-secrets-sample.jar")
    jar_ok += 1
    print("  OK edu-secrets-sample.jar (local)")

    print("Padding .so (extract leftovers / stubs to reach 5)...")
    so_n = len(list(so_dir.glob("*.so")))
    if so_n < 5:
        so_n += _extract_sos(apk_dir, so_dir, 5 - so_n)
    if so_n < 5 and (fixtures / "libdivajni.so").is_file():
        dest = so_dir / "libdivajni.so"
        if not dest.exists():
            shutil.copy2(fixtures / "libdivajni.so", dest)
            so_n += 1
    while so_n < 5:
        so_n += 1
        hdr = bytearray(b"\x7fELF\x01\x01\x01" + b"\x00" * 57)
        (so_dir / f"stub{so_n}.so").write_bytes(bytes(hdr) + b"JNI_OnLoad\x00password\x00")
        print(f"  stub so stub{so_n}.so")
    for extra in sorted(so_dir.glob("*.so"))[5:]:
        extra.unlink()

    print("Creating extra SDK dirs (showcase padding)...")
    _make_sdks(sdk_dir)
    save_history(HISTORY, history)
    print(f"Updated history → {HISTORY}")

    print("Running SAST (plugins/sca best-effort; dynamic if adb)...")
    import shutil as sh
    has_adb = sh.which("adb") is not None
    report = run(
        sandbox,
        recursive=True,
        types={"apk", "ipa", "jar", "so", "sdk"},
        jobs=1,
        sast=True,
        dynamic=has_adb,
        apkid=bool(sh.which("apkid")),
        semgrep=bool(sh.which("semgrep")),
        mobsfscan=bool(sh.which("mobsfscan")),
        sca=True,
        sca_offline=False,
    )
    reenrich_report(report)
    report = _sanitize(report, sandbox)

    # counts
    by_type = Counter()
    for m in report.get("metadata") or []:
        by_type[m.get("type", "?")] += 1
    by_sev = report.get("summary", {}).get("by_severity") or {}
    by_rule = Counter(f.get("rule_id") for f in report.get("findings") or [])

    pytest_info = {"command": "python -m pytest tests/ -q", "result": "see CI/local", "exit_code": None}
    try:
        pr = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/", "-q", "--tb=no"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=120,
        )
        m = re.search(r"(\d+) passed", pr.stdout + pr.stderr)
        pytest_info = {
            "command": "python -m pytest tests/ -q",
            "result": f"{m.group(1)} passed" if m else (pr.stdout + pr.stderr)[-200:],
            "exit_code": pr.returncode,
        }
    except Exception as e:
        pytest_info["result"] = str(e)

    summary = {
        "run_id": RUN_ID,
        "scan_timestamp": report.get("scan_timestamp"),
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "artifacts": report.get("summary", {}).get("artifacts"),
        "findings": report.get("summary", {}).get("findings"),
        "by_type_discovered": dict(by_type),
        "by_severity": by_sev,
        "by_rule_id": dict(by_rule.most_common(40)),
        "pytest": pytest_info,
        "dast": {
            "ran": has_adb,
            "reason": "adb present" if has_adb else "adb not on PATH; DAST skipped",
        },
        "plugins": {
            "apkid": bool(sh.which("apkid")),
            "semgrep": bool(sh.which("semgrep")),
            "mobsfscan": bool(sh.which("mobsfscan")),
        },
        "sca": True,
        "sources": {
            "allowlist": str(SOURCES.relative_to(ROOT)).replace("\\", "/"),
            "history": str(HISTORY.relative_to(ROOT)).replace("\\", "/"),
            "note": "primary+fallback from sources.json via scanner.sources_allowlist; synthetic pad to 5× types",
            "apk": "Allowlist APKs + local fixtures if present",
            "ipa": "Allowlist IPAs + synthetic ATS IPAs to reach 5",
            "jar": "Allowlist Maven JARs + edu-secrets-sample.jar",
            "so": "Allowlist extract_from_apk + APK extract / stubs",
            "sdk": "Allowlist generate recipes + synthetic SDK layouts",
        },
        "honesty": "Pattern-scan leads; Critical/High from shipped rules; CVE only from OSV when extracted.",
    }

    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    (out_dir / "report.json").write_text(to_json(report), encoding="utf-8")
    (out_dir / "report.html").write_text(to_html(report), encoding="utf-8")
    (out_dir / "report.csv").write_text(to_csv(report), encoding="utf-8")
    (out_dir / "report.txt").write_text(to_text(report), encoding="utf-8")
    (out_dir / "report.sarif.json").write_text(to_sarif(report), encoding="utf-8")
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (out_dir / "manager_report.html").write_text(_manager_html(report, summary), encoding="utf-8")

    print("Wrote", out_dir)
    print("Severity:", by_sev)
    print("Types:", dict(by_type))

    print("Purging sandbox...")
    shutil.rmtree(sandbox, ignore_errors=True)
    if sandbox.exists():
        print("WARN: sandbox still exists", sandbox)
        return 1
    print("Sandbox purged.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
