"""
Aggregate metadata + findings into report (JSON / text / CSV / HTML / SARIF).
Report schema: { "scan_timestamp", "metadata", "findings", "summary" }

Findings may include severity_score, classification, cvss_estimate, remediation, revalidate, cve.
Summary includes by_severity counts, max_severity_score, avg_severity_score.
"""

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .taxonomy import (
    classification_for_csv,
    classification_short,
    compute_severity_score,
    enrich_finding,
)


def _severity_rollups(findings: List[dict]) -> Dict[str, Any]:
    """Counts by severity band plus max/avg severity_score."""
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    scores: List[float] = []
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        if sev in by_severity:
            by_severity[sev] += 1
        else:
            by_severity.setdefault(sev, 0)
            by_severity[sev] += 1
        sc = f.get("severity_score")
        if sc is None:
            sc = compute_severity_score(f.get("severity") or "info", f.get("rule_id") or "")
        try:
            scores.append(float(sc))
        except (TypeError, ValueError):
            pass
    out: Dict[str, Any] = {"by_severity": by_severity}
    if scores:
        out["max_severity_score"] = max(scores)
        out["avg_severity_score"] = round(sum(scores) / len(scores), 2)
    else:
        out["max_severity_score"] = 0.0
        out["avg_severity_score"] = 0.0
    return out


def aggregate(
    metadata_items: List[dict],
    findings: Optional[List[dict]] = None,
    scan_timestamp: Optional[str] = None,
) -> dict:
    """Build report dict. findings default empty. scan_timestamp in ISO 8601 UTC."""
    if scan_timestamp is None:
        scan_timestamp = datetime.now(timezone.utc).isoformat()
    findings = findings or []
    rollups = _severity_rollups(findings)
    return {
        "scan_timestamp": scan_timestamp,
        "metadata": metadata_items,
        "findings": findings,
        "summary": {
            "artifacts": len(metadata_items),
            "findings": len(findings),
            "by_severity": rollups["by_severity"],
            "max_severity_score": rollups["max_severity_score"],
            "avg_severity_score": rollups["avg_severity_score"],
        },
    }


def reenrich_report(report: dict) -> dict:
    """
    Re-apply taxonomy enrichment and rebuild summary rollups in-place.
    Useful to refresh showcase JSON/HTML without re-scanning APKs.
    """
    findings = report.get("findings") or []
    for f in findings:
        enrich_finding(f)
    meta = report.get("metadata") or []
    ts = report.get("scan_timestamp")
    rebuilt = aggregate(meta, findings, scan_timestamp=ts)
    report["findings"] = rebuilt["findings"]
    report["summary"] = rebuilt["summary"]
    if ts:
        report["scan_timestamp"] = ts
    return report


def format_size(n: int) -> str:
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n} {u}"
        n //= 1024
    return f"{n} TB"


def to_json(report: dict, indent: int = 2) -> str:
    return json.dumps(report, indent=indent, default=str)


def to_text(report: dict) -> str:
    lines = []
    ts = report.get("scan_timestamp", "")
    if ts:
        lines.append(f"Scan time: {ts}")
    summary = report.get("summary", {})
    by_sev = summary.get("by_severity") or {}
    if by_sev:
        sev_parts = [f"{k}={by_sev.get(k, 0)}" for k in ("critical", "high", "medium", "low", "info")]
        lines.append(
            "Severity: "
            + ", ".join(sev_parts)
            + f" | max_score={summary.get('max_severity_score', 0)}"
            + f" | avg_score={summary.get('avg_severity_score', 0)}"
        )
    meta = report.get("metadata", [])
    by_type: Dict[str, List] = {}
    for m in meta:
        t = m.get("type", "?")
        by_type.setdefault(t, []).append(m)
    for t in ("apk", "ipa", "jar", "so", "sdk"):
        if t not in by_type:
            continue
        lines.append(f"\n=== {t.upper()} ({len(by_type[t])}) ===")
        for m in by_type[t]:
            path = m.get("path", "")
            size = m.get("size_bytes", 0)
            lines.append(f"  {path}")
            lines.append(f"    size: {format_size(size)}")
            for k, v in m.get("metadata", {}).items():
                if k != "path":
                    lines.append(f"    {k}: {v}")
    findings = report.get("findings", [])
    if findings:
        lines.append(f"\n=== FINDINGS ({len(findings)}) ===")
        for f in findings:
            loc = f.get("location") or {}
            loc_str = ""
            if loc.get("file"):
                loc_str = f" @ {loc['file']}"
                if loc.get("line") is not None:
                    loc_str += f":{loc['line']}"
            src = f.get("source", "sast")
            src_tag = " (dynamic)" if src == "dynamic" else ""
            score = f.get("severity_score")
            score_tag = f" score={score}" if score is not None else ""
            lines.append(
                f"  [{f.get('severity', '?')}]{score_tag} {f.get('rule_id', '')}: "
                f"{f.get('message', '')}{loc_str}{src_tag}"
            )
            cls_str = classification_short(f)
            if cls_str and cls_str != "—":
                lines.append(f"    Classification: {cls_str}")
            cvss = f.get("cvss_estimate") or {}
            if cvss:
                lines.append(
                    f"    CVSS-estimate: {cvss.get('score', '')} ({cvss.get('vector', '')}) "
                    f"— {cvss.get('note', '')}"
                )
            if f.get("remediation"):
                lines.append(f"    Remediation: {f['remediation']}")
            if f.get("revalidate"):
                lines.append(f"    Revalidate: {f['revalidate']}")
    lines.append(
        f"\nTotal: {summary.get('artifacts', 0)} artifact(s), {summary.get('findings', 0)} finding(s)"
    )
    return "\n".join(lines)


def to_csv(report: dict) -> str:
    """CSV: one row per finding with taxonomy, score, CVSS-estimate, remediation, revalidate."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    ts = report.get("scan_timestamp", "")
    summary = report.get("summary", {})
    writer.writerow(
        [
            "scan_timestamp",
            "total_artifacts",
            "total_findings",
            "max_severity_score",
            "avg_severity_score",
        ]
    )
    writer.writerow(
        [
            ts,
            summary.get("artifacts", 0),
            summary.get("findings", 0),
            summary.get("max_severity_score", ""),
            summary.get("avg_severity_score", ""),
        ]
    )
    writer.writerow([])
    header = [
        "scan_timestamp",
        "path",
        "severity",
        "severity_score",
        "rule_id",
        "message",
        "source",
        "masvs_id",
        "cvss_estimate_score",
        "cvss_estimate_vector",
        "remediation",
        "revalidate",
        "CWE",
        "NIST",
        "OWASP",
        "MASWE",
        "OWASP_Mobile_2024",
        "CAPEC",
        "CISA",
        "NSA",
    ]
    writer.writerow(header)
    for f in report.get("findings", []):
        loc = f.get("location") or {}
        path = loc.get("file", "")
        cls = classification_for_csv(f)
        cvss = f.get("cvss_estimate") or {}
        writer.writerow(
            [
                ts,
                path,
                f.get("severity", ""),
                f.get("severity_score", ""),
                f.get("rule_id", ""),
                f.get("message", ""),
                f.get("source", "sast"),
                f.get("masvs_id", ""),
                cvss.get("score", ""),
                cvss.get("vector", ""),
                f.get("remediation", ""),
                f.get("revalidate", ""),
                cls.get("cwe", ""),
                cls.get("nist", ""),
                cls.get("owasp", ""),
                cls.get("maswe", ""),
                cls.get("owasp_mobile", ""),
                cls.get("capec", ""),
                cls.get("cisa", ""),
                cls.get("nsa", ""),
            ]
        )
    return buf.getvalue()


def _taxonomy_html_block(f: dict) -> str:
    """Manager-friendly taxonomy / CVSS block for one finding."""
    cls = f.get("classification") or {}
    parts = ["<div class='tax-block'><h4>Taxonomy &amp; scoring</h4><ul>"]
    score = f.get("severity_score")
    if score is not None:
        parts.append(f"<li><strong>Severity score:</strong> {_escape(score)} / 10</li>")
    cvss = f.get("cvss_estimate") or {}
    if cvss:
        parts.append(
            f"<li><strong>CVSS-estimate:</strong> {_escape(cvss.get('score', ''))} "
            f"<code>{_escape(cvss.get('vector', ''))}</code>"
            f"<br><span class='note'>{_escape(cvss.get('note', ''))}</span></li>"
        )
    if "cve" in f:
        cve_val = f.get("cve")
        cve_txt = "null (CVE IDs require component/version SCA; not invented here)" if cve_val is None else _escape(cve_val)
        parts.append(f"<li><strong>CVE:</strong> {cve_txt}</li>")
    for db, label in (
        ("cwe", "CWE"),
        ("nist", "NIST"),
        ("owasp", "OWASP"),
        ("maswe", "MASWE"),
        ("owasp_mobile", "OWASP Mobile 2024"),
        ("capec", "CAPEC"),
        ("cisa", "CISA"),
        ("nsa", "NSA"),
    ):
        entries = cls.get(db) or []
        if not entries:
            continue
        items = []
        for e in entries:
            eid = _escape(e.get("id", ""))
            elabel = _escape(e.get("label", ""))
            url = e.get("url") or ""
            if url:
                items.append(f"<a href='{_escape(url)}'>{eid}</a> ({elabel})")
            else:
                items.append(f"{eid} ({elabel})")
        parts.append(f"<li><strong>{label}:</strong> {'; '.join(items)}</li>")
    parts.append("</ul></div>")
    return "\n".join(parts)


def to_html(report: dict) -> str:
    """Self-contained HTML report: executive summary, scores, taxonomy, remediation, revalidate."""
    ts = report.get("scan_timestamp", "")
    summary = report.get("summary", {})
    meta = report.get("metadata", [])
    findings = report.get("findings", [])
    by_sev = summary.get("by_severity") or {}

    css = """
body{font-family:Georgia,"Times New Roman",serif;margin:0;background:#eef2f5;color:#1c2430;line-height:1.45;}
.wrap{max-width:1100px;margin:0 auto;padding:1.5rem 1.25rem 3rem;}
h1{font-family:"Segoe UI",system-ui,sans-serif;font-size:1.85rem;margin:0 0 0.35rem;color:#0b3d91;}
h2{font-family:"Segoe UI",system-ui,sans-serif;font-size:1.25rem;margin:1.75rem 0 0.65rem;color:#1c2430;}
h3{font-family:"Segoe UI",system-ui,sans-serif;font-size:1.05rem;margin:0 0 0.4rem;}
h4{font-family:"Segoe UI",system-ui,sans-serif;font-size:0.95rem;margin:0.75rem 0 0.35rem;color:#334155;}
.lead{color:#4b5563;margin:0 0 1rem;}
.summary-grid{display:flex;flex-wrap:wrap;gap:0.75rem;margin:1rem 0 1.25rem;}
.stat{background:#fff;border:1px solid #cfd8e3;padding:0.75rem 1rem;min-width:7.5rem;}
.stat .n{display:block;font-family:"Segoe UI",system-ui,sans-serif;font-size:1.45rem;font-weight:700;}
.stat .l{font-size:0.8rem;color:#64748b;text-transform:uppercase;letter-spacing:0.04em;}
.stat.high .n{color:#b91c1c;} .stat.medium .n{color:#c2410c;} .stat.low .n{color:#15803d;}
.stat.info .n{color:#0369a1;} .stat.critical .n{color:#7f1d1d;}
table.meta-table{border-collapse:collapse;width:100%;background:#fff;border:1px solid #cfd8e3;}
table.meta-table th,table.meta-table td{border:1px solid #dbe3ec;padding:0.45rem 0.65rem;text-align:left;font-family:"Segoe UI",system-ui,sans-serif;font-size:0.9rem;}
table.meta-table th{background:#e8eef5;}
.finding{background:#fff;border:1px solid #cfd8e3;margin:0.85rem 0;padding:1rem 1.1rem;}
.finding .hdr{display:flex;flex-wrap:wrap;gap:0.5rem 1rem;align-items:baseline;margin-bottom:0.35rem;}
.badge{font-family:"Segoe UI",system-ui,sans-serif;font-size:0.75rem;font-weight:700;text-transform:uppercase;padding:0.15rem 0.45rem;border:1px solid #cbd5e1;}
.badge.high,.badge.critical{background:#fee2e2;color:#991b1b;border-color:#fecaca;}
.badge.medium{background:#ffedd5;color:#9a3412;border-color:#fed7aa;}
.badge.low{background:#dcfce7;color:#166534;border-color:#bbf7d0;}
.badge.info{background:#e0f2fe;color:#075985;border-color:#bae6fd;}
.score{font-family:"Segoe UI",system-ui,sans-serif;font-weight:700;color:#0b3d91;}
.msg{margin:0.35rem 0 0.5rem;}
.path{font-family:Consolas,"Courier New",monospace;font-size:0.85rem;color:#475569;word-break:break-all;}
.tax-block ul{margin:0.25rem 0 0;padding-left:1.2rem;}
.tax-block li{margin:0.2rem 0;}
.tax-block a{color:#0b5fff;}
.note{font-size:0.85rem;color:#64748b;}
.fix{background:#f0f7ff;border-left:4px solid #0b5fff;padding:0.65rem 0.85rem;margin:0.65rem 0;}
.fix.revalidate{background:#f3faf3;border-left-color:#15803d;}
.fix strong{font-family:"Segoe UI",system-ui,sans-serif;}
code{font-family:Consolas,"Courier New",monospace;font-size:0.88em;}
.source{font-size:0.8rem;color:#64748b;font-style:italic;}
""".strip()

    html_parts = [
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        "<title>Scan Report</title>",
        f"<style>{css}</style></head><body><div class='wrap'>",
        "<h1>Scan Report</h1>",
        f"<p class='lead'>Scan time: {_escape(ts)}</p>",
        "<div class='summary-grid'>",
        f"<div class='stat'><span class='n'>{summary.get('artifacts', 0)}</span><span class='l'>Artifacts</span></div>",
        f"<div class='stat'><span class='n'>{summary.get('findings', 0)}</span><span class='l'>Findings</span></div>",
        f"<div class='stat critical'><span class='n'>{by_sev.get('critical', 0)}</span><span class='l'>Critical</span></div>",
        f"<div class='stat high'><span class='n'>{by_sev.get('high', 0)}</span><span class='l'>High</span></div>",
        f"<div class='stat medium'><span class='n'>{by_sev.get('medium', 0)}</span><span class='l'>Medium</span></div>",
        f"<div class='stat low'><span class='n'>{by_sev.get('low', 0)}</span><span class='l'>Low</span></div>",
        f"<div class='stat info'><span class='n'>{by_sev.get('info', 0)}</span><span class='l'>Info</span></div>",
        f"<div class='stat'><span class='n'>{_escape(summary.get('max_severity_score', 0))}</span><span class='l'>Max score</span></div>",
        f"<div class='stat'><span class='n'>{_escape(summary.get('avg_severity_score', 0))}</span><span class='l'>Avg score</span></div>",
        "</div>",
        "<p class='note'>Severity scores are rule-based (band × weight), 0–10. "
        "CVSS-estimate fields are not NVD CVSS for a CVE. "
        "CVE IDs appear only from real OSV SCA (--sca) when component+version was extracted; otherwise null.</p>",
    ]

    if meta:
        html_parts.append("<h2>Artifacts</h2><table class='meta-table'><tr><th>Path</th><th>Type</th><th>Size</th></tr>")
        for m in meta:
            path = _escape(m.get("path", ""))
            typ = _escape(m.get("type", ""))
            size = format_size(m.get("size_bytes", 0))
            html_parts.append(f"<tr><td>{path}</td><td>{typ}</td><td>{size}</td></tr>")
        html_parts.append("</table>")

    if findings:
        html_parts.append(f"<h2>Findings ({len(findings)})</h2>")
        for f in findings:
            sev = (f.get("severity") or "info").lower()
            rule_id = _escape(f.get("rule_id", ""))
            msg = _escape(f.get("message", ""))
            src = f.get("source", "sast")
            loc = f.get("location") or {}
            path = _escape(loc.get("file", ""))
            src_label = "dynamic" if src == "dynamic" else "static"
            score = f.get("severity_score")
            score_html = f"<span class='score'>score {_escape(score)}</span>" if score is not None else ""
            html_parts.append("<div class='finding'>")
            html_parts.append("<div class='hdr'>")
            html_parts.append(f"<span class='badge {sev}'>{_escape(sev)}</span>")
            if score_html:
                html_parts.append(score_html)
            html_parts.append(f"<h3>{rule_id}</h3>")
            html_parts.append(f"<span class='source'>{src_label}</span>")
            html_parts.append("</div>")
            html_parts.append(f"<p class='msg'>{msg}</p>")
            if path:
                html_parts.append(f"<p class='path'>{path}</p>")
            html_parts.append(_taxonomy_html_block(f))
            if f.get("remediation"):
                html_parts.append(
                    f"<div class='fix'><strong>How to fix</strong><br>{_escape(f['remediation'])}</div>"
                )
            if f.get("revalidate"):
                html_parts.append(
                    f"<div class='fix revalidate'><strong>How to revalidate</strong><br>{_escape(f['revalidate'])}</div>"
                )
            html_parts.append("</div>")

    html_parts.append("</div></body></html>")
    return "\n".join(html_parts)


def _escape(s: Any) -> str:
    if not isinstance(s, str):
        s = str(s)
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _sarif_level(severity: str) -> str:
    sev = (severity or "").lower()
    if sev == "critical":
        return "error"
    if sev == "high":
        return "error"
    if sev == "info":
        return "note"
    return "warning"


def _sarif_taxa_for_finding(f: dict) -> List[Dict[str, Any]]:
    """Build SARIF taxa references from classification (CWE / MASWE / OWASP Mobile)."""
    cls = f.get("classification") or {}
    taxa: List[Dict[str, Any]] = []
    for db, tool_comp in (
        ("cwe", "cwe"),
        ("maswe", "maswe"),
        ("owasp_mobile", "owasp-mobile-2024"),
    ):
        for e in cls.get(db) or []:
            eid = e.get("id")
            if not eid:
                continue
            taxa.append({"id": eid, "toolComponent": {"name": tool_comp}})
    return taxa


def to_sarif(report: dict, tool_name: str = "apk-scanner") -> str:
    """
    SARIF 2.1.0: ruleId, level, locations, help (remediation+revalidate), taxa, properties.
    Honest: scores/CVSS-estimate are rule-based; CVE only when SCA populated.
    """
    findings = report.get("findings", [])
    by_rule: Dict[str, dict] = {}
    for f in findings:
        rid = f.get("rule_id") or "unknown"
        if rid not in by_rule:
            by_rule[rid] = f

    rules = []
    for rid in sorted(by_rule):
        f = by_rule[rid]
        rem = f.get("remediation") or ""
        rev = f.get("revalidate") or ""
        help_text = rem
        if rev:
            help_text = f"{rem}\n\nRevalidate: {rev}" if rem else f"Revalidate: {rev}"
        sev = (f.get("severity") or "warning").lower()
        rule: Dict[str, Any] = {
            "id": rid,
            "name": rid,
            "shortDescription": {"text": rid},
            "fullDescription": {"text": (f.get("message") or rid)[:256]},
            "defaultConfiguration": {"level": _sarif_level(sev)},
            "properties": {
                "severity": f.get("severity"),
                "maswe_id": f.get("maswe_id"),
                "owasp_mobile": f.get("owasp_mobile"),
            },
        }
        if help_text:
            rule["help"] = {
                "text": help_text,
                "markdown": (
                    f"**Remediation**\n\n{rem}\n\n**Revalidate**\n\n{rev}"
                    if rem or rev
                    else help_text
                ),
            }
        rules.append(rule)

    results = []
    for f in findings:
        rule_id = f.get("rule_id") or "unknown"
        loc = f.get("location") or {}
        path = loc.get("file", "")
        level = _sarif_level(f.get("severity") or "")
        result: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f.get("message", "")},
            "properties": {
                "severity": f.get("severity"),
                "severity_score": f.get("severity_score"),
                "cvss_estimate": f.get("cvss_estimate"),
                "remediation": f.get("remediation"),
                "revalidate": f.get("revalidate"),
                "cve": f.get("cve"),
                "maswe_id": f.get("maswe_id"),
                "owasp_mobile": f.get("owasp_mobile"),
                "source": f.get("source"),
            },
        }
        taxa = _sarif_taxa_for_finding(f)
        if taxa:
            result["taxa"] = taxa
        if path:
            phys: Dict[str, Any] = {"artifactLocation": {"uri": path.replace("\\", "/")}}
            if loc.get("line") is not None:
                phys["region"] = {"startLine": int(loc["line"])}
            result["locations"] = [{"physicalLocation": phys}]
        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": "0.2.0",
                        "informationUri": "https://github.com/beejak/apk-scanner",
                        "rules": rules,
                    }
                },
                "taxonomies": [
                    {
                        "name": "cwe",
                        "organization": "MITRE",
                        "informationUri": "https://cwe.mitre.org/",
                    },
                    {
                        "name": "maswe",
                        "organization": "OWASP",
                        "informationUri": "https://mas.owasp.org/MASWE/",
                    },
                    {
                        "name": "owasp-mobile-2024",
                        "organization": "OWASP",
                        "informationUri": "https://owasp.org/www-project-mobile-top-10/",
                    },
                ],
                "results": results,
                "properties": {
                    "summary": report.get("summary"),
                },
            }
        ],
    }
    return json.dumps(sarif, indent=2, default=str)
