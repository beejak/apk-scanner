"""
Aggregate metadata + findings into report (JSON / text / CSV).
Report schema: { "scan_timestamp", "metadata", "findings", "summary" }
"""

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .taxonomy import classification_for_csv, classification_short


def aggregate(
    metadata_items: List[dict],
    findings: Optional[List[dict]] = None,
    scan_timestamp: Optional[str] = None,
) -> dict:
    """Build report dict. findings default empty. scan_timestamp in ISO 8601 UTC."""
    if scan_timestamp is None:
        scan_timestamp = datetime.now(timezone.utc).isoformat()
    return {
        "scan_timestamp": scan_timestamp,
        "metadata": metadata_items,
        "findings": findings or [],
        "summary": {
            "artifacts": len(metadata_items),
            "findings": len(findings or []),
        },
    }


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
            lines.append(f"  [{f.get('severity', '?')}] {f.get('rule_id', '')}: {f.get('message', '')}{loc_str}{src_tag}")
            cls_str = classification_short(f)
            if cls_str and cls_str != "—":
                lines.append(f"    Classification: {cls_str}")
    summary = report.get("summary", {})
    lines.append(f"\nTotal: {summary.get('artifacts', 0)} artifact(s), {summary.get('findings', 0)} finding(s)")
    return "\n".join(lines)


def to_csv(report: dict) -> str:
    """Human-readable CSV: one row per finding with classification (CWE, NIST, OWASP, CAPEC, CISA, NSA)."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    ts = report.get("scan_timestamp", "")
    summary = report.get("summary", {})
    writer.writerow(["scan_timestamp", "total_artifacts", "total_findings"])
    writer.writerow([ts, summary.get("artifacts", 0), summary.get("findings", 0)])
    writer.writerow([])
    header = ["scan_timestamp", "path", "severity", "rule_id", "message", "source", "masvs_id", "CWE", "NIST", "OWASP", "CAPEC", "CISA", "NSA"]
    writer.writerow(header)
    for f in report.get("findings", []):
        loc = f.get("location") or {}
        path = loc.get("file", "")
        cls = classification_for_csv(f)
        writer.writerow([
            ts,
            path,
            f.get("severity", ""),
            f.get("rule_id", ""),
            f.get("message", ""),
            f.get("source", "sast"),
            f.get("masvs_id", ""),
            cls.get("cwe", ""),
            cls.get("nist", ""),
            cls.get("owasp", ""),
            cls.get("capec", ""),
            cls.get("cisa", ""),
            cls.get("nsa", ""),
        ])
    return buf.getvalue()


def to_html(report: dict) -> str:
    """Single-file HTML report with metadata and findings tables."""
    ts = report.get("scan_timestamp", "")
    summary = report.get("summary", {})
    meta = report.get("metadata", [])
    findings = report.get("findings", [])

    html_parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Scan Report</title>",
        "<style>body{font-family:system-ui,sans-serif;margin:1rem 2rem;background:#f8f9fa;}",
        "h1{color:#0d6efd;} .meta-table,.findings-table{border-collapse:collapse;width:100%;margin:1rem 0;}",
        ".meta-table th,.meta-table td,.findings-table th,.findings-table td{border:1px solid #dee2e6;padding:0.5rem 0.75rem;text-align:left;}",
        "th{background:#e9ecef;} .severity-high{color:#dc3545;} .severity-medium{color:#fd7e14;} .severity-low{color:#198754;}",
        ".source-dynamic{font-style:italic;color:#6c757d;} .summary{margin:1rem 0;}</style></head><body>",
        f"<h1>Scan Report</h1><p class='summary'>Scan time: {_escape(ts)}</p>",
        f"<p class='summary'><strong>Artifacts:</strong> {summary.get('artifacts', 0)} &nbsp; <strong>Findings:</strong> {summary.get('findings', 0)}</p>",
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
        html_parts.append("<h2>Findings</h2><table class='findings-table'><tr><th>Severity</th><th>Rule</th><th>Message</th><th>Source</th><th>Path</th></tr>")
        for f in findings:
            sev = f.get("severity", "")
            rule_id = _escape(f.get("rule_id", ""))
            msg = _escape(f.get("message", ""))
            src = f.get("source", "sast")
            loc = f.get("location") or {}
            path = _escape(loc.get("file", ""))
            src_label = "dynamic" if src == "dynamic" else "static"
            cls_str = classification_short(f)
            if cls_str and cls_str != "—":
                msg = msg + " [" + cls_str + "]"
            html_parts.append(
                f"<tr><td class='severity-{sev}'>{sev}</td><td>{rule_id}</td><td>{msg}</td>"
                f"<td class='source-dynamic'>{src_label}</td><td>{path}</td></tr>"
            )
        html_parts.append("</table>")

    html_parts.append("</body></html>")
    return "\n".join(html_parts)


def _escape(s: str) -> str:
    if not isinstance(s, str):
        s = str(s)
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def to_sarif(report: dict, tool_name: str = "apk-scanner") -> str:
    """SARIF 2.1.0 minimal: one run with results and reportingDescriptor per rule."""
    findings = report.get("findings", [])
    rule_ids = sorted({f.get("rule_id") or "unknown" for f in findings})
    rules = [
        {
            "id": rid,
            "shortDescription": {"text": rid},
            "defaultConfiguration": {"level": "warning"},
        }
        for rid in rule_ids
    ]
    results = []
    for i, f in enumerate(findings):
        rule_id = f.get("rule_id") or "unknown"
        loc = f.get("location") or {}
        path = loc.get("file", "")
        result = {
            "ruleId": rule_id,
            "level": "error" if f.get("severity") == "critical" else "warning",
            "message": {"text": f.get("message", "")},
        }
        if path:
            result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": path}}}]
        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": "1.0",
                        "informationUri": "https://github.com/",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, default=str)
