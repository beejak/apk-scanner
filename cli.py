#!/usr/bin/env python3
"""
CLI for discovery, metadata, optional pattern-scan SAST, optional plugins/SCA, and DAST scaffold.

This is a discovery + metadata + keyword/pattern-lint tool, not a full SAST/DAST product.
"""

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from scanner.run import run
from scanner.report import to_csv, to_html, to_json, to_sarif, to_text

# Nomenclature: use {timestamp} in --out-file for scan_20250221_143052.json style names
REPORT_TIMESTAMP_FORMAT = "%Y%m%d_%H%M%S"


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Discover APK/IPA/JAR/.so/SDK under a path, extract metadata, and optionally "
            "run pattern-scan SAST (--sast), optional plugins (--apkid/--semgrep/--mobsfscan), "
            "real OSV SCA (--sca), and/or a DAST scaffold (--dynamic). "
            "SAST: constrained regex/metadata heuristics including WebView JS bridge, "
            "SQL/content-provider leads, unsafe deserialization, exported+unprotected intent/"
            "provider risks, path traversal/file URI, Runtime.exec/ProcessBuilder, trust-all, "
            "cleartext flags, high-confidence secret formats. Critical severity used where "
            "justified. Vague password tokens are info (assignment-shaped still low). "
            "Taxonomy: CWE/NIST/OWASP/MASWE/Mobile Top 10 2024/CAPEC/CISA/NSA plus "
            "severity_score, cvss_estimate (rule-based, not NVD CVE CVSS), remediation, "
            "revalidate. CVE IDs only via --sca when component+version extracted (never invented). "
            "Plugins/SCA skip cleanly if tools/network missing. "
            "DEX scan is ZIP-based by default; APK_SCANNER_ANDROGUARD=1 for optional androguard. "
            "Formats: text, json, csv, html, sarif."
        )
    )
    parser.add_argument("path", nargs="?", default=".", type=Path, help="Path to scan (file or directory)")
    parser.add_argument("-r", "--recursive", action="store_true", default=True, help="Recurse into directories")
    parser.add_argument("--no-recursive", action="store_false", dest="recursive")
    parser.add_argument(
        "--types",
        nargs="+",
        default=["apk", "ipa", "jar", "so", "sdk"],
        choices=["apk", "ipa", "jar", "so", "sdk"],
        help="Artifact types to include",
    )
    parser.add_argument(
        "-o",
        "--output",
        choices=("text", "json", "csv", "html", "sarif"),
        default="text",
        help=(
            "Output format: json/text (richest: scores, taxonomy, remediation); "
            "csv (findings table + score/CVSS/remediation/taxonomy columns; no full metadata); "
            "html (executive summary + per-finding fix/revalidate); sarif (CI + taxa/help)"
        ),
    )
    parser.add_argument("-j", "--jobs", type=int, default=1, help="Parallel workers for discovery/metadata (default 1)")
    parser.add_argument(
        "--sast",
        action="store_true",
        help=(
            "Run pattern-scan SAST: constrained string/regex + metadata heuristics "
            "(critical/high impact rules: JS bridge, runtime exec, trust-all, secrets, "
            "exported intent/provider risks, etc.). Not deep static analysis or confirmed vulns"
        ),
    )
    parser.add_argument(
        "--dynamic",
        action="store_true",
        help=(
            "Run DAST scaffold on APK/IPA: Android needs adb + device; Frida hooks for "
            "SSL trust-all, sensitive logging, cleartext URL observation when Python frida "
            "is installed; iOS stub. Skips cleanly without adb/device"
        ),
    )
    parser.add_argument(
        "--apkid",
        action="store_true",
        help="Optional: run APKiD on APKs if `apkid` is on PATH (packer/obfuscator tags); skip if missing",
    )
    parser.add_argument(
        "--semgrep",
        action="store_true",
        help="Optional: run Semgrep subprocess if `semgrep` on PATH; skip if missing",
    )
    parser.add_argument(
        "--mobsfscan",
        action="store_true",
        help="Optional: run mobsfscan subprocess if `mobsfscan` on PATH; skip if missing",
    )
    parser.add_argument(
        "--sca",
        action="store_true",
        help=(
            "Optional: real OSV CVE/advisory lookup when component+version can be extracted "
            "(JAR names, pom.properties, Gradle hints). Never invents CVE IDs. Caches under "
            "~/.cache/apk-scanner/osv (or APK_SCANNER_SCA_CACHE). Polite rate delay via "
            "APK_SCANNER_OSV_DELAY (default 0.35s)"
        ),
    )
    parser.add_argument(
        "--sca-offline",
        action="store_true",
        help="With --sca: do not call OSV (use only if you want extract-only skip of live queries)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose (DEBUG) logging")
    parser.add_argument("--quiet", action="store_true", help="Only report to stdout; no progress logs")
    parser.add_argument(
        "--out-file",
        type=Path,
        help="Write report to file. Use {timestamp} for nomenclature, e.g. reports/scan_{timestamp}.json",
    )
    args = parser.parse_args()

    if args.quiet:
        logging.basicConfig(level=logging.WARNING, format="%(message)s")
    elif args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")
    else:
        logging.basicConfig(level=logging.INFO, format="%(message)s")

    root = args.path.resolve()
    if not root.exists():
        logging.error("Path does not exist: %s", root)
        return 1

    report = run(
        root,
        recursive=args.recursive,
        types=set(args.types),
        jobs=max(1, args.jobs),
        sast=args.sast,
        dynamic=args.dynamic,
        apkid=args.apkid,
        semgrep=args.semgrep,
        mobsfscan=args.mobsfscan,
        sca=args.sca,
        sca_offline=args.sca_offline,
    )

    if args.output == "json":
        out = to_json(report)
    elif args.output == "csv":
        out = to_csv(report)
    elif args.output == "html":
        out = to_html(report)
    elif args.output == "sarif":
        out = to_sarif(report)
    else:
        out = to_text(report)
    if args.out_file:
        out_path = args.out_file
        if "{timestamp}" in str(out_path):
            ts = datetime.now(timezone.utc).strftime(REPORT_TIMESTAMP_FORMAT)
            out_path = Path(str(out_path).replace("{timestamp}", ts))
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(out, encoding="utf-8")
        logging.info("Report written to %s", out_path)
    else:
        print(out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
