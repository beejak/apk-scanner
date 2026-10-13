#!/usr/bin/env python3
"""
CLI for the full mobile & binary security scanner.
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
        description="Scan path for APK, IPA, JAR, .so, SDK; extract metadata and report."
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
    parser.add_argument("-o", "--output", choices=("text", "json", "csv", "html", "sarif"), default="text", help="Output format")
    parser.add_argument("-j", "--jobs", type=int, default=1, help="Parallel workers (default 1)")
    parser.add_argument("--sast", action="store_true", help="Run static analysis (SAST) and include findings in report")
    parser.add_argument("--dynamic", action="store_true", help="Run dynamic analysis (DAST) on APK/IPA when emulator and Frida are available")
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
