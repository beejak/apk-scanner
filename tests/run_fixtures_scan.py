#!/usr/bin/env python3
"""
Run scanner on tests/fixtures and optionally save report.
Usage: python tests/run_fixtures_scan.py [--out report.json]
"""
import sys
from pathlib import Path

# Add project root
root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root))

from datetime import datetime, timezone
from scanner.run import run
from scanner.report import to_text, to_json, to_csv

FIXTURES = root / "tests" / "fixtures"
TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def main():
    if not FIXTURES.exists():
        print("Fixtures dir not found:", FIXTURES)
        return 1
    print("Scanning", FIXTURES, "(APK, JAR, SDK, and optionally IPA/.so)...")
    report = run(FIXTURES, recursive=True, types=None, jobs=1, sast=True)
    n_artifacts = len(report.get("metadata", []))
    n_findings = len(report.get("findings", []))
    print(to_text(report))
    out_dir = root / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_json = out_dir / f"fixtures_scan_{TS}.json"
    out_csv = out_dir / f"fixtures_scan_{TS}.csv"
    out_json.write_text(to_json(report), encoding="utf-8")
    out_csv.write_text(to_csv(report), encoding="utf-8")
    print("\nSaved:", out_json, out_csv)
    return 0


if __name__ == "__main__":
    sys.exit(main())
