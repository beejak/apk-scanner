"""Integration test: run() on fixtures dir produces valid report shape."""
from pathlib import Path

import pytest
from scanner.run import run
from scanner.report import aggregate, to_json, to_text

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.mark.skipif(not FIXTURES.exists(), reason="tests/fixtures not found")
def test_run_produces_report_shape():
    report = run(FIXTURES, recursive=True, types=None, jobs=1, sast=False, dynamic=False)
    assert "scan_timestamp" in report
    assert "metadata" in report
    assert "findings" in report
    assert "summary" in report
    assert report["summary"]["artifacts"] >= 0
    assert report["summary"]["findings"] >= 0
    assert len(report["metadata"]) == report["summary"]["artifacts"]


@pytest.mark.skipif(not FIXTURES.exists(), reason="tests/fixtures not found")
def test_run_metadata_items_have_path_type():
    report = run(FIXTURES, recursive=True, types=None, jobs=1, sast=False, dynamic=False)
    for item in report["metadata"]:
        assert "path" in item
        assert "type" in item
        assert item["type"] in ("apk", "ipa", "jar", "so", "sdk")


def test_aggregate_roundtrip():
    report = aggregate(
        [{"path": "/x", "type": "jar", "metadata": {}}],
        [{"rule_id": "r1", "severity": "high", "message": "M"}],
        scan_timestamp="2026-01-01T00:00:00Z",
    )
    assert to_json(report)
    assert to_text(report)
    assert "r1" in to_text(report)
