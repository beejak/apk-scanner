"""Allowlist sources.json must stay https-only and capped."""
import json
from pathlib import Path

SOURCES = Path(__file__).resolve().parents[1] / "fixtures" / "sources.json"


def test_sources_json_shape_and_https_only():
    data = json.loads(SOURCES.read_text(encoding="utf-8"))
    assert isinstance(data.get("artifacts"), list)
    assert int(data.get("max_artifacts") or 0) <= 15
    assert len(data["artifacts"]) <= int(data["max_artifacts"])
    for item in data["artifacts"]:
        url = item.get("url") or ""
        assert url.startswith("https://"), item
        assert item.get("name")
        assert item.get("type") in ("apk", "ipa", "jar", "so", "sdk")
