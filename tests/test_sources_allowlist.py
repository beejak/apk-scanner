"""Allowlist schema + dedupe/fallback (no network)."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scanner.sources_allowlist import (
    count_by_type,
    entry_id,
    generate_sdk,
    load_history,
    load_sources,
    materialize_entry,
    max_artifacts,
    primary_entries,
    fallback_entries,
    record_scan,
    save_history,
    select_entries,
    should_skip_entry,
    validate_entry,
    validate_sources,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SOURCES = FIXTURES / "sources.json"


def test_shipped_sources_schema_https_and_cap():
    data = load_sources(SOURCES)
    assert max_artifacts(data) <= 15
    errs = validate_sources(data)
    assert errs == [], errs
    primary = primary_entries(data)
    fallback = fallback_entries(data)
    assert primary, "primary required"
    assert fallback, "fallback required"
    # Cap applies to selection, not raw list length; lists may exceed max if fallback present
    assert len(primary) <= 15
    types = set()
    for item in primary + fallback:
        typ = item["type"]
        types.add(typ)
        assert typ in ("apk", "ipa", "jar", "so", "sdk")
        assert item.get("id")
        assert item.get("name")
        if item.get("generate"):
            assert typ == "sdk"
            assert item.get("files")
        elif item.get("extract_from_apk"):
            assert typ == "so"
            assert str(item["extract_from_apk"]["url"]).startswith("https://")
        else:
            assert str(item.get("url") or "").startswith("https://"), item
    # Diversity across package kinds
    for need in ("apk", "ipa", "jar", "so", "sdk"):
        assert need in types, f"missing type {need}"


def test_backward_compat_artifacts_key(tmp_path):
    legacy = {
        "max_artifacts": 5,
        "artifacts": [
            {
                "id": "a1",
                "type": "jar",
                "name": "x.jar",
                "url": "https://example.com/x.jar",
                "version": "1.0",
            }
        ],
    }
    assert primary_entries(legacy)[0]["id"] == "a1"
    assert validate_sources(legacy) == []


def test_should_skip_same_version_and_force():
    entry = {
        "id": "junit-4.13.2",
        "type": "jar",
        "name": "junit-4.13.2.jar",
        "url": "https://repo1.maven.org/maven2/junit/junit/4.13.2/junit-4.13.2.jar",
        "version": "4.13.2",
    }
    history = {"version": 1, "entries": {}}
    skip, reason = should_skip_entry(entry, history)
    assert skip is False
    assert "not in history" in reason

    record_scan(history, entry, version="4.13.2", sha256="abc", last_scan_date="2026-10-01")
    skip, reason = should_skip_entry(entry, history)
    assert skip is True
    assert "same version" in reason

    entry_new = dict(entry, version="4.13.3")
    skip, reason = should_skip_entry(entry_new, history)
    assert skip is False
    assert "version changed" in reason

    entry_force = dict(entry, force=True)
    skip, reason = should_skip_entry(entry_force, history)
    assert skip is False
    assert reason == "force=true"


def test_should_skip_etag_and_sha_change():
    entry = {
        "id": "pkg",
        "type": "jar",
        "name": "pkg.jar",
        "url": "https://example.com/pkg.jar",
        "version": "1.0",
    }
    history = {"version": 1, "entries": {}}
    record_scan(history, entry, version="1.0", etag="etag-a", sha256="sha-a")
    assert should_skip_entry(entry, history)[0] is True
    assert should_skip_entry(entry, history, remote_etag="etag-b")[0] is False
    assert should_skip_entry(entry, history, remote_sha256="sha-b")[0] is False


def test_min_interval_days():
    entry = {
        "id": "pkg",
        "type": "jar",
        "name": "pkg.jar",
        "url": "https://example.com/pkg.jar",
        "version": "1.0",
        "min_interval_days": 30,
    }
    history = {"version": 1, "entries": {}}
    now = datetime(2026, 10, 14, tzinfo=timezone.utc)
    record_scan(history, entry, version="1.0", last_scan_date="2026-10-10")
    skip, reason = should_skip_entry(entry, history, now=now)
    assert skip is True
    assert "min_interval" in reason or "same version" in reason


def test_select_entries_primary_then_fallback(tmp_path):
    data = {
        "max_artifacts": 3,
        "primary": [
            {
                "id": "p1",
                "type": "jar",
                "name": "p1.jar",
                "url": "https://example.com/p1.jar",
                "version": "1",
            },
            {
                "id": "p2",
                "type": "jar",
                "name": "p2.jar",
                "url": "https://example.com/p2.jar",
                "version": "1",
            },
            {
                "id": "p3",
                "type": "jar",
                "name": "p3.jar",
                "url": "https://example.com/p3.jar",
                "version": "1",
            },
        ],
        "fallback": [
            {
                "id": "f1",
                "type": "jar",
                "name": "f1.jar",
                "url": "https://example.com/f1.jar",
                "version": "1",
            },
            {
                "id": "f2",
                "type": "sdk",
                "name": "f2-sdk",
                "version": "1",
                "generate": True,
                "files": [{"path": "include/a.h", "content": "//a\n"}],
            },
        ],
    }
    history = {"version": 1, "entries": {}}
    # Mark all primary as already scanned
    for e in data["primary"]:
        record_scan(history, e, version="1", last_scan_date="2026-01-01")

    selected, skipped = select_entries(data, history, max_n=3)
    assert len(selected) == 2  # only fallback left within cap
    assert all(s.get("_pool") == "fallback" for s in selected)
    assert {entry_id(s) for s in selected} == {"f1", "f2"}
    assert len(skipped) == 3
    assert count_by_type(selected)["jar"] == 1
    assert count_by_type(selected)["sdk"] == 1


def test_generate_sdk_and_history_roundtrip(tmp_path):
    entry = {
        "id": "gen-sdk",
        "type": "sdk",
        "name": "sample_sdk",
        "version": "1.0.0",
        "generate": True,
        "files": [
            {"path": "include/note.h", "content": "// hi\n"},
            {"path": "config/.env", "content": "API_KEY=x\n"},
        ],
    }
    assert validate_entry(entry) == []
    root = generate_sdk(entry, tmp_path)
    assert (root / "include" / "note.h").is_file()
    assert (root / "config" / ".env").is_file()

    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    meta = materialize_entry(entry, sandbox)
    assert meta["ok"] is True
    assert meta["sha256"]
    assert Path(meta["path"]).is_dir()

    hist_path = tmp_path / "scan_history.json"
    history = load_history(hist_path)
    record_scan(
        history,
        entry,
        version=meta["version"],
        sha256=meta["sha256"],
        last_report_dir="docs/results/weekly_test",
        last_scan_date="2026-10-14",
    )
    save_history(hist_path, history)
    reloaded = load_history(hist_path)
    assert reloaded["entries"]["gen-sdk"]["sha256"] == meta["sha256"]
    assert reloaded["entries"]["gen-sdk"]["last_report_dir"] == "docs/results/weekly_test"


def test_shipped_scan_history_is_repo_safe():
    hist = FIXTURES / "scan_history.json"
    assert hist.is_file()
    data = json.loads(hist.read_text(encoding="utf-8"))
    assert "entries" in data
    # Must not look like binary storage
    text = hist.read_text(encoding="utf-8")
    assert len(text) < 200_000
