"""Tests for scanner.discovery: classify, discover."""
import os
import tempfile
from pathlib import Path

import pytest
from scanner.discovery import classify, discover


def test_classify_file_apk():
    p = Path("/dummy/app.apk")
    assert classify(p, is_file=True) == "apk"


def test_classify_file_ipa_jar_so():
    assert classify(Path("/a.ipa"), is_file=True) == "ipa"
    assert classify(Path("/a.jar"), is_file=True) == "jar"
    assert classify(Path("/a.so"), is_file=True) == "so"


def test_classify_file_unknown():
    assert classify(Path("/a.txt"), is_file=True) is None
    assert classify(Path("/a.dex"), is_file=True) is None


def test_classify_dir_sdk_by_name():
    with tempfile.TemporaryDirectory(prefix="my_sdk_") as d:
        path = Path(d)
        assert path.name.lower().startswith("my_sdk")
        assert "sdk" in path.name.lower()
        assert classify(path, is_file=False) == "sdk"


def test_classify_dir_sdk_by_indicators():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "include").mkdir()
        (root / "lib").mkdir()
        assert classify(root, is_file=False) == "sdk"


def test_classify_dir_not_sdk():
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "other").mkdir()
        assert classify(Path(d), is_file=False) is None


def test_discover_empty_dir():
    with tempfile.TemporaryDirectory() as d:
        items = discover(Path(d), recursive=True, types=None)
        assert items == []


def test_discover_finds_jar(tmp_path):  # tmp_path from pytest
    (tmp_path / "app.jar").write_bytes(b"PK\x03\x04")
    items = discover(tmp_path, recursive=False, types={"jar"})
    assert len(items) == 1
    assert items[0][1] == "jar"
    assert items[0][0].name == "app.jar"


def test_discover_respects_types(tmp_path):
    (tmp_path / "a.apk").write_bytes(b"PK")
    (tmp_path / "b.jar").write_bytes(b"PK")
    items_apk = discover(tmp_path, recursive=False, types={"apk"})
    items_jar = discover(tmp_path, recursive=False, types={"jar"})
    assert len(items_apk) == 1
    assert items_apk[0][1] == "apk"
    assert len(items_jar) == 1
    assert items_jar[0][1] == "jar"
