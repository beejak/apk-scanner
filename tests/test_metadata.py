"""Tests for scanner.metadata: extract per type (jar, so, sdk). Uses fixtures when available."""
from pathlib import Path

import pytest
from scanner.metadata import extract

# Project root and fixtures path (relative to repo)
TESTS_DIR = Path(__file__).resolve().parent
FIXTURES = TESTS_DIR / "fixtures"


def test_extract_jar_returns_dict(tmp_path):
    # Invalid or minimal JAR still returns a dict (metadata or error)
    jar = tmp_path / "minimal.jar"
    jar.write_bytes(b"PK\x03\x04")  # minimal zip
    out = extract(jar, "jar")
    assert isinstance(out, dict)
    assert "error" in out or "file_count" in out


@pytest.mark.skipif(not (FIXTURES / "junit-4.13.2.jar").exists(), reason="fixtures not present")
def test_extract_jar_fixture():
    path = FIXTURES / "junit-4.13.2.jar"
    out = extract(path, "jar")
    assert isinstance(out, dict)
    assert "error" not in out or not out.get("error")
    # Real JAR has manifest or file_count
    assert "file_count" in out or "manifest_version" in out or "Implementation-Version" in str(out)


def test_extract_sdk_dir(tmp_path):
    (tmp_path / "include").mkdir()
    (tmp_path / "lib").mkdir()
    out = extract(tmp_path, "sdk")
    assert isinstance(out, dict)
    assert "entry_count" in out or "path" in str(out)


@pytest.mark.skipif(not (FIXTURES / "libdivajni.so").exists(), reason="fixtures not present")
def test_extract_so_fixture():
    path = FIXTURES / "libdivajni.so"
    out = extract(path, "so")
    assert isinstance(out, dict)
    # With pyelftools: elf_class, machine, etc. Without: note about pyelftools
    assert "path" in out or "elf_class" in out or "note" in out
