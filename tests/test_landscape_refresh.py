"""Unit tests for landscape refresh markers / table render (no live GitHub required)."""
import importlib.util
import json
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def _load_rl():
    path = ROOT / "scripts" / "refresh_landscape.py"
    spec = importlib.util.spec_from_file_location("refresh_landscape", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def test_landscape_has_auto_markers():
    rl = _load_rl()
    text = (ROOT / "docs" / "LANDSCAPE.md").read_text(encoding="utf-8")
    assert rl.START in text and rl.END in text
    assert "docs/landscape_sources.json" in text


def test_landscape_sources_allowlist():
    data = json.loads((ROOT / "docs" / "landscape_sources.json").read_text(encoding="utf-8"))
    repos = data.get("repos") or []
    assert len(repos) >= 8
    assert any(r.get("repo") == "quark-engine" for r in repos)


def test_render_and_update_landscape(tmp_path, monkeypatch):
    rl = _load_rl()
    md = tmp_path / "LANDSCAPE.md"
    md.write_text(
        "# t\n\n" + rl.START + "\nold\n" + rl.END + "\n\nafter\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(rl, "LANDSCAPE", md)
    block = rl.render_table(
        [
            {
                "label": "APKiD",
                "url": "https://github.com/rednaga/APKiD",
                "stars": 2600,
                "tag": "v3.1.0",
                "published_at": "2026-04-09",
                "pushed_at": "2026-10-07",
                "archived": False,
            }
        ]
    )
    assert "2,600" in block
    assert "v3.1.0" in block
    assert rl.update_landscape(block)
    out = md.read_text(encoding="utf-8")
    assert "APKiD" in out
    assert "after" in out
    mid = out.split(rl.START)[1].split(rl.END)[0]
    assert "old" not in mid


def test_main_with_mocked_api(tmp_path, monkeypatch):
    rl = _load_rl()
    md = tmp_path / "LANDSCAPE.md"
    md.write_text(
        "intro\n" + rl.START + "\nseed\n" + rl.END + "\noutro\n",
        encoding="utf-8",
    )
    src = tmp_path / "sources.json"
    src.write_text(
        '{"repos":[{"owner":"rednaga","repo":"APKiD","label":"APKiD",'
        '"url":"https://github.com/rednaga/APKiD"}]}',
        encoding="utf-8",
    )
    monkeypatch.setattr(rl, "LANDSCAPE", md)
    monkeypatch.setattr(rl, "SOURCES", src)

    def fake_get(url: str):
        if url.endswith("/releases/latest"):
            return {"tag_name": "v3.1.0", "published_at": "2026-04-09T00:00:00Z"}
        return {
            "stargazers_count": 42,
            "pushed_at": "2026-10-07T00:00:00Z",
            "archived": False,
        }

    with patch.object(rl, "_get_json", side_effect=fake_get):
        assert rl.main() == 0
    text = md.read_text(encoding="utf-8")
    assert "42" in text
    assert "v3.1.0" in text
    assert "outro" in text
