"""SDK directory metadata (heuristic)."""

from pathlib import Path


def extract_sdk(path: Path) -> dict:
    if not path.is_dir():
        return {"error": "not a directory"}
    total = 0
    count = 0
    for p in path.rglob("*"):
        count += 1
        if p.is_file():
            try:
                total += p.stat().st_size
            except OSError:
                pass
    return {"directory": True, "entry_count": count, "size_bytes": total}
