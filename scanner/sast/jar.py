"""
JAR (Java) SAST: constrained string/regex scan of class and config entries.
"""

import re
import zipfile
from pathlib import Path
from typing import Any, Dict, List

from .patterns import jar_id_map, scan_text_for_rules


def run_jar_rules(jar_path: Path) -> List[Dict[str, Any]]:
    """Scan JAR (ZIP) for constrained patterns in .class and text files."""
    findings: List[Dict[str, Any]] = []
    path_str = str(jar_path)
    seen: set = set()
    id_map = jar_id_map()

    try:
        with zipfile.ZipFile(jar_path, "r") as zf:
            for name in zf.namelist():
                if not (
                    name.endswith(".class")
                    or name.endswith(".xml")
                    or name.endswith(".properties")
                    or name.endswith(".txt")
                    or name.endswith(".json")
                ):
                    continue
                try:
                    data = zf.read(name)
                except Exception:
                    continue
                if not data:
                    continue
                for m in re.finditer(rb"[\x20-\x7e]{8,200}", data):
                    s = m.group(0).decode("ascii", errors="replace")
                    for hit in scan_text_for_rules(s, id_map=id_map):
                        key = (hit["rule_id"], s[:80].lower())
                        if key in seen:
                            continue
                        seen.add(key)
                        hit["message"] = hit["message"].replace("(seen:", f"(in {name}; seen:")
                        hit["location"] = {"file": path_str, "line": None}
                        hit["source"] = "sast"
                        findings.append(hit)
    except Exception:
        pass
    return findings
