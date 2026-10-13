"""
Metadata extractors per artifact type: apk, ipa, jar, so, sdk.
"""

from pathlib import Path

from .apk import extract_apk
from .ipa import extract_ipa
from .jar import extract_jar
from .so import extract_so
from .sdk import extract_sdk

__all__ = ["extract_apk", "extract_ipa", "extract_jar", "extract_so", "extract_sdk"]


def extract(path, artifact_type: str) -> dict:
    """Dispatch to the right extractor; return metadata dict. On error, return dict with 'error' key."""
    path = Path(path).resolve() if path else path
    extractors = {
        "apk": extract_apk,
        "ipa": extract_ipa,
        "jar": extract_jar,
        "so": extract_so,
        "sdk": extract_sdk,
    }
    fn = extractors.get(artifact_type)
    if not fn:
        return {"error": f"unknown type: {artifact_type}"}
    try:
        return fn(path)
    except Exception as e:
        return {"error": str(e)}
