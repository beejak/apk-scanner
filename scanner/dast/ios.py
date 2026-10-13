"""
iOS DAST: run IPA in simulator (macOS), instrument with Frida, collect runtime findings.
Requires: macOS, Xcode/simulator, Frida. Not implemented on Windows/Linux.
"""

import logging
import sys
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


def run_ios_dast(ipa_path: Path, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Run dynamic checks on iOS IPA. Returns list of findings.
    Only supported on macOS with simulator and Frida; otherwise returns [].
    """
    if sys.platform != "darwin":
        logger.info("DAST iOS: requires macOS; skip for %s", ipa_path.name)
        return []
    # TODO: boot simulator, install IPA (xcrun simctl install), run Frida
    logger.info("DAST iOS: not yet implemented; skip for %s", ipa_path.name)
    return []
