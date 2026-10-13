"""
Android DAST scaffold: adb install + one optional Frida SSLContext.init check.
Requires: Android SDK (adb), device/emulator; Python frida for message capture
(CLI frida alone produces no hook findings). Not a full runtime suite.
"""

import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


def run_android_dast(apk_path: Path, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Run dynamic checks on Android APK. Returns list of findings.
    If adb or Frida is missing, or no device/emulator, returns [] and logs.
    """
    findings: List[Dict[str, Any]] = []
    apk_path = Path(apk_path)
    pkg = metadata.get("package_name") or metadata.get("package")
    if not pkg:
        logger.warning("DAST Android: no package name in metadata for %s", apk_path)
        return findings

    if not _has_adb():
        logger.info("DAST Android: adb not found; skip dynamic scan for %s", apk_path.name)
        return findings
    devices = _adb_devices()
    if not devices:
        logger.info("DAST Android: no device/emulator; skip dynamic scan for %s", apk_path.name)
        return findings

    # Install APK (optional: could skip if already installed and same version)
    install_ok = _adb_install(apk_path, devices[0])
    if not install_ok:
        logger.warning("DAST Android: install failed for %s", apk_path.name)
        return findings

    # Run Frida-based checks: prefer Python frida API (to capture messages), else CLI
    findings.extend(_run_frida_checks(pkg, apk_path, devices[0]))

    return findings


def _has_adb() -> bool:
    return shutil.which("adb") is not None


def _has_frida_cli() -> bool:
    return shutil.which("frida") is not None


def _has_frida_python() -> bool:
    try:
        import frida  # noqa: F401
        return True
    except ImportError:
        return False


def _adb_devices() -> List[str]:
    """Return list of device serials (e.g. emulator-5554)."""
    try:
        out = subprocess.run(
            ["adb", "devices"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if out.returncode != 0:
            return []
        lines = [l.strip() for l in out.stdout.splitlines() if l.strip()]
        devices = []
        for line in lines[1:]:  # skip "List of devices attached"
            part = line.split()
            if part and part[1] == "device":
                devices.append(part[0])
        return devices
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.debug("adb devices failed: %s", e)
        return []


def _adb_install(apk_path: Path, device: str) -> bool:
    try:
        out = subprocess.run(
            ["adb", "-s", device, "install", "-r", str(apk_path)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if out.returncode != 0:
            logger.debug("adb install: %s", out.stderr or out.stdout)
            return False
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.debug("adb install failed: %s", e)
        return False


def _run_frida_checks(pkg: str, apk_path: Path, device: str) -> List[Dict[str, Any]]:
    """
    Run Frida script(s) against the app. Detects SSLContext.init with null TrustManager
    (trust-all) and adds a runtime finding. Prefers Python frida API to capture messages.
    """
    if _has_frida_python():
        return _run_frida_python(pkg, apk_path)
    if _has_frida_cli():
        return _run_frida_cli(pkg, apk_path)
    logger.info("DAST Android: Frida not found (install frida-tools or frida); skip hooks for %s", apk_path.name)
    return []


def _run_frida_python(pkg: str, apk_path: Path) -> List[Dict[str, Any]]:
    """Use Python frida to spawn app, inject script, collect messages, map to findings."""
    import frida  # type: ignore

    findings: List[Dict[str, Any]] = []
    messages: List[dict] = []

    def on_message(message: dict, data: Any) -> None:
        if message.get("type") == "send" and isinstance(message.get("payload"), dict):
            messages.append(message["payload"])

    script_js = _default_frida_script()
    try:
        device = frida.get_usb_device(timeout=5)
        pid = device.spawn([pkg])
        session = device.attach(pid)
        script = session.create_script(script_js)
        script.on("message", on_message)
        script.load()
        device.resume(pid)
        import time
        time.sleep(8)
        session.detach()
        try:
            device.kill(pid)
        except Exception:
            pass
    except Exception as e:
        logger.debug("Frida Python run failed: %s", e)
        return findings

    for payload in messages:
        if payload.get("type") == "ssl_init" and payload.get("trustAll") is True:
            findings.append({
                "rule_id": "dast-android-ssl-trust-all",
                "severity": "high",
                "message": "Runtime: SSLContext.init called with null TrustManager (trust-all); enables MITM.",
                "location": {"file": str(apk_path), "line": None},
                "evidence": payload,
            })
            break
    return findings


def _run_frida_cli(pkg: str, apk_path: Path) -> List[Dict[str, Any]]:
    """Fallback: run frida CLI; cannot capture send() easily so no findings from hooks."""
    script = _default_frida_script()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False, encoding="utf-8") as f:
        f.write(script)
        script_path = Path(f.name)
    try:
        subprocess.run(
            ["frida", "-U", "-f", pkg, "-l", str(script_path), "--no-pause", "-q"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        pass
    finally:
        try:
            script_path.unlink(missing_ok=True)
        except Exception:
            pass
    return []


def _default_frida_script() -> str:
    """Minimal script: hook SSLContext.init to detect pinning bypass."""
    return r"""
'use strict';
var findings = [];
try {
  var SSLContext = Java.use('javax.net.ssl.SSLContext');
  SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function (km, tm, sr) {
    send({ type: 'ssl_init', trustAll: (tm === null) });
    this.init(km, tm, sr);
  };
} catch (e) { send({ type: 'error', message: e.message }); }
rpc.exports = { getFindings: function () { return findings; } };
"""
