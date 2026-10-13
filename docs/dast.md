# DAST (Dynamic Application Security Testing)

**Status:** scaffold only — not production DAST.

Dynamic mode can install an APK via `adb` and, if the Python `frida` package is available, run **one** Android hook check. Findings are tagged with `source: "dynamic"` in reports. iOS is a stub.

## Enabling DAST

Use the `--dynamic` flag:

```bash
python cli.py path/to/app.apk --sast --dynamic -o text
```

DAST runs only on **APK** and **IPA** artifacts. Other types are skipped.

## Android

### Requirements

- **Android SDK** — `adb` on PATH
- **Device or emulator** — at least one device listed by `adb devices` (e.g. AVD running)
- **Frida** (optional) — Python package `frida` for the SSL check with message capture; or `frida` CLI (script may run but **no findings** are captured from hooks)

### What is implemented today

Exactly **one** runtime check when Python Frida works:

| Check | Behavior |
|-------|----------|
| `dast-android-ssl-trust-all` | Hook `SSLContext.init`; if called with a null `TrustManager`, emit a high-severity finding (CWE-295 / MASVS-NETWORK-2) |

There is **no** automated UI flow, network capture, storage inspection, pinning-bypass suite, or evidence harvesting beyond that Frida message.

### Flow

1. Resolve package name from APK metadata (from static extraction).
2. Check for `adb`; if missing, skip DAST and log.
3. Check for at least one connected device/emulator; if none, skip and log.
4. Install APK on the first device: `adb -s <device> install -r <apk>`.
5. If the **Python `frida`** package is installed, spawn the app, inject the SSLContext script, and collect messages. If only the **frida CLI** is available, the script may run but messages are **not** captured, so **no** hook-based finding is produced. If Frida is missing entirely, install may succeed and hooks are skipped.

### Running an emulator

Start an AVD from Android Studio or:

```bash
emulator -avd <avd_name>
```

Then run the scanner with `--dynamic`.

## iOS

- **Supported only on macOS** (simulator and Xcode toolchain) when implemented.
- **Status:** Stub only. `run_ios_dast` returns `[]` and logs that iOS DAST is not yet implemented (also skips on non-Darwin).
- Planned (not implemented): `xcrun simctl` boot, install IPA, Frida attach, runtime checks.

## Report

- Findings from DAST use the same schema as SAST and pass through the same enrichment: `rule_id`, `severity`, `severity_score`, `message`, `location`, optional `evidence`, plus `classification`, `cvss_estimate` (rule-based, not NVD CVE CVSS), `remediation`, `revalidate`, and `cve: null`.
- Each finding has **`source`: `"dynamic"`** so you can filter or highlight runtime findings.
- Text report appends ` (dynamic)` to the finding line; CSV has a `source` column; HTML shows fix/revalidate blocks when present.

## Exit code and logging

- If no device/emulator or no adb, DAST is skipped for that artifact; the scan still succeeds (exit 0).
- Use `-v` to see DEBUG logs (e.g. "adb not found", "no device/emulator").
