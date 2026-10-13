# DAST (Dynamic Application Security Testing)

**Status:** scaffold only — not production DAST. No exploit / bypass weaponization.

Dynamic mode can install an APK via `adb` and, if the Python `frida` package is available, run Android observation hooks. Findings use `source: "dynamic"`. iOS is a stub.

## Enabling DAST

```bash
python cli.py path/to/app.apk --sast --dynamic -o text
```

Runs only for **APK** and **IPA**. Other types skipped.

## Android

### Requirements

- **adb** on PATH (Android SDK)
- **Device or emulator** listed by `adb devices`
- **Python `frida`** for message capture (recommended). Frida **CLI-only** may run the script but **captures no findings**

Missing adb/device → skip cleanly (exit 0).

### Checks implemented

| rule_id | Severity | Behavior |
|---------|----------|----------|
| `dast-android-ssl-trust-all` | critical | `SSLContext.init` with null TrustManager |
| `dast-android-sensitive-log` | high | `Log.*` message matches password/token/secret-like patterns |
| `dast-android-cleartext-observed` | high | `http://` seen via `URL` / `Uri.parse` |

No automated UI flows, pinning-bypass suite, or evidence harvesting beyond Frida messages.

### Flow

1. Package name from metadata  
2. adb / device check  
3. `adb install -r`  
4. Frida spawn + hooks (if Python frida available)  
5. Enrich findings like SAST (taxonomy, scores, remediation)

## iOS

Stub only: `run_ios_dast` → `[]`. Not implemented on macOS either beyond the stub log.

## Report

Same enrichment as SAST. Text appends ` (dynamic)`; CSV `source` column; HTML fix/revalidate blocks.

## Honesty

This is **not** a browser emulator, cloud device farm, or production runtime suite. Local adb/AVD only when you already have them.
