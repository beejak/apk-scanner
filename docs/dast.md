# DAST (Dynamic Application Security Testing)

Dynamic analysis runs the app in an emulator or on a device and uses Frida to instrument runtime behavior. Findings are tagged with `source: "dynamic"` in reports.

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
- **Frida** (optional) — `frida` and `frida-tools` for hook-based checks. If missing, only install is attempted.

### Flow

1. Resolve package name from APK metadata (from static extraction).
2. Check for `adb`; if missing, skip DAST and log.
3. Check for at least one connected device/emulator; if none, skip and log.
4. Install APK on the first device: `adb -s <device> install -r <apk>`.
5. If the **Python `frida`** package is installed, the scanner spawns the app, injects a script that hooks `SSLContext.init`, and collects messages. If `SSLContext.init` is called with a null `TrustManager` (trust-all), a **runtime finding** `dast-android-ssl-trust-all` is added (high severity; CWE-295, MASVS-NETWORK-2). If only the **frida CLI** is available, the script runs but messages are not captured, so no finding is produced from hooks.

### Running an emulator

Start an AVD from Android Studio or:

```bash
emulator -avd <avd_name>
```

Then run the scanner with `--dynamic`.

## iOS

- **Supported only on macOS** (simulator and Xcode toolchain).
- **Status:** Stub only. `run_ios_dast` returns `[]` and logs that iOS DAST is not yet implemented.
- Planned: `xcrun simctl` boot, install IPA, Frida attach, runtime checks.

## Report

- Findings from DAST use the same schema as SAST: `rule_id`, `severity`, `message`, `location`, optional `evidence`.
- Each finding has **`source`: `"dynamic"`** so you can filter or highlight runtime findings.
- Text report appends ` (dynamic)` to the finding line; CSV has a `source` column.

## Exit code and logging

- If no device/emulator or no adb, DAST is skipped for that artifact; the scan still succeeds (exit 0).
- Use `-v` to see DEBUG logs (e.g. "adb not found", "no device/emulator").
