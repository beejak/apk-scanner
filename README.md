# APK / IPA / JAR / .so / SDK Scanner

**Project path:** `C:\Users\Master\Git Projects\apk scanner` — all project and future project files live here.

Full-fledged scanner: **discovery**, **metadata extraction**, **SAST** (static analysis for APK, IPA, JAR, .so, SDK), **taxonomy** (CWE, NIST, OWASP, CAPEC, CISA, NSA), and optional **DAST** (emulator + Frida). Outputs JSON, text, CSV, HTML, and SARIF reports with optional timestamped filenames.

## Requirements

- Python 3.9+ (3.10+ recommended for full APK metadata via apk-info)
- **Pinned deps:** `apk-info==1.0.10`, `pyelftools==0.32`, `androguard>=4.0` (see `requirements.txt`)

Without apk-info (e.g. Python &lt; 3.10), APK scan falls back to ZIP-only metadata. Without pyelftools, .so scan returns minimal info. Without androguard, DEX SAST uses a built-in ZIP string scan (still finds patterns).

## Usage (new CLI)

```bash
# Scan current directory (recursive)
python cli.py .

# Scan a path
python cli.py "C:\path\to\scan"

# JSON output
python cli.py . -o json

# CSV output (human-readable table with CWE/NIST/OWASP/CAPEC/CISA/NSA columns)
python cli.py . --sast -o csv --out-file "reports/scan_{timestamp}.csv"

# HTML or SARIF (e.g. for CI / code scanning)
python cli.py . --sast -o html --out-file reports/scan.html
python cli.py . --sast -o sarif --out-file reports/scan.sarif.json

# With static analysis (SAST) — findings in report
python cli.py . --sast

# With dynamic analysis (DAST) on APK/IPA — requires emulator + Frida
python cli.py path/to/app.apk --sast --dynamic -o text

# Only certain types
python cli.py . --types apk ipa jar

# Parallel workers
python cli.py . -j 4

# Verbose / quiet
python cli.py . -v
python cli.py . --quiet

# Write report to file (use {timestamp} for timestamped names)
python cli.py . -o json --out-file report.json
python cli.py . --sast -o json --out-file reports/scan_{timestamp}.json
```

## What it detects

| Type | Detection | Metadata (when deps installed) |
|------|-----------|--------------------------------|
| **APK** | `.apk` files | apk-info: package, version, permissions, components, signatures, debuggable, etc. |
| **IPA** | `.ipa` files | Info.plist: bundle_id, version, display_name, min_OS |
| **JAR** | `.jar` files | MANIFEST.MF: Main-Class, version, Created-By |
| **.so** | `.so` files | pyelftools: elf_class, machine, DT_NEEDED, JNI exports, stripped |
| **SDK** | Dirs named *sdk* or with include/lib/samples/etc. | entry count, size |

## Testing with vulnerable apps

Prepared fixtures in **`tests/fixtures/`** (see `tests/fixtures/README.md`): InsecureBankv2.apk, DivaApplication.apk (with native .so), JARs, libdivajni.so, sample_sdk. Run:

```bash
python cli.py tests\fixtures --sast -o text
python tests/run_fixtures_scan.py   # saves reports/fixtures_scan_<timestamp>.json and .csv
```

To add your own: drop InsecureBankv2 from [Android-InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2), DIVA from [diva-apk](https://github.com/zpatshueh/diva-apk), or any APK/IPA/JAR/.so into a folder and scan it.

## Report formats and taxonomy

- **Formats:** `-o text` (default), `-o json`, `-o csv`, `-o html`, `-o sarif`. Use `--out-file "reports/scan_{timestamp}.json"` (quote in PowerShell) for timestamped filenames (`YYYYMMDD_HHMMSS`). Every report includes `scan_timestamp` (ISO 8601 UTC). SARIF 2.1.0 is suitable for GitHub Code Scanning and similar.
- **Taxonomy:** Each finding is cross-referenced with **CWE**, **NIST** (SP 800-53), **OWASP** (MASVS, Mobile Top 10), **CAPEC**, **CISA**, and **NSA** where applicable. Shown in text (classification line), CSV (one column per DB), and JSON (`classification` object per finding).

## Project layout

- **`cli.py`** — main entrypoint (discovery → metadata → SAST → report)
- **`scanner/`** — package: `discovery`, `metadata/` (apk, ipa, jar, so, sdk), `sast/` (dex, jar, ipa, native, sdk), `taxonomy` (CWE/NIST/OWASP/CAPEC/CISA/NSA mapping), `report`, `run`
- **`scanner.py`** — legacy minimal scanner (stdlib only)
- **`docs/PRD.md`** — product requirements, test use cases, reference apps
- **`tests/fixtures/`** — test APKs, JARs, .so, SDK; see `tests/fixtures/README.md`

## SAST (static analysis)

With `--sast`, the scanner runs static checks and adds findings to the report:

- **APK:** Metadata-based (debuggable, allowBackup, exported components when apk-info is used) and **DEX-based** rules. DEX rules run via a built-in ZIP scan of `.dex` contents (no extra deps) or via **androguard** if installed (richer analysis). Patterns: hardcoded password/API key/secret, cleartext HTTP, logging, SharedPreferences, weak SSL.
- **.so:** Binary string patterns: hardcoded credentials, weak crypto (e.g. MD5, DES), JNI.
- **JAR (Java executable):** ZIP scan of `.class`, `.xml`, `.properties` for hardcoded password/API key/secret, cleartext HTTP, trust-all SSL, weak crypto (MD5, DES). Same CWE/NIST/OWASP/CAPEC/CISA/NSA classification as APK where applicable.
- **IPA (iOS):** Info.plist checks (NSAllowsArbitraryLoads, UIFileSharingEnabled, LSSupportsOpeningDocumentsInPlace, NSAllowsLocalNetworking) and binary string scan for hardcoded credentials and cleartext URLs. Full taxonomy mapping.
- **SDK:** Directory scan for sensitive filenames (`.pem`, `.key`, `.p12`, `*secret*`, `.env`, etc.) and credential-like patterns in `.properties`, `.xml`, `.json`, `.env`, `.yaml`, `.config`. Taxonomy: CWE, NIST, OWASP, CAPEC, CISA, NSA.

Findings include `rule_id`, `severity`, `message`, `location`, and optional `masvs_id` (OWASP MASVS). Optional dependency for full DEX analysis: `androguard>=4.0` (may require C++ build tools on Windows).

## DAST (dynamic analysis)

Use `--dynamic` to run runtime checks on APK/IPA. Requires Android SDK (`adb`) and a device/emulator; optional Frida for hook-based checks. iOS DAST is macOS-only and not yet implemented. See **`docs/dast.md`** for requirements and flow.

## Tests

From the project root:

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

Requires `pytest` (in requirements.txt). Fixture-based tests are skipped if `tests/fixtures/` is missing.

## Roadmap

DAST is scaffolded (Android: adb install + optional Frida; iOS: stub). Next: more Frida checks, iOS simulator support; optional Semgrep/mobsfscan integration. See `.cursor/plans/full_mobile_scanner_replan.md` and the PRD.
