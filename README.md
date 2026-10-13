# APK / IPA / JAR / .so / SDK Scanner

**Project path:** `C:\Users\Master\Git Projects\apk scanner` — all project and future project files live here.

CLI for **discovery**, **metadata extraction**, optional **pattern-scan SAST** (substring/regex lint), **taxonomy lookup** (CWE, NIST, OWASP, CAPEC, CISA, NSA after findings exist), and an optional **DAST scaffold** (one Android Frida check; iOS stub). Outputs JSON, text, CSV, HTML, and SARIF with optional timestamped filenames.

**Honest capability:** solid inventory + metadata + keyword/pattern lint — **not** a full SAST/DAST product yet. Useful today for binary inventory, cheap secret/HTTP/plist lint, and CI SARIF scaffolding. **Not** useful today for confirmed vuln triage, real crypto/WebView/IPC analysis, or production DAST.

## Requirements

- Python 3.9+ (3.10+ recommended for full APK metadata via apk-info)
- **Pinned deps:** `apk-info==1.0.10`, `pyelftools==0.32`, `androguard>=4.0` (see `requirements.txt`)

Without apk-info (e.g. Python &lt; 3.10), APK scan falls back to ZIP-only metadata. Without pyelftools, .so scan returns minimal info (stdlib fallback path is limited). Without androguard, DEX SAST uses a built-in ZIP string scan. **Androguard improves string/class name tables only — same substring patterns; it does not deepen analysis.**

## Public repo / fixtures

`*.apk`, `*.ipa`, and similar binaries are **gitignored**. After a public clone you must **download** training APKs yourself into `tests/fixtures/` (see [`tests/fixtures/README.md`](tests/fixtures/README.md)). Small text/SDK fixtures and a tiny JAR remain in git.

## Usage (CLI)

```bash
# Discovery + metadata (no SAST/DAST unless flagged)
python cli.py .

# Scan a path
python cli.py "C:\path\to\scan"

# JSON output (richest with metadata + findings when --sast)
python cli.py . -o json

# Pattern-scan SAST — findings in report
python cli.py . --sast

# CSV (findings table with taxonomy columns; does not include full per-artifact metadata)
python cli.py . --sast -o csv --out-file "reports/scan_{timestamp}.csv"

# HTML or SARIF (thinner than JSON/text; useful for CI scaffolding)
python cli.py . --sast -o html --out-file reports/scan.html
python cli.py . --sast -o sarif --out-file reports/scan.sarif.json

# DAST scaffold on APK — needs adb + device; Frida optional (see docs/dast.md)
python cli.py path/to/app.apk --sast --dynamic -o text

# Only certain types
python cli.py . --types apk ipa jar

# Parallel workers (discovery/metadata)
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
| **APK** | `.apk` files | apk-info: package, version, permissions, components, signatures, debuggable, etc.; else ZIP crumbs |
| **IPA** | `.ipa` files | Info.plist: bundle_id, version, display_name, min_OS (stdlib) |
| **JAR** | `.jar` files | MANIFEST.MF: Main-Class, version, Created-By (stdlib) |
| **.so** | `.so` files | pyelftools: elf_class, machine, DT_NEEDED, JNI exports, stripped |
| **SDK** | Dirs named *sdk* or with include/lib/samples/etc. | entry count, size (file counter) |

## Testing with vulnerable apps

Prepared fixtures in **`tests/fixtures/`** (see `tests/fixtures/README.md`). **APKs are not in git** — download InsecureBankv2, InsecureShop, DIVA, etc. locally. JARs, `libdivajni.so`, and `sample_sdk/` are tracked.

```bash
python cli.py tests\fixtures --sast -o text
python tests/run_fixtures_scan.py   # saves reports/fixtures_scan_<timestamp>.json and .csv
```

Sources: [Android-InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2), [diva-apk](https://github.com/zpatshueh/diva-apk), [InsecureShop](https://github.com/hax0rgb/InsecureShop).

## Report formats and taxonomy

- **Formats:** `-o text` / `-o json` (richest), `-o csv` (findings + taxonomy columns; drops full metadata blobs), `-o html` / `-o sarif` (thinner). Use `--out-file "reports/scan_{timestamp}.json"` (quote in PowerShell). Every report includes `scan_timestamp` (ISO 8601 UTC). SARIF 2.1.0 is suitable for CI scaffolding (not a substitute for confirmed triage).
- **Taxonomy:** After a finding exists, the report **looks up** CWE / NIST / OWASP / CAPEC / CISA / NSA labels. Taxonomy packaging is a mapping table — it does not deepen detection.

## Project layout

- **`cli.py`** — main entrypoint (discovery → metadata → optional SAST/DAST → report)
- **`scanner/`** — package: `discovery`, `metadata/`, `sast/` (pattern rules), `dast/` (scaffold), `taxonomy`, `report`, `run`
- **`scanner.py`** — legacy stdlib-only discovery + light metadata (no SAST/DAST); prefer `cli.py`
- **`docs/PRD.md`** — product requirements (vision + implemented vs planned)
- **`docs/dast.md`** — DAST requirements and current behavior
- **`tests/fixtures/`** — download APKs locally; see `tests/fixtures/README.md`

## SAST (pattern scan)

With `--sast`, the scanner runs **substring/regex and metadata heuristics** and adds findings. Expect **high false positives** on broad tokens like `password`, `secret`, `md5`.

- **APK:** Metadata heuristics (debuggable, allowBackup, exported components when apk-info is used) plus DEX **string** patterns via ZIP scan or androguard string tables (same rules either way). Examples: hardcoded password/API key/secret, cleartext `http://`, logging, SharedPreferences, weak SSL keywords.
- **.so:** Binary string patterns: credentials, weak crypto names (e.g. MD5, DES), JNI.
- **JAR:** ZIP scan of `.class` / config-like entries for secrets, cleartext HTTP, trust-all SSL, weak crypto names.
- **IPA:** Info.plist flags (e.g. NSAllowsArbitraryLoads) and binary string scan for credentials / cleartext URLs.
- **SDK:** Sensitive filenames and credential-like patterns in config-ish files.

Findings include `rule_id`, `severity`, `message`, `location`, and optional `masvs_id`. Optional `androguard` improves string extraction, **not** analysis depth (no xrefs / API-misuse engine yet).

## DAST (scaffold)

Use `--dynamic` for a **scaffold**, not production DAST. Android: `adb` install + optional one Frida check (`SSLContext.init` with null TrustManager). Python `frida` can emit that finding; Frida **CLI-only** runs the script but **captures no messages**. iOS: stub (returns no findings). See **`docs/dast.md`**.

## Tests

From the project root:

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

Requires `pytest` (in requirements.txt). Unit/integration coverage is strongest for discovery, taxonomy, and reporting; APK-dependent tests skip if fixtures are missing. There are **no dedicated SAST/DAST unit suites** yet.

## Roadmap

Honesty and depth next: real constrained SAST detectors, `.so` fallback wiring, SAST tests on synthetic fixtures, then more Frida checks. Optional Semgrep/mobsfscan as a pluggable backend later. See `docs/PRD.md` and `.cursor/plans/`.
