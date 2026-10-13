# APK / IPA / JAR / .so / SDK Scanner

**Project path:** `C:\Users\Master\Git Projects\apk scanner` — all project and future project files live here.

CLI for **discovery**, **metadata extraction**, optional **pattern-scan SAST** (substring/regex lint), **taxonomy lookup** (CWE, NIST, OWASP, CAPEC, CISA, NSA after findings exist), and an optional **DAST scaffold** (one Android Frida check; iOS stub). Outputs JSON, text, CSV, HTML, and SARIF with optional timestamped filenames.

**Honest capability:** solid inventory + metadata + constrained pattern-scan SAST — **not** a full SAST/DAST product yet. Useful today for binary inventory, cleartext/exported-component/WebView/crypto-string leads, high-confidence secret-format hits, and CI SARIF scaffolding. **Not** useful today for confirmed vuln triage, call-graph/API-misuse proof, or production DAST.

## Requirements

- Python 3.9+ (3.10+ recommended for full APK metadata via apk-info)
- **Pinned deps:** `apk-info==1.0.10`, `pyelftools==0.32`, `androguard>=4.0` (see `requirements.txt`)

Without apk-info (e.g. Python &lt; 3.10), APK scan falls back to ZIP-only metadata. Without pyelftools, `.so` metadata uses a **wired stdlib fallback** (`path`, `size_bytes`, install note). DEX SAST defaults to a built-in ZIP string scan. Optional `androguard` is **off by default** (set `APK_SCANNER_ANDROGUARD=1`); it only adds string/class name tables — same constrained patterns, much slower (`AnalyzeAPK`).

## Public repo / fixtures

`*.apk`, `*.ipa`, and similar binaries are **gitignored**. After a public clone you must **download** training APKs yourself into `tests/fixtures/` (see [`tests/fixtures/README.md`](tests/fixtures/README.md)). Small text/SDK fixtures and a tiny JAR remain in git.

**Capabilities showcase (no APKs):** browsable sandbox summaries under [`docs/results/`](docs/results/) and [`docs/capabilities.html`](docs/capabilities.html).
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

With `--sast`, the scanner runs **constrained regex + metadata heuristics** and adds findings. This is still pattern lint, not confirmed triage.

- **APK:** Metadata: debuggable, allowBackup, `usesCleartextTraffic` when available, **exported components without permission** (apk-info). DEX/ZIP strings: weak `Cipher.getInstance` / MessageDigest, WebView JS bridge / file access, trust-all heuristics, cleartext `http://` (skips Android schema URLs), network-security-config cleartext flags, high-confidence secret formats (AWS `AKIA…`, Google `AIza…`, PEM private keys). Vague `password` / `secret` / `api_key` tokens are **low/info** only.
- **.so:** Binary string patterns: credentials, weak crypto names (e.g. MD5, DES), JNI. Metadata falls back without pyelftools.
- **JAR:** Same constrained patterns on `.class` / config-like entries.
- **IPA:** Info.plist ATS (`NSAllowsArbitraryLoads`, exception insecure HTTP) and binary string scan.
- **SDK:** Sensitive filenames and credential-like patterns in config-ish files.

Findings include `rule_id`, `severity`, `message`, `location`, and optional `masvs_id`. Optional `androguard` improves string extraction, **not** analysis depth (no xrefs / API-misuse engine yet).

**Local UI (planned, not built):** a static HTML/JS drop-zone cannot run this Python scanner in-browser alone; it would need a companion local server or Tauri shell that invokes `cli.py`. See Phase 3 notes in the audit roadmap plan.

## DAST (scaffold)

Use `--dynamic` for a **scaffold**, not production DAST. Android: `adb` install + optional one Frida check (`SSLContext.init` with null TrustManager). Python `frida` can emit that finding; Frida **CLI-only** runs the script but **captures no messages**. iOS: stub (returns no findings). See **`docs/dast.md`**.

## Tests

From the project root:

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

Requires `pytest` (in requirements.txt). Use **Python 3.10+** for `apk-info`; on 3.9, APK metadata is ZIP-only. Unit tests cover discovery, taxonomy, reporting, and **synthetic SAST fixtures** (no APK binaries in git). APK-dependent integration tests skip if fixtures are missing. DAST still has no dedicated unit suite.

## Roadmap

Shipped in Phase 3 light: constrained SAST detectors, `.so` fallback wiring, synthetic SAST tests, high-confidence secret formats. Next: MASWE taxonomy depth, SARIF honesty, optional APKiD/CI sandbox, then Frida/DAST. Optional Semgrep/mobsfscan as a pluggable backend later. Static local drop-zone UI remains planned (needs local bridge to `cli.py`). See `docs/PRD.md`.
