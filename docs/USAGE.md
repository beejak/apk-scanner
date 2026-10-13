# How to use apk-scanner

In-depth guide matching **shipped** code only. Entry overview: [README.md](../README.md). Product status: [PRD.md](PRD.md). DAST details: [dast.md](dast.md). Competitive landscape + 6-month backlog: [LANDSCAPE.md](LANDSCAPE.md).

## Install

```bash
# Python 3.10+ required for full APK metadata (apk-info). 3.11/3.12 fine.
git clone https://github.com/beejak/apk-scanner.git
cd apk-scanner
python -m pip install -r requirements.txt
python -m pytest tests/ -q
```

Pinned core deps: `apk-info`, `pyelftools`, `androguard` (optional at runtime; ZIP DEX scan is default). Optional tools **not** in requirements (install yourself if you want flags):

| Tool | Flag | Notes |
|------|------|--------|
| `apkid` | `--apkid` | On PATH; APK packer/obfuscator tags |
| `semgrep` | `--semgrep` | On PATH; default config `rules/semgrep/android-mastg-starter.yml` (override `APK_SCANNER_SEMGREP_CONFIG`; see `rules/semgrep/README.md` for full MASTG fetch) |
| `mobsfscan` | `--mobsfscan` | On PATH |
| `quark` | `--quark` | On PATH; Quark-Engine behavior score / family **hints** (not an AV verdict) |
| `jadx` + `nuclei` | `--nuclei` | Both on PATH; jadx decompile to temp → `nuclei -t file/android`; purge after |
| `frida` (Python) | `--dynamic` | Message capture for Android hooks |
| `adb` + device/emulator | `--dynamic` | Required for any Android DAST |

Missing optional tools → log + skip (scan still exits 0).

## CLI overview

```bash
python cli.py <path> [options]
```

| Flag | Meaning |
|------|---------|
| `--types apk ipa jar so sdk` | Filter artifact types |
| `-j N` | Parallel discovery/metadata workers |
| `--sast` | Built-in pattern-scan SAST |
| `--dynamic` | DAST scaffold (adb/device; Frida optional) |
| `--apkid` / `--semgrep` / `--mobsfscan` / `--quark` / `--nuclei` | Optional plugin backends |
| `--sca` | Real OSV lookups when name+version extracted; fills `summary.sca` inventory + CVE board |
| `--sca-offline` | With `--sca`: do not call network |
| `-o text\|json\|csv\|html\|sarif` | Report format |
| `--out-file path` | Write report; `{timestamp}` → `YYYYMMDD_HHMMSS` |
| `-v` / `--quiet` | Logging |

Env:

- `APK_SCANNER_ANDROGUARD=1` — optional androguard string tables (same rules, slower)
- `APK_SCANNER_SCA_CACHE` — OSV cache dir (default `~/.cache/apk-scanner/osv`)
- `APK_SCANNER_OSV_DELAY` — seconds between live OSV queries (default `0.35`)
- `APK_SCANNER_SEMGREP_CONFIG` — Semgrep config id/path

## Scanning by type

### APK

```bash
python cli.py path/to/app.apk --sast -o json --out-file reports/apk_{timestamp}.json
```

Metadata via `apk-info` when installed (package, permissions, components, debuggable, backup, cleartext when exposed). SAST: metadata rules (debuggable, allowBackup, cleartext flag, **exported activity intent risk**, **exported unprotected provider → critical**, other exported unprotected) + DEX/ZIP string rules (WebView JS bridge **critical**, Runtime.exec **critical**, trust-all **critical**, SQL concat, deserialization, path/file URI, weak crypto, secrets, demoted password noise).

### IPA

```bash
python cli.py path/to/app.ipa --sast -o text
```

Info.plist ATS checks + binary string scan. DAST: stub (returns no findings).

### JAR

```bash
python cli.py path/to/lib.jar --sast --sca -o json
```

ZIP/string patterns (JAR-prefixed rule ids). `--sca` may resolve `name-version.jar` / pom.properties → OSV.

### .so

```bash
python cli.py path/to/libfoo.so --sast -o text
```

String/symbol patterns; pyelftools metadata or stdlib fallback.

### SDK directory

```bash
python cli.py path/to/some_sdk --types sdk --sast -o text
```

Heuristic SDK dirs; sensitive filenames / credential-like config patterns.

### Mixed tree

```bash
python cli.py tests/fixtures --sast -o html --out-file reports/fixtures.html
```

APKs are **not** in git — download training samples locally (see `tests/fixtures/README.md`).

## SAST severity (honest)

Pattern lint / metadata heuristics — **leads**, not confirmed exploits.

| Band | Examples (shipped) |
|------|---------------------|
| **critical** | AWS key / PEM private key formats; `addJavascriptInterface`; trust-all SSL; `Runtime.exec`/`ProcessBuilder`; exported ContentProvider without permission |
| **high** | Exported activity without permission (intent risk); weak Cipher; SQL concat; unsafe deserialization; path traversal/file URI; Google API key format; cleartext traffic flags |
| **medium** | Cleartext `http://` URLs (non-schema); WebView JS enabled / file access; allowBackup; content-provider access patterns |
| **low** | Assignment-shaped `password=...` literals only |
| **info** | Bare `password`/`secret`/`api_key` tokens; SharedPreferences; Log usage; APKiD tags |

Vague password keyword noise is **info** unless assignment-shaped (**low**).

## Plugins

Off by default. Merge into the same finding schema (`source`: `plugin` / `quark` / `nuclei`).

```bash
python cli.py app.apk --sast --apkid --semgrep --mobsfscan --quark --nuclei -o json
```

If a tool is missing → that backend is skipped (scan still succeeds).

- **Semgrep:** default ruleset is the small vendored Android/MASVS starter under `rules/semgrep/`. Override with `APK_SCANNER_SEMGREP_CONFIG` for full [OWASP MASTG rules](https://github.com/OWASP/mastg/tree/master/rules) after you clone them locally.
- **Quark:** behavior score / family hints only — **not** an antivirus verdict.
- **nuclei:** requires both `jadx` and `nuclei`; decompiles to `$TEMP`, runs `file/android` templates, deletes the tree.

## SCA / CVE

```bash
python cli.py libs/ --types jar --sca -o json
# HTML/manager board also surfaces summary.sca
python cli.py libs/ --types jar --sca -o html --out-file reports/sca.html
```

- Extracts component+version only (JAR filename, Maven `pom.properties`, Gradle `group:name:version`, known lib patterns).
- Queries [OSV](https://api.osv.dev/v1/query); caches responses; polite delay between calls.
- Emits `sca-osv-vuln` with real `cve: ["CVE-…"]` **only** when OSV returns aliases/ids. **Never invents CVE IDs.**
- Report `summary.sca`: `inventory` (component/version/ecosystem), `vulnerabilities` (component, version, severity, CVE ids, OSV id). HTML and weekly `manager_report.html` show an **SCA / OSV board**.
- Offline / network failure → skip (log). `--sca-offline` forces no network.
- Pattern findings keep `cve: null` unless they are SCA findings.

NVD is not called directly (API key / rate limits); CVE IDs come from OSV aliases when present.

## DAST

```bash
python cli.py app.apk --sast --dynamic -o text
```

See [dast.md](dast.md). Android: adb install + Frida hooks (SSL trust-all, sensitive log, cleartext URL) when Python `frida` works. Without adb/device → skip. iOS → stub. No browser/cloud emulator in this repo.

## Report formats

| Format | Contents |
|--------|----------|
| `json` / `text` | Full metadata + findings + enrichment |
| `csv` | Findings table: scores, CVSS-estimate, remediation, CWE/NIST/OWASP/MASWE/Mobile2024/CAPEC/CISA/NSA |
| `html` | Executive KPIs (incl. **Critical**) + SCA/OSV board when present + per-finding taxonomy / How to fix / How to revalidate |
| `sarif` | SARIF 2.1: `ruleId`, `level`, `locations`, rule `help` (remediation+revalidate), `taxa`, properties — CI uploads to GitHub Code Scanning when permissions allow |

Enrichment fields: `severity_score`, `classification` (incl. MASWE + OWASP Mobile Top 10 2024), `cvss_estimate` (rule-based, **not** NVD CVSS), `remediation`, `revalidate`, `maswe_id`, `owasp_mobile`, `cve`.

### Where Critical appears

- HTML summary grid: **Critical** count
- Text: `Severity: critical=N, high=N, ...`
- JSON `summary.by_severity.critical`
- SARIF: critical/high → `level: error`
- Finding badges / `[critical]` lines per hit

### How to open HTML

1. Double-click the `.html` file, or  
2. `file:///` URL (encode spaces as `%20`).  
Self-contained (inline CSS). Prefer `docs/results/capability_run_*/manager_report.html` for executive view.

## CI

- **Push/PR:** `.github/workflows/ci.yml` — `pytest` + synthetic SAST → SARIF → **GitHub Code Scanning** (`github/codeql-action/upload-sarif`, category `apk-scanner-ci`; `continue-on-error` if Security tab / permissions unavailable)
- **Optional manual:** `.github/workflows/sandbox-sast.yml` — temp sandbox → `--sast` → SARIF artifact + Code Scanning upload (`apk-scanner-sandbox`) → **purge**
- **Weekly (cron + manual):** `.github/workflows/weekly-sandbox-scan.yml` — Monday 06:00 UTC + `workflow_dispatch`
  - Allowlist only: `tests/fixtures/sources.json` (not an internet crawl)
  - **`primary`** entries tried first; **`fallback`** fills `max_artifacts` (≤ 15) when primary is exhausted (already scanned at same version) or materialize fails
  - **History dedupe:** `tests/fixtures/scan_history.json` records `id`, `version` / etag / sha256, `last_scan_date`, `last_report_dir`. Same id+version skipped unless `version`/URL changes, remote ETag/SHA differs, or `force: true`. Optional `min_interval_days`.
  - **SDK:** https zip URL, or `{ "type": "sdk", "generate": true, "files": [...] }` → tiny tree in TEMP (no binary commit)
  - **.so:** public https URL, or `extract_from_apk: { "url", "member" }` (download APK to temp, extract `.so`, delete APK)
  - Logic shared via `scanner/sources_allowlist.py` (weekly + capability scripts)
  - Downloads into `$RUNNER_TEMP`, runs `python scripts/weekly_sandbox_scan.py` (`--sast` + `--sca`)
  - Writes **`docs/results/weekly_YYYYMMDD/`** (`manager_report.html` with SCA board, JSON/text/SARIF/summary)
  - Uploads SARIF to Code Scanning (`apk-scanner-weekly`) when `security-events: write` is allowed
  - Commits **reports + `scan_history.json`** with `GITHUB_TOKEN` (needs Actions write permission); purges binaries
  - Soft-fail: findings do not fail the job. Critical/High in reports are **pattern-scan leads**, not confirmed vulns
- **Landscape metrics (monthly + manual):** `.github/workflows/landscape-refresh.yml` — `scripts/refresh_landscape.py` updates the auto table in [LANDSCAPE.md](LANDSCAPE.md) from `docs/landscape_sources.json` (stars/release/push only; no feature scraping; no APKs)

Code Scanning notes: public repos generally work with `security-events: write`. Private/fork uploads may need GitHub Advanced Security or fail softly (`continue-on-error: true`). Findings appear under the repo **Security** tab when the upload succeeds.

### GitHub-only maintenance (~6 months without IDE)

Keep improving scanner/signatures from GitHub alone (no local IDE required):

1. **Edit rules/signatures in the web UI or PRs**  
   - Patterns: `scanner/sast/patterns.py`, `scanner/sast/__init__.py`  
   - Taxonomy / MASWE: `scanner/taxonomy.py`, `scanner/taxonomy_maswe.py`  
   - Semgrep starter: `rules/semgrep/`
2. **PR validation** — `ci.yml` runs pytest on every PR; merge when green.
3. **Tweak allowlist** — edit `tests/fixtures/sources.json` (`primary` / `fallback`, https-only; keep `max_artifacts` ≤ 15). History: `tests/fixtures/scan_history.json`. Enforced by `tests/test_sources_allowlist.py`.
4. **Cron / manual weekly scan** — schedule is `0 6 * * 1` in `weekly-sandbox-scan.yml`. Re-run: **Actions → Weekly sandbox scan → Run workflow**.
5. **Read results** — `docs/results/weekly_YYYYMMDD/manager_report.html` (or SARIF / Security tab). If the bot cannot push: **Settings → Actions → General → Workflow permissions → Read and write**.
6. **Landscape metrics** — automatic monthly via `landscape-refresh.yml`, or **Actions → Landscape refresh → Run workflow**, or locally: `python scripts/refresh_landscape.py`. Human narrative edits still manual (see [LANDSCAPE.md](LANDSCAPE.md)).

Honest limits: allowlist only (no random crawl); no in-browser emulator; no cloud device farm; no binaries in git.

Local:

```bash
python -m pytest tests/ -v
python cli.py <sandbox> --sast -o sarif --out-file scan.sarif.json
# Dry-run weekly job locally (downloads to TEMP, writes docs/results/weekly_*, updates history, purges):
python scripts/weekly_sandbox_scan.py
```

## Regenerating showcases

Do **not** commit APKs/IPAs.

```bash
# 1) TEMP sandbox, download 5× apk/ipa/jar/so/sdk yourself
# 2) Scan
python cli.py %TEMP%\apk-scanner-capability-... --sast -o json --out-file report.json
python cli.py %TEMP%\apk-scanner-capability-... --sast -o html --out-file report.html
# --dynamic only if adb+device; plugins only if tools installed
# 3) Sanitize paths, copy to docs/results/capability_run_YYYYMMDD/
# 4) Purge sandbox
# 5) Optional re-enrich without APKs:
python -c "import json; from pathlib import Path; from scanner.report import reenrich_report, to_html; p=Path('docs/results/capability_run_.../report.json'); r=json.loads(p.read_text(encoding='utf-8')); reenrich_report(r); p.write_text(json.dumps(r,indent=2),encoding='utf-8'); Path(str(p).replace('report.json','report.html')).write_text(to_html(r),encoding='utf-8')"
```

## Honesty limits

**Useful today:** inventory, constrained SAST leads (incl. Critical/High signal), taxonomy packaging, scored reports with fix/revalidate, SARIF/CI scaffolding, optional plugins/SCA when tools/network allow.

**Not this tool:** confirmed vuln triage, invented CVEs, call-graph proof, production DAST, in-browser APK/IPA emulation, bundled training APKs in git.
