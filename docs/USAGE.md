# How to use apk-scanner

In-depth guide matching **shipped** code only. Entry overview: [README.md](../README.md). Product status: [PRD.md](PRD.md). DAST details: [dast.md](dast.md).

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
| `semgrep` | `--semgrep` | On PATH; config via `APK_SCANNER_SEMGREP_CONFIG` (default `p/security-audit`) |
| `mobsfscan` | `--mobsfscan` | On PATH |
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
| `--apkid` / `--semgrep` / `--mobsfscan` | Optional plugin backends |
| `--sca` | Real OSV lookups when name+version extracted |
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

Off by default. Merge into the same finding schema (`source: plugin`).

```bash
python cli.py app.apk --sast --apkid --semgrep --mobsfscan -o json
```

If `apkid` / `semgrep` / `mobsfscan` missing → skip that backend.

## SCA / CVE

```bash
python cli.py libs/ --types jar --sca -o json
```

- Extracts component+version only (JAR filename, Maven `pom.properties`, Gradle `group:name:version`, known lib patterns).
- Queries [OSV](https://api.osv.dev/v1/query); caches responses; polite delay between calls.
- Emits `sca-osv-vuln` with real `cve: ["CVE-…"]` **only** when OSV returns aliases/ids. **Never invents CVE IDs.**
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
| `html` | Executive KPIs (incl. **Critical**) + per-finding taxonomy / How to fix / How to revalidate |
| `sarif` | SARIF 2.1: `ruleId`, `level`, `locations`, rule `help` (remediation+revalidate), `taxa`, properties |

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

- **Push/PR:** `.github/workflows/ci.yml` — `pytest`
- **Optional manual:** `.github/workflows/sandbox-sast.yml` — temp sandbox → `--sast` → SARIF artifact → **purge** (no APKs committed)
- **Weekly (cron + manual):** `.github/workflows/weekly-sandbox-scan.yml` — Monday 06:00 UTC + `workflow_dispatch`
  - Allowlist only: `tests/fixtures/sources.json` (HTTPS training/Maven URLs; not an internet crawl)
  - Downloads into `$RUNNER_TEMP`, runs `python scripts/weekly_sandbox_scan.py` (`--sast`), writes `docs/results/weekly_YYYYMMDD/`
  - Purges binaries; commits **reports only** with `GITHUB_TOKEN` (needs Actions write permission)
  - Soft-fail: findings do not fail the job; keep allowlist ≤ ~15 for runner disk/time

### GitHub-only maintenance (~6 months without IDE)

Keep improving scanner/signatures from GitHub alone (no local IDE required):

1. **Edit rules/signatures in the web UI or PRs**  
   - Patterns: `scanner/sast/patterns.py`, `scanner/sast/__init__.py`  
   - Taxonomy / MASWE: `scanner/taxonomy.py`, `scanner/taxonomy_maswe.py`
2. **PR validation** — `ci.yml` runs pytest on every PR; merge when green.
3. **Tweak allowlist** — edit `tests/fixtures/sources.json` (https training/Maven URLs only; keep `max_artifacts` ≤ 15). Enforced by `tests/test_sources_allowlist.py`.
4. **Cron / manual weekly scan** — schedule is `0 6 * * 1` in `weekly-sandbox-scan.yml`. Re-run: **Actions → Weekly sandbox scan → Run workflow**.
5. **Read results** — `docs/results/weekly_YYYYMMDD/manager_report.html` (or SARIF artifact). Enable **Actions → Workflow permissions → Read and write** so the job can commit reports.

Honest limits: allowlist only (no random crawl); no in-browser emulator; no cloud device farm; no binaries in git.

Local:

```bash
python -m pytest tests/ -v
python cli.py <sandbox> --sast -o sarif --out-file scan.sarif.json
# Dry-run weekly job locally (downloads to TEMP, writes docs/results/weekly_*, purges):
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
