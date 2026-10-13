# Sandbox / capability scan results

Sanitized reports from disposable temp sandboxes. **APK / IPA / similar binaries are never stored in this repository**. Pattern-scan **leads** only — not confirmed triage.

## How to open HTML

1. Double-click the `.html` file, or paste a `file:///` URL (encode spaces as `%20`).
2. Self-contained pages work under `file://`:
   - `capability_run_*/manager_report.html` — manager POV with **Critical/High**, scores, fix/revalidate
   - `weekly_*/manager_report.html` — same for GitHub Actions weekly allowlist scans
   - `capability_run_*/report.html` — CLI-style enriched HTML

## Latest capability / weekly runs

| Path | Contents |
|------|----------|
| [`capability_run_20261014/`](capability_run_20261014/) | Fresh 5× apk/ipa/jar/so/sdk retest after high-impact rules + MASWE/Mobile2024 + SARIF/CI/plugins/SCA. **Critical** in KPIs + finding badges. Sandbox purged. |
| [`weekly_20261013/`](weekly_20261013/) | First Actions weekly allowlist run (reports only). |
| `weekly_YYYYMMDD/` | Cron / `workflow_dispatch` (`.github/workflows/weekly-sandbox-scan.yml`): `primary`+`fallback` allowlist, history dedupe via [`tests/fixtures/scan_history.json`](../../tests/fixtures/scan_history.json). Reports + history JSON committed; binaries never. |
| [`sandbox_20261013/`](sandbox_20261013/) | Earlier APK-only enriched showcase |

### capability_run_20261014 facts

- 25 artifacts (5 of each type); Critical/High bands populated by shipped rules (JS bridge, secrets, trust-all, exec, exported provider/intent, etc.).
- DAST skipped unless adb present; plugins skipped unless tools on PATH; `--sca` attempted (real OSV only).
- Regen: `python scripts/capability_retest.py` (downloads into TEMP, copies sanitized reports here, purges sandbox).
- How-to: [`docs/USAGE.md`](../USAGE.md).

### What enrichment means

`severity_score`, `cvss_estimate` (not NVD CVE CVSS), `remediation`, `revalidate`, MASWE / OWASP Mobile Top 10 2024 in taxonomy. `cve` only when OSV SCA returned real IDs; otherwise null.

## Process (same as before)

1. TEMP sandbox  
2. Download 5× each type (no commit of binaries)  
3. `python cli.py <sandbox> --sast` (+ `--dynamic` / plugins / `--sca` if available)  
4. Copy sanitized reports → `docs/results/capability_run_<date>/`  
5. **Purge** sandbox  
