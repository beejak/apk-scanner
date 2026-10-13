# APK / IPA / JAR / .so / SDK Scanner

Repo: [github.com/beejak/apk-scanner](https://github.com/beejak/apk-scanner)

CLI for **discovery**, **metadata**, optional **pattern-scan SAST**, optional **plugins** (APKiD / Semgrep / mobsfscan), optional **real OSV SCA**, finding enrichment (MASWE + OWASP Mobile Top 10 2024, scores, remediation), and an optional **DAST scaffold** (Android Frida hooks when adb/device present; iOS stub). Outputs JSON, text, CSV, HTML, and SARIF.

**Deep guide:** [`docs/USAGE.md`](docs/USAGE.md) — install, per-type scanning, flags, SCA, CI, **weekly allowlist scan**, GitHub-only maintenance, honesty limits.

**Honest capability:** solid inventory + constrained SAST with Critical/High signal rules — **not** a full SAST/DAST product. Useful for binary inventory, high-impact pattern leads, scored reports with fix/revalidate, CI SARIF. **Not** useful for confirmed triage, invented CVEs, or production DAST.

## Requirements

- **Python 3.10+** (full APK metadata via `apk-info`)
- **Pinned:** `apk-info==1.0.10`, `pyelftools==0.32`, `androguard>=4.0` (`requirements.txt`)

Optional (skip if missing): `apkid`, `semgrep`, `mobsfscan`, `adb` + device, Python `frida`. DEX SAST defaults to ZIP strings; `APK_SCANNER_ANDROGUARD=1` for optional androguard tables.

## Public repo / fixtures

`*.apk` / `*.ipa` are **gitignored**. Download training samples yourself (`tests/fixtures/README.md`). Showcase reports (no binaries): [`docs/results/`](docs/results/).

## Quick start

```bash
pip install -r requirements.txt
python -m pytest tests/ -q

python cli.py . --sast -o text
python cli.py . --sast -o html --out-file reports/scan.html
python cli.py . --sast -o sarif --out-file reports/scan.sarif.json

# Optional backends (skip if tools missing)
python cli.py app.apk --sast --apkid --semgrep --mobsfscan -o json
python cli.py libs/ --types jar --sca -o json

# DAST only with adb + device; Frida optional
python cli.py app.apk --sast --dynamic -o text
```

CLI flags: `--sast`, `--dynamic`, `--apkid`, `--semgrep`, `--mobsfscan`, `--sca`, `--sca-offline`, `-o`, `--out-file`, `--types`, `-j`. Full help: `python cli.py -h` or [`docs/USAGE.md`](docs/USAGE.md).

### Open HTML reports

Self-contained: double-click or `file:///` (encode spaces). Prefer `docs/results/capability_run_*/manager_report.html` for Critical/High + fix/revalidate.

## What SAST flags (summary)

| Severity | Examples |
|----------|----------|
| **critical** | JS bridge (`addJavascriptInterface`), trust-all SSL, Runtime.exec/ProcessBuilder, AWS/PEM secrets, exported unprotected ContentProvider |
| **high** | Exported activity intent risk, weak Cipher, SQL concat, unsafe deserialization, path/file URI, cleartext traffic flags |
| **medium / low / info** | Cleartext URLs, WebView settings, backup/debug, demoted password noise (info unless assignment-shaped) |

Taxonomy per finding: CWE, NIST, OWASP, **MASWE**, **OWASP Mobile Top 10 2024**, CAPEC, CISA, NSA + `severity_score`, `cvss_estimate` (rule-based), `remediation`, `revalidate`. CVE only via `--sca` + OSV when name+version extracted.

## CI

- **Push/PR:** pytest (`.github/workflows/ci.yml`, Python 3.12)
- **Weekly (Mon 06:00 UTC) + manual:** allowlist-only download → SAST → `docs/results/weekly_YYYYMMDD/` → purge binaries → commit reports (`.github/workflows/weekly-sandbox-scan.yml`). Allowlist: [`tests/fixtures/sources.json`](tests/fixtures/sources.json). Soft-fail on findings; never commits APK/IPA.
- **Optional manual synthetic SARIF:** `.github/workflows/sandbox-sast.yml`

GitHub-only maintenance (edit rules/allowlist via web UI/PRs, rely on Actions): see **GitHub-only maintenance** in [`docs/USAGE.md`](docs/USAGE.md). No in-browser emulator.
- **Weekly allowlist scan** (cron Mon 06:00 UTC + manual): `.github/workflows/weekly-sandbox-scan.yml` → reports in `docs/results/weekly_*/` (see [`docs/USAGE.md`](docs/USAGE.md#ci)); sources `tests/fixtures/sources.json`

## Project layout

- `cli.py` — entrypoint
- `scanner/` — discovery, metadata, sast, plugins, sca, dast, taxonomy, report, run
- `docs/USAGE.md` — full how-to
- `docs/PRD.md`, `docs/dast.md`, `docs/results/`

## Tests

```bash
python -m pytest tests/ -v
```

## Roadmap note

Phase 3 enrichment + high-impact rules + MASWE/Mobile2024 + SARIF/CI + optional plugins + real OSV SCA + expanded Android DAST hooks are shipped. See `docs/PRD.md` and `.cursor/plans/full_mobile_scanner_replan.md`.
