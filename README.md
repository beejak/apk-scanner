# APK / IPA / JAR / .so / SDK Scanner

Repo: [github.com/beejak/apk-scanner](https://github.com/beejak/apk-scanner)

CLI for **discovery**, **metadata extraction**, optional **pattern-scan SAST** (substring/regex lint), **finding enrichment** (taxonomy, severity scores, CVSS-estimate, remediation/revalidate), and an optional **DAST scaffold** (one Android Frida check; iOS stub). Outputs JSON, text, CSV, HTML, and SARIF with optional timestamped filenames.

**Honest capability:** solid inventory + metadata + constrained pattern-scan SAST — **not** a full SAST/DAST product. Useful today for binary inventory, cleartext/exported-component/WebView/crypto-string leads, high-confidence secret-format hits, scored reports with fix/revalidate text, and CI SARIF scaffolding. **Not** useful today for confirmed vuln triage, real CVE assignment, call-graph/API-misuse proof, or production DAST.

## Requirements

- **Python 3.10+** (required for full APK metadata via `apk-info`; older Python may run with ZIP-only APK crumbs)
- **Pinned deps:** `apk-info==1.0.10`, `pyelftools==0.32`, `androguard>=4.0` (see `requirements.txt`)

Without apk-info, APK scan falls back to ZIP-only metadata. Without pyelftools, `.so` metadata uses a **wired stdlib fallback** (`path`, `size_bytes`, install note). DEX SAST defaults to a built-in ZIP string scan. Optional `androguard` is **off by default** (set `APK_SCANNER_ANDROGUARD=1`); it only adds string/class name tables — same constrained patterns, much slower (`AnalyzeAPK`).

## Public repo / fixtures

`*.apk`, `*.ipa`, and similar binaries are **gitignored**. After a public clone you must **download** training APKs yourself into `tests/fixtures/` (see [`tests/fixtures/README.md`](tests/fixtures/README.md)). Small text/SDK fixtures and a tiny JAR remain in git.

**Capabilities showcase (no APKs):** [`docs/results/`](docs/results/) and [`docs/capabilities.html`](docs/capabilities.html).

| Showcase | What it is |
|----------|------------|
| [`docs/results/capability_run_20261014/manager_report.html`](docs/results/capability_run_20261014/manager_report.html) | Manager POV: 5× APK/IPA/JAR/.so/SDK (25 artifacts, 325 findings); self-contained HTML |
| [`docs/results/sandbox_20261013/report.html`](docs/results/sandbox_20261013/report.html) | Technical enriched HTML (APK-only training set) with scores, CVSS-estimate, fix/revalidate |
| [`docs/results/index.html`](docs/results/index.html) | Results index |

## Usage (CLI)

```bash
# Discovery + metadata (no SAST/DAST unless flagged)
python cli.py .

# Pattern-scan SAST — findings + enrichment in report
python cli.py . --sast

# JSON (richest: metadata + findings + scores/taxonomy/remediation)
python cli.py . --sast -o json --out-file "reports/scan_{timestamp}.json"

# CSV (findings table + score/CVSS/remediation/taxonomy; no full metadata blobs)
python cli.py . --sast -o csv --out-file "reports/scan_{timestamp}.csv"

# HTML (executive summary + per-finding taxonomy / fix / revalidate) or SARIF
python cli.py . --sast -o html --out-file reports/scan.html
python cli.py . --sast -o sarif --out-file reports/scan.sarif.json

# DAST scaffold on APK — needs adb + device; Frida optional (see docs/dast.md)
python cli.py path/to/app.apk --sast --dynamic -o text

# Only certain types / parallel discovery
python cli.py . --types apk ipa jar
python cli.py . -j 4
```

### How to open HTML reports

CLI `-o html` and showcase HTML are **self-contained** (inline CSS; no server required):

1. Double-click the `.html` file in Explorer, or
2. Paste a `file:///` path into the browser (encode spaces as `%20`), e.g.  
   `file:///C:/Users/…/apk%20scanner/docs/results/capability_run_20261014/manager_report.html`

Prefer **`manager_report.html`** for an executive summary of a capability run, and CLI / sandbox **`report.html`** for per-finding technical detail (scores, taxonomy, how to fix / revalidate). Pages that `fetch()` JSON can break under `file://` — the shipped manager report and enriched `report.html` do not need that.

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

## Report fields (honest)

Report schema: `{ scan_timestamp, metadata, findings, summary }`.

**Per finding** (after enrichment in `scanner/taxonomy.py`):

| Field | Meaning |
|-------|---------|
| `rule_id`, `severity`, `message`, `location`, `source`, optional `masvs_id` | Core finding |
| `classification` | Lookup: CWE / NIST / OWASP / CAPEC / CISA / NSA — packaging only; does not deepen detection |
| `severity_score` | 0.0–10.0 = severity band × rule weight (heuristic, not exploitability proof) |
| `cvss_estimate` | `{ score, vector, note }` — **rule-based estimate, not NVD CVSS for a CVE** |
| `remediation` | Short “how to fix” guidance for the rule family |
| `revalidate` | How to re-scan and expect the finding to clear |
| `cve` | Always `null` today — real CVE IDs need component/version SCA (not implemented; we do not invent CVE-YYYY-NNNN) |

**Summary rollups:** `artifacts`, `findings`, `by_severity`, `max_severity_score`, `avg_severity_score`.

**Formats:** `-o json` / `-o text` (richest), `-o csv` (findings + score/CVSS/remediation/taxonomy columns), `-o html` (executive summary + per-finding fix/revalidate), `-o sarif` (CI + properties). Use `--out-file "reports/scan_{timestamp}.json"` (quote in PowerShell).

## Project layout

- **`cli.py`** — main entrypoint (discovery → metadata → optional SAST/DAST → enrich → report)
- **`scanner/`** — `discovery`, `metadata/`, `sast/`, `dast/`, `taxonomy`, `report`, `run`
- **`docs/PRD.md`** — vision + implemented vs planned
- **`docs/dast.md`** — DAST scaffold behavior
- **`docs/results/`** — sanitized showcase reports (no binaries)
- **`tests/fixtures/`** — download APKs locally; see `tests/fixtures/README.md`

## SAST (pattern scan)

With `--sast`, the scanner runs **constrained regex + metadata heuristics** and adds findings. This is still pattern lint, not confirmed triage.

- **APK:** Metadata: debuggable, allowBackup, `usesCleartextTraffic` when available, **exported components without permission** (apk-info). DEX/ZIP strings: weak `Cipher.getInstance` / MessageDigest, WebView JS bridge / file access, trust-all heuristics, cleartext `http://` (skips Android schema URLs), network-security-config cleartext flags, high-confidence secret formats (AWS `AKIA…`, Google `AIza…`, PEM private keys). Vague `password` / `secret` / `api_key` tokens are **low/info** only.
- **.so:** Binary string patterns: credentials, weak crypto names (e.g. MD5, DES), JNI. Metadata falls back without pyelftools.
- **JAR:** Same constrained patterns on `.class` / config-like entries.
- **IPA:** Info.plist ATS (`NSAllowsArbitraryLoads`, exception insecure HTTP) and binary string scan.
- **SDK:** Sensitive filenames and credential-like patterns in config-ish files.

Optional `androguard` improves string extraction, **not** analysis depth (no xrefs / API-misuse engine yet).

**Local UI (planned, not built):** a static HTML/JS drop-zone cannot run this Python scanner in-browser alone; it would need a companion local server or Tauri shell that invokes `cli.py`.

## DAST (scaffold)

Use `--dynamic` for a **scaffold**, not production DAST. Android: `adb` install + optional one Frida check (`SSLContext.init` with null TrustManager). Python `frida` can emit that finding; Frida **CLI-only** runs the script but **captures no messages**. iOS: stub (returns no findings). DAST findings get the same enrichment fields as SAST. See **`docs/dast.md`**.

## Tests

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

Requires `pytest` (in requirements.txt). Unit tests cover discovery, taxonomy (scores/CVSS/remediation), reporting, and **synthetic SAST fixtures** (no APK binaries in git). APK-dependent integration tests skip if fixtures are missing. DAST still has no dedicated unit suite.

## Roadmap

Shipped: constrained SAST detectors, `.so` fallback, synthetic tests, high-confidence secret formats, **severity_score**, **cvss_estimate** (rule-based), **remediation/revalidate**, enriched HTML, and a full-type capability showcase. **CVE/SCA** (real CVE-YYYY-NNNN) remains backlog. Next: MASWE depth, optional APKiD/CI sandbox, then Frida/DAST. Optional Semgrep/mobsfscan later. Static local drop-zone UI remains planned. See `docs/PRD.md`.
