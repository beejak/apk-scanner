# Sandbox / capability scan results

Sanitized reports from disposable temp sandboxes. **APK / IPA / similar binaries are never stored in this repository** (see root `.gitignore`). Pattern-scan **leads** only — not confirmed triage.

## How to open HTML

1. **Double-click** the `.html` file in Explorer, or open with your browser.
2. Or paste a `file:///` URL (encode spaces as `%20`), e.g.  
   `file:///C:/Users/…/apk%20scanner/docs/results/capability_run_20261014/manager_report.html`
3. **Self-contained** pages (inline CSS/data) work under `file://` with no server:
   - `capability_run_*/manager_report.html` — manager POV **with** per-finding scores / fix / revalidate
   - `capability_run_*/report.html` and `sandbox_*/report.html` — enriched CLI HTML (same fields)
4. Older pages that `fetch()` a sibling JSON may fail under `file://` (browser CORS). Prefer the manager report or enriched `report.html`, or serve the folder with a tiny static server.

Also linked from [`index.html`](index.html) and [`../capabilities.html`](../capabilities.html).

## Manager vs technical HTML

| Kind | File | Audience | Contents |
|------|------|----------|----------|
| **Manager (enriched)** | `capability_run_20261014/manager_report.html` | Exec / program | KPIs, capability checklist, themes, top rules, **plus** per-finding severity / `severity_score` / taxonomy / `cvss_estimate` / **How to fix** / **How to revalidate** |
| **Technical (enriched)** | `sandbox_20261013/report.html` | Engineers | CLI-style report: severity bands, `severity_score`, taxonomy, **CVSS-estimate** (rule-based, not NVD CVE CVSS), **How to fix** / **How to revalidate** |
| **Technical (capability, enriched)** | `capability_run_20261014/report.html` | Engineers | Same enriched CLI HTML for the 5×-type run (re-enriched from `report.json` without re-scanning) |

New scans with current `cli.py --sast -o html` always emit the enriched technical format.

## Layout

| Path | Contents |
|------|----------|
| [`capability_run_20261014/`](capability_run_20261014/) | Full-type run (5 APK + 5 IPA + 5 JAR + 5 .so + 5 SDK). **`manager_report.html`** + `report.*` **re-enriched** (`severity_score`, `cvss_estimate`, `remediation`, `revalidate`, `cve: null`) from existing JSON — no APK re-download. Sandbox purged after original copy. |
| [`sandbox_20261013/`](sandbox_20261013/) | Earlier APK-only training set (14 apps). **`report.*` regenerated with enrichment** (`severity_score`, `cvss_estimate`, `remediation`, `revalidate`, `cve: null`). |
| [`index.html`](index.html) | Results index → latest manager report |
| [`../capabilities.html`](../capabilities.html) | Shortcut entry |

### Capability run facts (2026-10-14)

- 25 artifacts discovered; **325** pattern-scan findings; pytest **41 passed** at run time (suite has grown since — see CI/local `pytest`).
- DAST **not** run (`adb` unavailable); documented as skipped, not failed.
- Binaries downloaded into temp sandbox, reports sanitized (`<sandbox>` paths), sandbox **purged**.

### What enrichment means

When present on a finding: `severity_score` (0–10 band × weight), `cvss_estimate` `{score, vector, note}` (**not** NVD CVSS for a CVE), `remediation`, `revalidate`, `cve: null` (SCA backlog — no invented CVE IDs). Taxonomy (CWE/NIST/OWASP/CAPEC/CISA/NSA) is a lookup table after a finding exists.

## How these were produced

1. Create `%TEMP%\apk-scanner-capability-<timestamp>\` (or similar).
2. Download public training samples (APK / IPA / JAR / extract `.so` / SDK-like dirs).
3. Run: `python cli.py <sandbox> --sast -o json` (also html/csv/text). Use `--dynamic` only if `adb` + a device exist.
4. Copy **sanitized** reports here. Keep manager HTML + `summary.json` for capability runs.
5. **Purge** the entire sandbox (binaries + local copies).

Regenerate anytime; do not commit APKs/IPAs.

## Planned local drop-zone UI

A static HTML/JS drag-and-drop page **cannot** run this Python scanner in-browser. A future UI needs a companion local server or Tauri wrapper that invokes `cli.py`. That UI is **not** built here — only documented.
