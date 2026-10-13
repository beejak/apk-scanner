# Product Requirements Document: Full-Fledged Mobile & Binary Security Scanner

## 0. Current capability (honest)

**Today this is a solid discovery + metadata + keyword/pattern-lint CLI**, not a full SAST/DAST product. Docs and taxonomy packaging historically outran the analysis engine; this PRD marks **implemented** vs **planned** explicitly.

| Layer | Reality today |
|-------|----------------|
| Discovery | **Implemented:** apk/ipa/jar/so/sdk via `scanner/discovery.py` |
| Metadata | **Implemented with gaps:** APK strong only with `apk-info` (Python 3.10+; ZIP crumbs without it); IPA/JAR OK (stdlib); `.so` via pyelftools with **wired stdlib fallback**; SDK is a file counter |
| SAST | **Constrained pattern scan with Critical/High bands:** WebView JS bridge, Runtime.exec, trust-all, SQL concat, unsafe deserialization, path/file URI, exported intent/provider risks, weak crypto, secret formats. Vague password → info (assignment-shaped low). Optional plugins: `--apkid` / `--semgrep` / `--mobsfscan` (skip if missing) |
| SCA | **[Partial]** `--sca` real OSV lookups when component+version extracted; cache + rate delay; never invents CVE IDs; offline skip |
| DAST | **Scaffold:** Android Frida hooks for SSL trust-all, sensitive log, cleartext URL when adb+Python frida; CLI Frida captures nothing; iOS stub |
| Reports | JSON/text/CSV/HTML/SARIF 2.1 (ruleId/level/locations/help/taxa); taxonomy includes **MASWE** + **OWASP Mobile Top 10 2024**; scores, remediation/revalidate; CVE only from SCA. How-to: `docs/USAGE.md`. CI: pytest on push/PR; optional sandbox→SARIF workflow |
| Tests | Synthetic SAST + taxonomy + plugins/SCA (mocked) + DAST skip-path tests; integration without APKs in git |

**Useful today for:** inventory, high-impact pattern leads (Critical/High), taxonomy packaging, scored fix/revalidate reports, CI SARIF, optional plugins/SCA.  
**Not useful today for:** confirmed triage, invented CVEs, call-graph proof, production DAST, in-browser emulation.

The sections below describe the **product vision** and requirements. Status tags: **[Implemented]**, **[Partial]**, **[Planned]**.

---

## 1. Product overview

### 1.1 Vision

A **full-blown code and runtime vulnerability scanner** for Android (APK/AAB), iOS (IPA), Java (JAR), native libraries (.so, .dylib), and SDK-style directories. The product performs **discovery**, **metadata extraction**, **static application security testing (SAST)**, and **dynamic application security testing (DAST)** in one CLI-driven (and optionally UI-driven) toolchain.

**Current delivery vs vision:** discovery + metadata + pattern-scan SAST + DAST scaffold are in the CLI; deep SAST, production DAST, and UI remain **planned**.

### 1.2 Goals

- **Single toolchain:** One scanner that handles APK, IPA, JAR, .so, and SDK from a path or drag-and-drop input. **[Partial]** — CLI path scan works; drag-and-drop UI not built.
- **Full vulnerability coverage:** Find code-level issues (SAST) and runtime issues (DAST), not only metadata. **[Partial]** — pattern lint + one DAST check; not confirmed triage.
- **Standards-aligned:** Map findings to OWASP MASVS/MASTG/MASWE where applicable. **[Partial]** — taxonomy lookup after findings; MASWE/MASTG IDs not fully wired.
- **Multi-agent friendly:** Structure and documentation support splitting work across specialized agents (discovery, SAST, DAST, reporting). **[Implemented]** for repo layout/skills.

### 1.3 Out of scope (for v1)

- Commercial app-store submission gates or store-specific APIs.
- Real-device farm orchestration (focus: emulator/simulator on single machine).
- Full binary decompilation for every format (use decompilation where needed for SAST; not a general-purpose decompiler UI).

---

## 2. User personas and use cases

| Persona | Use case |
|---------|----------|
| **App developer** | Scan a build folder or CI artifact; get a report of metadata + pattern findings before release. |
| **Security reviewer** | Point at a directory of APKs/IPAs; run pattern SAST + optional DAST scaffold; export report (JSON/HTML/SARIF). Treat findings as leads, not confirmed vulns. |
| **DevSecOps** | Integrate scanner in pipeline (CLI); consume JSON/SARIF for scaffolding; do not treat exit code as severity gate yet (always 0 on successful scan). |

---

## 3. Functional requirements

### 3.1 Discovery and metadata (foundation)

- **FR-D1** **[Implemented]** Discover by path: files (APK, IPA, JAR, .so) and directories (SDK heuristics). (`.dylib` not a first-class type yet.)
- **FR-D2** Extract and report metadata per type:
  - **APK/AAB:** **[Partial]** APK via apk-info when installed; AAB not fully supported. ZIP-only crumbs without apk-info.
  - **IPA:** **[Implemented]** bundle ID, version, display name, min OS, Info.plist-derived metadata.
  - **JAR:** **[Implemented]** manifest (Main-Class, version, Created-By, etc.).
  - **SDK:** **[Implemented]** directory path, size, entry count, heuristic type.
  - **.so:** **[Implemented with fallback]** path, size, ELF fields via pyelftools; stdlib fallback returns `size_bytes` + install note without it.
- **FR-D3** **[Implemented]** Support recursive and non-recursive scan; filter by type (e.g. `--types apk ipa so`).
- **FR-D4** **[Implemented]** Mid-level logging (INFO); optional verbose (DEBUG) and quiet mode.

### 3.2 Static analysis (SAST)

- **FR-S1** **Android (APK):** **[Partial — constrained pattern scan]** DEX/ZIP + metadata; Critical/High rules (JS bridge, exec, trust-all, exported intent/provider, SQL/deser/path). **Not** full decompile rule engine.
- **FR-S2** **JAR:** **[Partial — constrained pattern scan]** ZIP/string scan; **not** bytecode AST.
- **FR-S3** **IPA / native:** **[Partial]** Plist ATS + binary strings; **not** full Mach-O misuse analysis.
- **FR-S4** **.so:** **[Partial]** String patterns for secrets/weak crypto/JNI; deeper symbol misuse **planned**.
- **FR-S5** **Rule engine:** **[Partial]** Built-in patterns + optional `--apkid`/`--semgrep`/`--mobsfscan` subprocess backends (skip if missing). Custom `--rules` path **not** implemented.
- **FR-S6** Taxonomy: **[Implemented lookup]** CWE, NIST, OWASP, **MASWE**, **OWASP Mobile Top 10 2024**, CAPEC, CISA, NSA; scores; remediation/revalidate. **CVE/SCA:** **[Partial]** `--sca` + OSV when name+version extracted (no invented CVEs).

### 3.3 Dynamic analysis (DAST)

- **FR-DA1** **Android:** **[Partial — scaffold]** adb install + Frida observation (SSL trust-all, sensitive log, cleartext URL). No scripted UI flows.
- **FR-DA2** **iOS:** **[Planned]** Stub only (`run_ios_dast` → `[]`).
- **FR-DA3** **Runtime checks:** **[Partial]** Three observation hooks above; broader suite **planned** (no exploit docs).
- **FR-DA4** **[Implemented]** `--dynamic`; skipped cleanly if adb/device missing.

### 3.4 Reporting and output

- **FR-R1** **Formats:** **[Implemented]** JSON, text, CSV, HTML, SARIF 2.1 (`ruleId`, level, locations, help, taxa); `{timestamp}` out-file.
- **FR-R2** **Content:** **[Implemented]** metadata + findings + `by_severity` (incl. critical) + enrichment.
- **FR-R3** **Exit code:** **[Partial]** 0 on success; non-zero on fatal/invalid path. Severity gate **planned**.
- **FR-R4** **[Implemented]** Logging to stderr; report to stdout or file.

### 3.5 CLI and integration

- **FR-C1** CLI: **[Implemented]** `--sast`, `--dynamic`, `--apkid`, `--semgrep`, `--mobsfscan`, `--sca`, `--sca-offline`, formats, types, jobs. See `docs/USAGE.md`.
- **FR-C2** Optional web UI: **[Out of scope / not shipped]** — no in-repo browser emulator or web main page for DAST.

---

## 4. Non-functional requirements

- **NFR-1** **Performance:** **[Partial]** Parallel discovery/metadata via `-j`; SAST not heavily parallelized; DAST sequential per artifact.
- **NFR-2** **Reproducibility:** **[Implemented]** requirements.txt; documented Python/platform notes in README.
- **NFR-3** **Platform:** **[Partial]** CLI on Windows/Linux/macOS; iOS DAST requires macOS when built.
- **NFR-4** **Extensibility:** **[Partial]** Package layout allows new rules; pluggable Semgrep/mobsfscan backend **planned**.

---

## 5. Vulnerability taxonomy (alignment)

Align findings with **OWASP MASVS** control groups (lookup after a finding exists):

| MASVS | Focus | Example checks (SAST/DAST) |
|-------|--------|----------------------------|
| MASVS-STORAGE | Data at rest | Sensitive data in SharedPreferences/files; backup exposure. |
| MASVS-CRYPTO | Cryptography | Weak algorithms; hardcoded keys; insecure random. |
| MASVS-AUTH | Auth/authz | Hardcoded credentials; token handling; auth bypass. |
| MASVS-NETWORK | Data in transit | Cleartext traffic; weak TLS; certificate validation. |
| MASVS-PLATFORM | Platform interaction | Exported components; intents; deep links. |
| MASVS-CODE | Data processing | SQLi; XSS; injection; unsafe deserialization. |
| MASVS-RESILIENCE | Reverse engineering | Debuggable; tampering; root detection. |
| MASVS-PRIVACY | Privacy | PII handling; logging; permissions. |

Use **MASTG** tests and **MASWE** weakness IDs in rule metadata where possible (**mostly planned** beyond MASVS-ish tags on pattern rules).

---

## 6. Architecture (high level)

- **Discovery layer:** Walk filesystem; classify by extension/type. **[Implemented]** APK, IPA, JAR, .so, SDK.
- **Metadata layer:** Per type, parse artifact. **[Implemented with gaps]** as in §0.
- **SAST layer:** Extract strings / metadata heuristics; pattern rules; emit findings. **[Implemented as pattern scan]** — not decompile + Semgrep. Taxonomy enrichment after the fact.
- **DAST layer (optional):** **[Partial]** Android scaffold; iOS stub. Broader runtime suite **planned**.
- **Reporting layer:** Aggregate metadata + findings; JSON/text/CSV/HTML/SARIF. **[Implemented]** with format-depth caveats in §0.
- **CLI/UI:** **[Partial]** CLI implemented (`cli.py`); UI planned. Prefer `cli.py` over legacy `scanner.py` (stdlib discovery only).

---

## 7. Dependencies and tooling

| Area | Dependency | Purpose | Status |
|------|------------|---------|--------|
| APK metadata | apk-info | Manifest, permissions, components, signatures. | Used when installed |
| ELF/.so | pyelftools | ELF parsing, DT_NEEDED, symbols. | Used when installed |
| DEX string tables (Android) | androguard (optional) | Better string/class name extraction for **same** pattern rules; not deeper analysis. | Optional |
| Rule engine | custom patterns today; Semgrep/mobsfscan later | Pattern matching. | Custom **[Implemented]**; Semgrep **[Planned]** |
| DAST | Frida, Android emulator (AVD), iOS simulator | Instrumentation and runtime testing. | Android one-check **[Partial]**; iOS **[Planned]** |
| Stdlib | zipfile, plistlib, pathlib, multiprocessing, logging | JAR, IPA plist, discovery, concurrency, logging. | Used |

---

## 8. Success criteria

- User can run one CLI command on a path and receive a report containing metadata + (optional) pattern-scan SAST findings and (optional) DAST scaffold findings when the environment allows.
- Findings are categorized by severity and mapped to taxonomy labels where a rule mapping exists — treat as **leads**, not confirmed vulns, until deeper detectors exist.
- Multiple agents can work on different layers with clear handoffs (see agent skills).

---

## 9. Testing use cases

Use these scenarios to validate the product in real time. Tests can be automated (CI) or run manually.

| ID | Use case | What to do | Layer(s) | Status note |
|----|----------|------------|----------|-------------|
| **TC-1** | Scan single vulnerable APK | Run scanner on one known-vulnerable APK (download locally; APKs gitignored). | Discovery, metadata, SAST | Manual / fixtures download |
| **TC-2** | Scan single vulnerable IPA | Run scanner on one known-vulnerable IPA (download; IPAs gitignored). | Discovery, metadata, SAST | Manual |
| **TC-3** | Scan mixed directory | Run scanner on a folder containing APKs, IPAs, JARs, .so, and an SDK-like directory. | Discovery, metadata | Partial without downloaded APKs |
| **TC-4** | Metadata correctness (APK) | Assert package, version, permissions, exported component, signature when apk-info + APK present. | Metadata | Needs downloaded APK |
| **TC-5** | SAST findings on vulnerable APK | Assert presence of pattern findings (not confirmed vuln triage). | SAST | Needs downloaded APK |
| **TC-6** | SAST findings on vulnerable IPA | Assert at least one finding category when IPA present. | SAST | Manual |
| **TC-7** | Dynamic scan (Android) | With emulator + Python Frida, `--dynamic`; expect install and possibly one SSL finding. | DAST | Scaffold only |
| **TC-8** | Dynamic scan (iOS) | On macOS with simulator, `--dynamic` on IPA. | DAST | Stub — expect skip / empty |
| **TC-9** | Report formats | Assert JSON valid; text/HTML/SARIF generate. | Reporting | Unit coverage partial |
| **TC-10** | CLI robustness | Invalid path → non-zero; `--types` filter. | CLI | Limited automated coverage |
| **TC-11** | Real-time regression | Re-download reference app; compare finding categories to baseline. | End-to-end | Manual |

---

## 10. Test success criteria

A test **passes** when all of the following hold for its scope:

- **Discovery:** All expected files (by type) in the path are listed in the report; no crash on malformed or empty paths.
- **Metadata:** For each artifact in the report, required fields for that type are present and non-empty where the artifact and deps provide them.
- **SAST:** For vulnerable reference apps (§11), the report contains at least the minimum expected **pattern** findings (e.g. cleartext/`http://` or secret-like substring). Success is presence of expected **classes** of hits, not confirmed exploitability.
- **DAST:** When enabled and environment available, run completes without fatal error; may produce the SSL trust-all finding or only successful install/instrumentation. If emulator unavailable, skip (not fail). iOS DAST currently always empty.
- **Reporting:** JSON valid with metadata + findings arrays. Text/HTML/SARIF generation do not raise.
- **CLI:** Exit code 0 for successful scan; non-zero for invalid path or fatal error.

**Baseline (expected findings):** Maintain a small baseline per reference app (e.g. “InsecureBankv2: expect ≥1 DEX/metadata pattern finding”). Update when rules or app versions change.

---

## 11. Reference test artifacts (vulnerable APK / IPA)

Use these **intentionally vulnerable** apps to test the scanner. **Binaries are gitignored** — download into `tests/fixtures/` (or another local dir). See `tests/fixtures/README.md`.

### Android (APK)

| App | Description | Source / download |
|-----|-------------|-------------------|
| **OWASP MASTG Hacking Playground** | Official OWASP vulnerable app (Kotlin/Java). | [GitHub: OWASP/MASTG-Hacking-Playground](https://github.com/OWASP/MASTG-Hacking-Playground) |
| **InsecureBankv2** | Widely used for Android security training. | [Android-InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2) |
| **DIVA** | Intentional vulnerabilities for learning. | [diva-apk](https://github.com/zpatshueh/diva-apk) |
| **InsecureShop** | Training shop APK. | [InsecureShop releases](https://github.com/hax0rgb/InsecureShop/releases) |
| **UnCrackable (L1–L4)** | OWASP reverse-engineering challenges. | [MASTG apps](https://mas.owasp.org/MASTG/apps/). |
| **AndroGoat** | OWASP vulnerable app. | [MASTG reference applications](https://mas.owasp.org/MASTG/apps/). |

**Suggested default for TC-1:** InsecureBankv2 or InsecureShop APK. **In git under `tests/fixtures/`:** small JARs, `libdivajni.so`, `sample_sdk/` — **not** the APKs. `tests/run_fixtures_scan.py` writes reports under `reports/` (also gitignored).

### iOS (IPA)

| App | Description | Source / download |
|-----|-------------|-------------------|
| **Damn Vulnerable iOS App (DVIA-v2)** | Swift app with many vulnerability categories. | [GitHub: prateek147/DVIA-v2](https://github.com/prateek147/DVIA-v2) |
| **iGoat (Swift)** | OWASP intentionally insecure iOS app. | [OWASP iGoat-Swift](https://github.com/OWASP/iGoat-Swift) |

**Suggested default for TC-2:** DVIA-v2 IPA (download/build locally; gitignored).

### Usage in tests

- **Automated:** CI should not assume APKs in git. Prefer synthetic non-binary fixtures for unit tests; download fixed URLs in optional integration jobs.
- **Manual / real-time:** Download reference apps into a local folder and run `python cli.py path/to/apps --sast -o json`.
- **Baseline:** Define minimum expected finding **categories** per app (see §10).

---

## 12. References

- [OWASP MASVS](https://mas.owasp.org/MASVS/)
- [OWASP MASTG](https://mas.owasp.org/MASTG/)
- [OWASP MASWE](https://mas.owasp.org/MASWE/)
- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) — reference architecture for static + dynamic.
