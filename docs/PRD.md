# Product Requirements Document: Full-Fledged Mobile & Binary Security Scanner

## 1. Product overview

### 1.1 Vision

A **full-blown code and runtime vulnerability scanner** for Android (APK/AAB), iOS (IPA), Java (JAR), native libraries (.so, .dylib), and SDK-style directories. The product performs **discovery**, **metadata extraction**, **static application security testing (SAST)**, and **dynamic application security testing (DAST)** in one CLI-driven (and optionally UI-driven) toolchain.

### 1.2 Goals

- **Single toolchain:** One scanner that handles APK, IPA, JAR, .so, and SDK from a path or drag-and-drop input.
- **Full vulnerability coverage:** Find code-level issues (SAST) and runtime issues (DAST), not only metadata.
- **Standards-aligned:** Map findings to OWASP MASVS/MASTG/MASWE where applicable.
- **Multi-agent friendly:** Structure and documentation support splitting work across specialized agents (discovery, SAST, DAST, reporting).

### 1.3 Out of scope (for v1)

- Commercial app-store submission gates or store-specific APIs.
- Real-device farm orchestration (focus: emulator/simulator on single machine).
- Full binary decompilation for every format (use decompilation where needed for SAST; not a general-purpose decompiler UI).

---

## 2. User personas and use cases

| Persona | Use case |
|---------|----------|
| **App developer** | Scan a build folder or CI artifact; get a report of metadata + vulnerabilities before release. |
| **Security reviewer** | Point at a directory of APKs/IPAs; run full static + optional dynamic scan; export report (JSON/HTML/SARIF). |
| **DevSecOps** | Integrate scanner in pipeline (CLI); fail build or gate on findings; consume JSON/SARIF. |

---

## 3. Functional requirements

### 3.1 Discovery and metadata (foundation)

- **FR-D1** Discover by path: files (APK, IPA, JAR, .so, .dylib) and directories (SDK heuristics).
- **FR-D2** Extract and report metadata per type:
  - **APK/AAB:** package, version, min/target SDK, permissions, components (activities/services/receivers/providers) with exported flag, signatures/certs, debuggable, allowBackup, features, libraries, multidex, .so list inside APK.
  - **IPA:** bundle ID, version, display name, min OS, Info.plist-derived metadata.
  - **JAR:** manifest (Main-Class, version, Created-By, etc.).
  - **SDK:** directory path, size, entry count, heuristic type.
  - **.so:** path, size, ELF class/machine, DT_NEEDED, DT_SONAME, JNI exports, stripped.
- **FR-D3** Support recursive and non-recursive scan; filter by type (e.g. `--types apk,ipa,so`).
- **FR-D4** Mid-level logging (INFO): discovery summary, per-file progress, OK/skip/error, final summary. Optional verbose (DEBUG) and quiet mode.

### 3.2 Static analysis (SAST)

- **FR-S1** **Android (APK):** Decompile DEX (classes.dex, multidex) to Java or Smali; run pattern/rule engine for code-level vulnerabilities.
- **FR-S2** **JAR:** Decompile or parse bytecode; run pattern/rule engine on code or AST.
- **FR-S3** **IPA / native:** Analyze Mach-O binary, symbols, strings; pattern match for secrets, weak crypto, unsafe APIs.
- **FR-S4** **.so:** String and symbol extraction; pattern match for hardcoded secrets, weak crypto, JNI misuse.
- **FR-S5** **Rule engine:** Configurable rules (e.g. Semgrep, mobsfscan, or custom) for: hardcoded secrets/API keys, insecure crypto, SQLi/XSS patterns, dangerous permissions usage, exported components without protection, debug/log in release, unsafe deserialization. Findings include: rule ID, severity, location (file/line or method), message.
- **FR-S6** Map findings to OWASP MASVS control groups (STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, CODE, RESILIENCE, PRIVACY) and/or MASWE where applicable. **Implemented:** Full taxonomy mapping (CWE, NIST SP 800-53, OWASP, CAPEC, CISA, NSA) per finding; shown in text, CSV, and JSON.

### 3.3 Dynamic analysis (DAST)

- **FR-DA1** **Android:** Run APK in Android emulator (e.g. AVD); instrument with Frida (or equivalent); support automated or scripted flows; observe network, storage, and API behavior.
- **FR-DA2** **iOS:** Run IPA in iOS simulator (macOS) or device; instrument; trigger flows; collect runtime findings.
- **FR-DA3** **Runtime checks:** Certificate pinning bypass, auth bypass, insecure IPC, sensitive data in logs/clipboard, weak TLS, etc. Findings include: check ID, severity, description, evidence.
- **FR-DA4** DAST can be optional (e.g. `--dynamic` flag or separate subcommand) due to environment requirements (emulator, macOS for iOS).

### 3.4 Reporting and output

- **FR-R1** **Formats:** JSON (machine), text (human), **CSV** (table with CWE/NIST/OWASP/CAPEC/CISA/NSA columns), **HTML** (single-file report), **SARIF 2.1.0** (for CI/code scanning). Reports include `scan_timestamp` (ISO 8601 UTC); CLI supports `--out-file` with `{timestamp}` placeholder for timestamped filenames.
- **FR-R2** **Content:** Per-artifact metadata + list of findings (SAST and DAST) with severity, rule/check ID, location, message; summary counts and error/skip list.
- **FR-R3** **Exit code:** 0 on success (with or without findings); non-zero on fatal error or invalid args.
- **FR-R4** Logging to stderr (or configurable); report to stdout or file so output is pipeable.

### 3.5 CLI and integration

- **FR-C1** CLI: positional path; `--types`, `-o` (text|json|csv|html|sarif), `-j` (workers), `--no-recursive`, `-v`/`--quiet`, `--dynamic` (enable DAST), `--rules` (rule set path).
- **FR-C2** Optional web UI: drag-and-drop or path input; run scan; display results and export (same formats). Backend reuses same scanner core.

---

## 4. Non-functional requirements

- **NFR-1** **Performance:** Parallel discovery and parsing (ProcessPoolExecutor or equivalent); SAST can be per-artifact parallel; DAST may be sequential per artifact due to emulator.
- **NFR-2** **Reproducibility:** Pinned dependencies (requirements.txt with versions); documented Python and platform requirements (e.g. Python 3.10+, 64-bit on Windows for apk-info).
- **NFR-3** **Platform:** CLI runs on Windows, Linux, macOS; DAST for iOS requires macOS for simulator.
- **NFR-4** **Extensibility:** Rule engine and SAST/DAST checks are pluggable or configurable so new rules can be added without rewriting core.

---

## 5. Vulnerability taxonomy (alignment)

Align findings with **OWASP MASVS** control groups:

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

Use **MASTG** tests and **MASWE** weakness IDs in rule metadata where possible.

---

## 6. Architecture (high level)

- **Discovery layer:** Walk filesystem (os.scandir); classify by extension/type; emit list of (path, type). **Implemented:** APK, IPA, JAR, .so, SDK (recursive with heuristics).
- **Metadata layer:** Per type, parse artifact (apk-info, plistlib, zipfile, pyelftools); emit unified metadata structure. **Implemented:** All five types; .so uses pyelftools `get_machine_arch()`, elf_class 32/64.
- **SAST layer:** For APK/JAR/IPA/.so/SDK, decompile or extract code/strings; run rule engine; emit findings. **Implemented:** APK (DEX via androguard or ZIP fallback), JAR (ZIP scan), IPA (plist + binary), .so (native strings), SDK (sensitive files + credential patterns). Findings enriched with taxonomy (CWE, NIST, OWASP, CAPEC, CISA, NSA).
- **DAST layer (optional):** For APK/IPA, launch emulator/simulator, install app, instrument (Frida), run flows; emit runtime findings. **Planned.**
- **Reporting layer:** Aggregate metadata + SAST + DAST findings; output JSON/text/CSV (HTML/SARIF optional). **Implemented:** `scan_timestamp`, text with classification line per finding, CSV with taxonomy columns, JSON with full `classification` per finding.
- **CLI/UI:** Entry points that invoke discovery → metadata → SAST [→ DAST] → report. **Implemented:** path, `-o text|json|csv`, `--sast`, `-j`, `--types`, `-v`/`--quiet`, `--out-file` with `{timestamp}`.

---

## 7. Dependencies and tooling

| Area | Dependency | Purpose |
|------|------------|---------|
| APK metadata | apk-info | Manifest, permissions, components, signatures. |
| ELF/.so | pyelftools | ELF parsing, DT_NEEDED, symbols. |
| DEX/SAST (Android) | androguard or jadx | DEX decompilation; optional androguard for bytecode analysis. |
| Rule engine | Semgrep, mobsfscan rules, or custom | Pattern matching on decompiled/source code. |
| DAST | Frida, Android emulator (AVD), iOS simulator | Instrumentation and runtime testing. |
| Stdlib | zipfile, plistlib, pathlib, multiprocessing, logging | JAR, IPA plist, discovery, concurrency, logging. |

---

## 8. Success criteria

- User can run one CLI command on a path and receive a report containing metadata + SAST findings (and DAST if enabled and environment is available).
- Findings are categorized by severity and mapped to MASVS/MASWE where applicable.
- Multiple agents can work on different layers (discovery, SAST, DAST, reporting) with clear handoffs and shared PRD/architecture (see agent skills).

---

## 9. Testing use cases

Use these scenarios to validate the product in real time. Tests can be automated (CI) or run manually.

| ID | Use case | What to do | Layer(s) |
|----|----------|------------|----------|
| **TC-1** | Scan single vulnerable APK | Run scanner on one known-vulnerable APK (e.g. InsecureBankv2 or MASTG Hacking Playground). | Discovery, metadata, SAST |
| **TC-2** | Scan single vulnerable IPA | Run scanner on one known-vulnerable IPA (e.g. DVIA-v2 or iGoat-Swift). | Discovery, metadata, SAST |
| **TC-3** | Scan mixed directory | Run scanner on a folder containing APKs, IPAs, JARs, .so, and an SDK-like directory. | Discovery, metadata |
| **TC-4** | Metadata correctness (APK) | For a reference APK, assert report contains expected package name, version, permission count, at least one exported component, and signature info. | Metadata |
| **TC-5** | SAST findings on vulnerable APK | For a vulnerable reference APK, assert report contains at least N expected SAST findings (e.g. hardcoded secret, debuggable=true, or known CWE/MASVS). | SAST |
| **TC-6** | SAST findings on vulnerable IPA | For a vulnerable reference IPA, assert report contains at least one finding in expected categories (e.g. storage, crypto, or network). | SAST |
| **TC-7** | Dynamic scan (Android) | With emulator and Frida available, run scanner with `--dynamic` on a vulnerable APK; assert at least one runtime finding or successful instrumentation. | DAST |
| **TC-8** | Dynamic scan (iOS) | On macOS with simulator, run `--dynamic` on a vulnerable IPA; assert runtime findings or successful run. | DAST |
| **TC-9** | Report formats | Run scan; assert JSON output is valid and contains metadata + findings arrays; assert text/HTML render without error. | Reporting |
| **TC-10** | CLI robustness | Run with invalid path → non-zero exit; run with `--types apk` on folder with only JARs → empty or JARs excluded per filter. | CLI |
| **TC-11** | Real-time regression | Download latest build of a reference vulnerable app (see §11); re-run TC-1 or TC-2 and compare findings to baseline. | End-to-end |

---

## 10. Test success criteria

A test **passes** when all of the following hold for its scope:

- **Discovery:** All expected files (by type) in the path are listed in the report; no crash on malformed or empty paths.
- **Metadata:** For each artifact in the report, required fields for that type are present and non-empty where the artifact provides them (e.g. APK has package name; IPA has bundle ID).
- **SAST:** For vulnerable reference apps (§11), the report contains at least the minimum expected findings defined in the test baseline (e.g. “at least 1 finding with severity high or critical” or “at least 1 finding tagged MASVS-STORAGE”). No requirement to match an exact count; focus on presence of expected vulnerability categories.
- **DAST:** When DAST is enabled and environment is available, the run completes without fatal error and either produces at least one runtime finding or logs successful instrumentation/flow execution. If emulator/simulator is unavailable, skip or mark DAST test as skipped (not fail).
- **Reporting:** JSON is valid and conforms to the report schema (metadata array, findings array with rule_id, severity, location, message). Text and HTML generation do not raise.
- **CLI:** Exit code 0 for successful scan; non-zero for invalid args or fatal error. Logging appears at configured level (INFO/DEBUG/quiet).

**Baseline (expected findings):** Maintain a small baseline file or table per reference app (e.g. “InsecureBankv2: expect ≥3 SAST findings including debuggable and hardcoded-secret”). Success = scanner finds at least the minimum set or superset. Update baselines when rules or reference app versions change.

---

## 11. Reference test artifacts (vulnerable APK / IPA)

Use these **intentionally vulnerable** apps to test the scanner in real time. Download and place in a test directory (e.g. `tests/fixtures/` or a path documented in the repo).

### Android (APK)

| App | Description | Source / download |
|-----|-------------|-------------------|
| **OWASP MASTG Hacking Playground** | Official OWASP vulnerable app (Kotlin/Java). | [GitHub: OWASP/MASTG-Hacking-Playground](https://github.com/OWASP/MASTG-Hacking-Playground) — build from source or use pre-built APK from releases/Android. |
| **InsecureBankv2** | Widely used for Android security training. | [MASTG reference apps](https://mas.owasp.org/MASTG/apps/) — link to repo or release. |
| **DIVA (Damn Insecure and Vulnerable App)** | Intentional vulnerabilities for learning. | [MASTG apps list](https://mas.owasp.org/MASTG/apps/) — Android/APK. |
| **UnCrackable (L1–L4)** | OWASP reverse-engineering challenges. | [MASTG apps](https://mas.owasp.org/MASTG/apps/). |
| **AndroGoat** | OWASP vulnerable app. | [MASTG reference applications](https://mas.owasp.org/MASTG/apps/). |

**Suggested default for TC-1:** InsecureBankv2 or MASTG Hacking Playground APK. **Fixtures in repo:** `tests/fixtures/` includes InsecureBankv2.apk, DivaApplication.apk (DIVA), libdivajni.so (from DIVA), JARs, and sample_sdk; `tests/run_fixtures_scan.py` runs a full scan and writes `reports/fixtures_scan_<timestamp>.json` and `.csv`. See `tests/fixtures/README.md` for details.

### iOS (IPA)

| App | Description | Source / download |
|-----|-------------|-------------------|
| **Damn Vulnerable iOS App (DVIA-v2)** | Swift app with 16+ vulnerability categories (storage, crypto, pinning, WebView, etc.). | [GitHub: prateek147/DVIA-v2](https://github.com/prateek147/DVIA-v2) — IPA in releases or build from Xcode. |
| **iGoat (Swift)** | OWASP intentionally insecure iOS app. | [OWASP iGoat-Swift](https://github.com/OWASP/iGoat-Swift) — source and unencrypted IPA. |

**Suggested default for TC-2:** DVIA-v2 IPA. Document download or build steps for CI (e.g. macOS runner) and local testing.

### Usage in tests

- **Automated:** In CI, either commit a small, stable test APK/IPA (if license permits) or download from a fixed URL/version in the test script before running TC-1, TC-2, TC-5, TC-6, TC-7, TC-8.
- **Manual / real-time:** Developer downloads one or more reference apps into a local folder and runs the scanner (e.g. `scanner path/to/vulnerable_apps -o json`) to verify behavior and findings.
- **Baseline:** For each reference app, define minimum expected findings (see §10). Store in `tests/baselines/` or in PRD appendix and update when rules or app versions change.

---

## 12. References

- [OWASP MASVS](https://mas.owasp.org/MASVS/)
- [OWASP MASTG](https://mas.owasp.org/MASTG/)
- [OWASP MASWE](https://mas.owasp.org/MASWE/)
- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) — reference architecture for static + dynamic.
