# Test fixtures

Sample artifacts used to test the scanner (discovery, metadata, SAST, taxonomy).

## Public clone note

**APKs are gitignored** and are not in the repository. After cloning, download the training APKs below into this directory (`tests/fixtures/`) if you want full APK / DEX coverage. Small non-APK fixtures (`sample_sdk/`, JARs, `libdivajni.so`) are tracked in git.

## What’s included (in git)

| Type | File / path | Source / note |
|------|-------------|----------------|
| **JAR** | `junit-4.13.2.jar` | Maven Central (JUnit). |
| **JAR** | `test-with-secrets.jar` | Local minimal JAR with `config.properties` containing `api_key=`, `password=`, `http://` to trigger JAR SAST. |
| **.so** | `libdivajni.so` | Extracted from DivaApplication.apk (`lib/x86_64/libdivajni.so`) to test .so metadata + native SAST (e.g. JNI_OnLoad, string patterns). |
| **SDK** | `sample_sdk/` | Local dir with `include/`, `lib/`, and `.env` (triggers SDK SAST: sensitive file + credential pattern). |
| **JSON** | `report.json` | Tiny sample report for unit tests. |

## Download APKs yourself (not in git)

Place these files in `tests/fixtures/` (same directory as this README):

| File | Source | How to get |
|------|--------|------------|
| `InsecureBankv2.apk` | [Android-InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2) | Build or obtain a release/build APK from that project and copy it here as `InsecureBankv2.apk`. |
| `InsecureShop.apk` | [hax0rgb/InsecureShop](https://github.com/hax0rgb/InsecureShop) | Direct: `https://github.com/hax0rgb/InsecureShop/releases/download/v1.0/InsecureShop.apk` |
| `DivaApplication.apk` | [diva-apk](https://github.com/zpatshueh/diva-apk) | Download/build from the DIVA project and save as `DivaApplication.apk`. |

Example (InsecureShop only; requires a network download):

```bash
# from project root (PowerShell or bash with curl)
curl -L -o tests/fixtures/InsecureShop.apk https://github.com/hax0rgb/InsecureShop/releases/download/v1.0/InsecureShop.apk
```

## Optional (add yourself for full coverage)

- **IPA**: Drop a test IPA (e.g. from [DVIA-v2](https://github.com/OWASP/owasp-mastg/tree/master/Crackmes/iOS) or build from OWASP iGoat) to test IPA metadata + SAST (plist + string scan). IPAs are also gitignored.
- **Live APKs (e.g. MyJio)**: Available from [APKMirror](https://www.apkmirror.com/apk/jio-platforms-limited/myjio/). Download manually via browser (APKMirror does not expose simple direct URLs for scripting). Use only for personal testing; commercial apps may have ToS restrictions on reverse engineering.

## Run scanner on fixtures

From project root:

```bash
python cli.py tests\fixtures --sast -o text
python cli.py tests\fixtures --sast -o csv --out-file "reports/scan_{timestamp}.csv"
```

Or use the test runner (writes JSON + CSV to `reports/`):

```bash
python tests/run_fixtures_scan.py
```

Expected with APKs present: **3 APKs** (InsecureBankv2, InsecureShop, DIVA – DEX findings), **2 JARs** (findings from `test-with-secrets.jar`), **1 .so** (libdivajni.so – JNI/string SAST), **1 SDK** (findings from `sample_sdk/.env`). Without APKs, discovery still covers JARs, `.so`, and `sample_sdk/`. Reports include taxonomy (CWE, NIST, OWASP, CAPEC, CISA, NSA) per finding. Install `pyelftools` for full .so metadata (elf_class, machine via `get_machine_arch()`, needed, JNI exports); `androguard` for richer DEX SAST.
