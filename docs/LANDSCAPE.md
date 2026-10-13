# Competitive landscape — apk-scanner

**Audience:** repo owner / product managers.  
**Survey date:** 2026-10-14 (GitHub API + public releases). Re-check stars/activity before betting a quarter.  
**Scope:** popular open-source Android/iOS/mobile security scanners vs [beejak/apk-scanner](https://github.com/beejak/apk-scanner).

Related: [USAGE.md](USAGE.md) (shipped capabilities), [PRD.md](PRD.md), [README](../README.md).

---

## Executive summary

**apk-scanner** is a thin, honest GitHub-maintained CLI: artifact discovery (APK/IPA/JAR/.so/SDK), metadata, constrained pattern-scan SAST with Critical/High signal rules, MASWE / OWASP Mobile Top 10 2024 enrichment, SARIF/HTML manager reports, optional plugins (APKiD / Semgrep / mobsfscan), real OSV SCA when name+version extract, and a Frida/adb DAST scaffold. Weekly Actions already prove allowlist-only sandbox scanning without committing binaries.

It is **not** competing with MobSF as an all-in-one lab, or Quark as a malware-family engine. Managers who need “is this sample malware / which family / what RCE-class behavior graph” will look at Quark/MobSF and find us empty. Managers who need “inventory + high-impact pattern leads + scored fix/revalidate + SARIF in CI on GitHub runners” already have a differentiated, maintainable niche.

**Blunt verdict:** Do **not** rebuild MobSF. Do **not** chase full DAST/device farms (GitHub-only constraint). Win the next 6 months by (1) malware/behavior scoring via optional Quark plugin, (2) shipping rules-as-code defaults (OWASP MASTG / Android Semgrep packs), (3) making SCA manager-grade (SBOM-ish inventory + OSV coverage), (4) optional nuclei `file/android` after decompile, (5) Code Scanning upload so findings show in the Security tab. Skip QARK and SUPER Android Analyzer — stale/archived.

**Actions status (2026-10-14):** CI green on recent pushes. Weekly sandbox scan succeeded on latest `workflow_dispatch` (2026-10-13). No cron weekly run observed yet after the workflow landed (next scheduled Monday 06:00 UTC).

---

## Competitor table

Stars / activity from GitHub API on survey date. “Killer feature” = what managers notice first.

| Tool | Stars (approx) | Last release / activity | Killer feature(s) | Alive? | Overlap with us |
|------|----------------|-------------------------|-------------------|--------|-----------------|
| **[MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)** | ~21.9k | **v4.5.3** (2026-09-21); push 2026-10-13 | Full static+dynamic lab, cert/malware/VT, AppSec score, web UI, iOS jailbreak path | Yes — active | We wrap none of the lab; we are CLI/CI inventory+pattern leads |
| **[Quark-Engine](https://github.com/ev-flow/quark-engine)** (ex quark-engine org) | ~1.7k | **v26.10.1** (2026-10-10); monthly family rules | Malware **family** scoring, Dalvik behavior rules, call graphs, obfuscation-tolerant loader | Yes — very active | **We lack entirely** — biggest credibility gap for “threat” narratives |
| **[APKiD](https://github.com/rednaga/APKiD)** | ~2.6k | **v3.1.0** (2026-04-09); push 2026-10-07 | Packer/protector/obfuscator ID (PEiD for APK) | Yes | Already optional `--apkid` plugin |
| **[mobsfscan](https://github.com/MobSF/mobsfscan)** | ~792 | **1.0.1** (2026-09-21) | Source SAST (Java/Kotlin/Swift/ObjC/XML) + **native GHA + SARIF→Code Scanning** | Yes | Already optional `--mobsfscan`; we don’t ship the Action UX |
| **[androguard](https://github.com/androguard/androguard)** | ~6.3k | **v4.1.4** (2026-06-05); push 2026-10-12 | DEX/APK RE library, analysis backbone | Yes | Optional via `APK_SCANNER_ANDROGUARD=1`; not default |
| **[jadx](https://github.com/skylot/jadx)** | ~50.9k | **v1.5.6** (2026-07-10); push 2026-10-12 | Best-in-class DEX→Java decompiler (GUI/CLI) | Yes | We don’t decompile; blocks deeper Semgrep/nuclei on Java |
| **Semgrep** (+ [OWASP MASTG rules](https://github.com/OWASP/mastg/tree/master/rules), [mindedsecurity Android rules](https://github.com/mindedsecurity/semgrep-rules-android-security) ~342★) | ~17k (engine) | Semgrep **v1.180.0** (2026-10-07); MASTG active | Rules-as-code, CI-native, MASVS-mapped Android packs | Yes | Plugin exists; default config is generic `p/security-audit`, not mobile packs |
| **[nuclei](https://github.com/projectdiscovery/nuclei)** + [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) `file/android` (~25 templates) | ~32k / ~13k | nuclei **v3.11.1** (2026-08); templates hot | YAML community templates; manifest/permission/exported/WebView file checks on decompiled trees | Yes | **No plugin**; needs decompile step first |
| **[QARK](https://github.com/linkedin/qark)** | ~3.4k | Last push **2024-01-16**; no 2025–26 releases | Classic Android vuln hunter (LinkedIn) | **Stale** — do not depend | Historical only |
| **[SUPER Android Analyzer](https://github.com/SUPERAndroidAnalyzer/super)** | ~427 | Archived; last push **2020-09** | Rust static analyzer | **Dead** | Ignore |
| **[APKHunt](https://github.com/Cyber-Buddy/APKHunt)** | ~986 | Push 2026-09-24 | MASVS-oriented static checks on APKs | Alive-ish | Overlaps our pattern SAST; less CI packaging than us |

---

## Diff: what THEY have that WE lack (high manager impact)

| Gap | Who has it | Manager impact | Our status |
|-----|------------|----------------|------------|
| **Malware family / behavior score** | Quark (primary), MobSF | “Is this trojan/RAT/banker?” board-level | Missing |
| **Full static+dynamic lab / AppSec scorecard** | MobSF | One-stop report for pen-test shops | Out of scope for GitHub-only CLI; don’t clone |
| **RCE-class *confirmed* or deep bytecode taint** | Quark behavior chains; MobSF deeper analysis | We have **pattern** Critical (`Runtime.exec`, JS bridge, etc.) — leads, not confirmed | Partial signal only — honesty already documented |
| **SCA/CVE at portfolio scale** | MobSF deps; commercial SCA; our OSV is real but thin | Managers want CVE counts on third-party SDKs | OSV exists; weak extraction / no CycloneDX SBOM / no KEV highlight |
| **Rules-as-code mobile defaults** | mobsfscan, MASTG Semgrep, nuclei YAML | Auditable rule PRs, community velocity | Custom Python patterns + optional Semgrep with wrong default pack |
| **Decompile → deeper SAST** | jadx + Semgrep/nuclei/mobsfscan on sources | Line-level Java findings vs ZIP strings | No jadx step |
| **CI → GitHub Code Scanning tab** | mobsfscan Action recipe | Findings visible without opening HTML | We emit SARIF; weekly/CI don’t upload to code-scanning |
| **Packer/obfuscator tags** | APKiD | Quick “is this packed?” | Have plugin |
| **iOS depth** | MobSF, mobsfscan (source) | IPA ATS + strings only for us | Weak by design today |
| **Production DAST** | MobSF dynamic | Runtime proof | Scaffold only — keep honest |

---

## Top 5 incorporations (next 6 months)

Ranked by **impact / effort** for **GitHub-only** maintenance (edit via web UI/PRs + Actions; no local IDE required; no random internet downloads).

| Rank | Incorporation | Impact | Effort | Why |
|------|---------------|--------|--------|-----|
| **1** | **Optional `--quark` plugin** — shell out to Quark-Engine when on PATH; map summary score + top rules/families into our finding schema | **High** — fills the malware narrative hole | Medium (plugin + CI optional install + tests with fixture skip) | Highest credibility per line of glue code; Quark actively ships family rules in 2026 |
| **2** | **Mobile rules-as-code defaults** — document + default `APK_SCANNER_SEMGREP_CONFIG` to OWASP MASTG `rules/` or mindedsecurity Android pack; keep Python Critical rules as fast path | **High** — manager-auditable rules, fewer “custom only” objections | Low–medium | Plugin already exists; wrong default is the gap |
| **3** | **SCA manager pack** — CycloneDX/JSON component inventory from JAR/Gradle/pom; OSV + optional CISA KEV tag on aliases; HTML “CVE board” section | **High** for SDK/supply-chain buyers | Medium | OSV path half-there; extraction + report UX is the work |
| **4** | **Optional jadx decompile → nuclei `file/android` (and/or Semgrep on Java)** in `$RUNNER_TEMP`, purge after | **Medium–high** coverage jump | Medium–high (tool install, time, flaky decompile) | Community YAML velocity; don’t vendor templates |
| **5** | **SARIF upload to GitHub Code Scanning** on weekly + optional PR workflow (`security-events: write`) | **Medium** visibility | **Low** | We already produce SARIF; missing the last mile MobSF/mobsfscan advertise |

**Explicit non-goals (6 months):** reimplement MobSF UI/dynamic lab; resurrect QARK/SUPER; cloud device farm; random APK crawling; claiming confirmed RCE without dynamic proof.

---

## Recommended backlog (checklist)

- [ ] `--quark` optional plugin + USAGE honesty (“behavior score / family hints, not AV verdict”)
- [ ] Default Semgrep config → MASTG or Android security pack; pin path/version in docs
- [ ] SCA: inventory export + KEV flag + manager HTML section
- [ ] Optional `jadx` + `nuclei -t file/android` plugin (skip if tools missing)
- [ ] Weekly/CI: `github/codeql-action/upload-sarif` (or equivalent) for sandbox SARIF
- [ ] Keep APKiD/mobsfscan optional; don’t vendor MobSF
- [ ] Monthly landscape refresh (below) — docs only

---

## Monthly landscape refresh (docs-only stub)

**Do not** implement automated random downloads or unallowlisted crawls.

GitHub-only cadence (owner or agent, ~30–45 min):

1. Open this file on `main`.
2. Refresh the competitor table with:
   ```bash
   gh api repos/OWNER/REPO --jq '{stargazers_count,pushed_at,archived}'
   gh api repos/OWNER/REPO/releases/latest --jq '{tag_name,published_at}'
   ```
   Suggested `OWNER/REPO` list: MobSF/Mobile-Security-Framework-MobSF, ev-flow/quark-engine, rednaga/APKiD, MobSF/mobsfscan, androguard/androguard, skylot/jadx, semgrep/semgrep, projectdiscovery/nuclei, projectdiscovery/nuclei-templates, linkedin/qark, SUPERAndroidAnalyzer/super, Cyber-Buddy/APKHunt.
3. Note any **new** high-impact capability (malware families, SCA, CI recipes).
4. Adjust the Top 5 backlog if impact/effort changed; bump **Survey date**.
5. PR titled `docs: monthly landscape refresh YYYY-MM`.
6. Optional reminder: GitHub Issue template or calendar; **no** new Actions download job required.

Optional future (only if desired): a `workflow_dispatch` / monthly cron that **opens a blank issue** “Landscape refresh due” with this checklist — zero binary downloads.

---

## What we already do well (keep)

- Honest severity language (leads vs confirmed)
- Multi-artifact inventory (APK/IPA/JAR/.so/SDK) in one CLI
- Taxonomy packaging (MASWE + Mobile Top 10 2024 + remediation/revalidate)
- GitHub Actions weekly allowlist sandbox + report commit without binaries
- Real OSV CVEs when coordinates exist (no invented CVEs)
- Optional plugin seam (APKiD / Semgrep / mobsfscan) that skips cleanly

---

*End of landscape note. Update via monthly refresh; do not treat star counts as quality.*
