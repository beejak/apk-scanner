# Semgrep starter rules (Android / MASVS-oriented)

Small **original** rule pack shipped with apk-scanner so `--semgrep` has a mobile-relevant default without downloading large external packs.

Default path used by the plugin when `APK_SCANNER_SEMGREP_CONFIG` is unset:

```
rules/semgrep/android-mastg-starter.yml
```

These rules are **starter leads** (pattern SAST), not a full OWASP MASTG suite.

## Optional: fuller community packs

Install Semgrep, then point at a larger config if you want:

```bash
# OWASP MASTG rules (clone separately; not vendored here)
git clone --depth 1 https://github.com/OWASP/mastg.git
export APK_SCANNER_SEMGREP_CONFIG="$PWD/mastg/rules"

# Or mindedsecurity Android pack
# export APK_SCANNER_SEMGREP_CONFIG=path/to/semgrep-rules-android-security

python cli.py app.apk --semgrep -o json
```

Missing `semgrep` on PATH → plugin logs and skips (scan still succeeds).
