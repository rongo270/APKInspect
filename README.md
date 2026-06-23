# APKInspect

A **self-contained static security scanner for Android APK / AAB files**. Point it
at an `.apk` or `.aab` and it inspects the manifest and every packaged file, then
rates the app from **100 (safe)** to **0 (fully exposed / unsafe)**.

* **Zero runtime dependencies** — pure Python standard library (3.8+). It ships its
  own Android Binary XML (AXML) parser and a protobuf decoder for AAB manifests, so
  there is no Android SDK, `aapt`, or `androguard` to install.
* **Defensive use** — built for app authors, reviewers, and CI to catch leaks
  *before* shipping. It reports the presence/exposure of issues; it does not attack
  anything.

```
$ apkinspect app.apk
----------------------------------------------------------------
  APKInspect security report
----------------------------------------------------------------
  File       : app.apk
  Type       : APK   Size: 7.31 MiB   Entries: 412
  Package    : com.example.app  v1.4.2 (1042)
  SDK        : minSdk=21  targetSdk=33   dex=2  native_libs=True

  SAFETY SCORE   42/100  [##########..............]  grade D  (high risk)
  Findings      Critical: 1  High: 3  Medium: 5  Low: 6
  ...
```

## Graphical interface

Prefer a UI? APKInspect ships a polished, self-contained **local web app** — drag in an
APK/AAB to get an animated safety score and expandable, colour-coded findings, plus a
built-in **Threat Book** that explains every issue and exactly how to block it.

```bash
python -m apkinspect.web      # starts a local server and opens your browser
# or, after `pip install .`
apkinspect-gui
```

On Windows you can just **double-click `APKInspect.cmd`**. Everything runs on
`127.0.0.1` — no file ever leaves your machine. (No sample handy? Click **“try a sample
scan”** on the drop zone.)

| Scanner | Threat Book |
|---|---|
| ![Scanner view](assets/screenshots/scanner.png) | ![Threat Book](assets/screenshots/threat-book.png) |

![Results view](assets/screenshots/results.png)

The app icon lives in `assets/` (`icon.png` / `icon.ico`), and the project folder is
configured via `desktop.ini` to show it in Windows Explorer.

## Install / run

No install required:

```bash
python -m apkinspect path/to/app.apk
```

Or install the console script:

```bash
pip install .
apkinspect path/to/app.apk path/to/bundle.aab
```

### Common options

| Option | Purpose |
|---|---|
| `--json` | Machine-readable output (one object, or a list for multiple files). |
| `--quiet` | Header + score + counts only (omit per-finding detail). |
| `--no-color` | Disable ANSI colour. |
| `--no-secrets` | Skip the secret/API-key sweep (manifest checks only, faster). |
| `--min-score N` | **CI gate:** exit non-zero if any file scores below `N`. |
| `--fail-on SEV` | **CI gate:** exit non-zero on any finding at/above `CRITICAL\|HIGH\|MEDIUM\|LOW`. |
| `-o FILE` | Write the report to a file (UTF-8). |

Exit codes: `0` ok · `1` a CI gate failed · `2` a file could not be scanned.

```bash
# Fail a pipeline if any shipped build scores under 70 or has a HIGH+ issue
apkinspect build/*.apk --min-score 70 --fail-on HIGH
```

## What it checks (the full map)

Every check has a stable `id` and is exercised by an automated test.

### Hard-coded secrets & exposed backends (`apkinspect/secrets.py`)
Swept across DEX, `resources.arsc`, `assets/`, native libs, and manifest meta-data.
Values are **redacted** in the report (`AKIA...MPLE (len 20)`); URLs/identifiers are
shown in full so you can act on them.

| id | severity | detects |
|---|---|---|
| `SECRET_PRIVATE_KEY` | CRITICAL | PEM private key blocks (RSA/EC/DSA/OPENSSH/PGP) |
| `SECRET_GCP_SERVICE_ACCOUNT` | CRITICAL | Google service-account JSON |
| `SECRET_AWS_ACCESS_KEY_ID` | CRITICAL | AWS access key id (`AKIA…`) |
| `SECRET_AWS_SECRET_KEY` | CRITICAL | AWS secret key (context-gated) |
| `SECRET_STRIPE_LIVE` | CRITICAL | Stripe live secret key (`sk_live_…`) |
| `SECRET_SENDGRID` | CRITICAL | SendGrid API key |
| `SECRET_GITHUB_TOKEN` | CRITICAL | GitHub tokens (`ghp_/gho_/…`) |
| `SECRET_GOOGLE_API_KEY` | HIGH | Google API key (`AIza…`) |
| `SECRET_FCM_SERVER_KEY` | HIGH | Firebase Cloud Messaging legacy server key |
| `SECRET_FIREBASE_DB_URL` | HIGH | **Firebase Realtime DB URL exposure** |
| `SECRET_FIREBASE_STORAGE` | MEDIUM | Firebase Storage / GCS bucket |
| `SECRET_SLACK_TOKEN` / `SECRET_SLACK_WEBHOOK` | HIGH | Slack token / incoming webhook |
| `SECRET_TWILIO_KEY` / `SECRET_MAILGUN` | HIGH | Twilio / Mailgun keys |
| `SECRET_GOOGLE_OAUTH` | LOW | Google OAuth client id |
| `SECRET_JWT` | LOW | JSON Web Tokens |
| `SECRET_HARDCODED_CREDENTIAL` | MEDIUM | `api_key=/password=/secret=` with a high-entropy value (placeholders and low-entropy strings are filtered out) |

### Exported components & deep links (`apkinspect/manifest.py`)

| id | severity | detects |
|---|---|---|
| `COMPONENT_EXPORTED` | HIGH/MEDIUM | activity/service/receiver/**provider** reachable by any app with no permission (explicit or implicit via intent-filter). Providers are HIGH; the launcher entry point is intentionally excluded. |
| `COMPONENT_HTTP_DEEPLINK` | HIGH | BROWSABLE intent-filter accepting **cleartext `http://`** web links (deep-link hijacking / MITM) |
| `COMPONENT_PROVIDER_GRANTURI` | MEDIUM | exported provider with `grantUriPermissions="true"` |
| `COMPONENT_EXPORTED_WEAKPERM` | LOW | exported but guarded only by a `normal`/`dangerous` permission |
| `COMPONENT_EXPORTED_PERM` | LOW | exported but permission-guarded (verify it is signature-level) |

### Configuration & network posture

| id | severity | detects |
|---|---|---|
| `MANIFEST_DEBUGGABLE` | HIGH | `android:debuggable="true"` |
| `MANIFEST_CLEARTEXT` | MEDIUM | `android:usesCleartextTraffic="true"` |
| `MANIFEST_CLEARTEXT_DEFAULT` | LOW | cleartext allowed by default (targetSdk < 28, no network security config) |
| `MANIFEST_ALLOWBACKUP` | MEDIUM | `android:allowBackup="true"` |
| `MANIFEST_ALLOWBACKUP_DEFAULT` | LOW | `allowBackup` not explicitly disabled |
| `MANIFEST_TESTONLY` | LOW | `android:testOnly="true"` |
| `MANIFEST_OLD_MINSDK` | LOW | `minSdkVersion < 24` |

### Dangerous permissions (`apkinspect/permissions.py`)

| id | severity | detects |
|---|---|---|
| `PERMISSION_DANGEROUS` | HIGH/MEDIUM/LOW | runtime-dangerous and powerful permissions (e.g. `SYSTEM_ALERT_WINDOW`, `REQUEST_INSTALL_PACKAGES`, `MANAGE_EXTERNAL_STORAGE`, `READ_SMS`, location, camera, …) with a per-permission severity and rationale |

## Scoring model (`apkinspect/scoring.py`)

A perfect app starts at **100**. Each finding multiplies the running score by
`(1 - impact)`, where `impact` depends on severity
(`CRITICAL 0.45 · HIGH 0.22 · MEDIUM 0.09 · LOW 0.025 · INFO 0`). Repeated findings
in the same category **decay** (× 0.55 each), so a long tail of minor issues — or a
permission-heavy but otherwise sound app — can't underflow the score. The result is
clamped to `[0, 100]` and mapped to a grade:

| score | grade | risk |
|---|---|---|
| 90–100 | A | minimal |
| 75–89 | B | low |
| 60–74 | C | moderate |
| 40–59 | D | high |
| 0–39 | F | critical |

## Testing

79 unit/integration tests build **synthetic APK/AAB archives with planted issues**
(a from-scratch AXML encoder round-trips against the parser) and assert that every
check fires, that a clean app scores 100, and that a vulnerable app scores in the
failing range.

```bash
python -m unittest discover -s tests -v
```

Generate sample artifacts to try the CLI by hand:

```bash
python tools/make_samples.py            # writes samples/{vulnerable,clean}.apk, vulnerable.aab
python -m apkinspect samples/vulnerable.apk
```

## Project layout

```
apkinspect/
  axml.py        Android Binary XML (APK manifest) parser
  aab.py         Protobuf manifest parser (AAB, best-effort)
  manifest.py    Exported-component / config / permission analysis
  permissions.py Dangerous-permission catalogue
  secrets.py     Secret / API-key / Firebase-URL scanner + redaction
  scoring.py     0-100 scoring engine
  scanner.py     Orchestration (open archive -> findings -> score)
  catalog.py     Threat encyclopedia (powers the Threat Book + fix advice)
  report.py      Text + JSON rendering
  __main__.py    CLI
  web/           Local web GUI (stdlib http.server + static SPA)
    server.py    API (/api/scan, /api/catalog, /api/demo) + static serving
    static/      index.html, styles.css, app.js, icon.svg
assets/          App icon (png/ico) + screenshots
tests/           Test suite + synthetic-fixture builders
tools/           Sample generator + pure-Python icon generator
APKInspect.cmd   Windows double-click launcher for the GUI
```

## Limitations & honest caveats

* **Static analysis.** It flags the *presence/exposure* of issues, not proven
  exploitability. A flagged Firebase URL or exported component may be intentional and
  safe — verify (e.g. test `https://<db>.firebaseio.com/.json` for open rules).
* **AAB manifests are best-effort.** The bundle manifest is protobuf-encoded and
  decoded generically; most attributes resolve, but unusual compiled values may not.
* **AXML parser** follows the documented AOSP on-disk format and is validated by
  encode/decode round-trips. For high-assurance review of arbitrary real-world APKs
  you can additionally cross-check with a heavyweight tool such as `androguard`.
* No DEX bytecode/dataflow analysis, certificate/signature-scheme verification, or
  native-code disassembly (the secret sweep does scan `.so` bytes).
