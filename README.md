# APKInspect

[![CI](https://github.com/rongo270/APKInspect/actions/workflows/ci.yml/badge.svg)](https://github.com/rongo270/APKInspect/actions/workflows/ci.yml)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Runtime dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](pyproject.toml)

A **self-contained static security scanner for Android APK / AAB files**. Point it at an
`.apk` or `.aab` and it inspects the manifest and every packaged file, then rates the app
from **100 (safe)** to **0 (fully exposed)**.

* **Zero dependencies** — pure Python standard library (3.8+). It ships its own Android
  Binary XML and AAB protobuf parsers, so there's no Android SDK, `aapt`, or `androguard`
  to install.
* **Defensive** — built for app authors, reviewers, and CI to catch leaks *before*
  shipping. It reports exposure; it does not attack anything.

```
$ apkinspect app.apk
----------------------------------------------------------------
  APKInspect security report
----------------------------------------------------------------
  File       : app.apk
  Type       : APK   Size: 7.31 MiB   Entries: 412
  Package    : com.example.app  v1.4.2 (1042)
  SAFETY SCORE   42/100  [##########..............]  grade D  (high risk)
  Findings      Critical: 1  High: 3  Medium: 5  Low: 6
  ...
```

## Run it — no command line needed

APKInspect ships a polished **local web app**: drag in an APK/AAB to get an animated safety
score, colour-coded findings, and a built-in **Threat Book** that explains every issue and
exactly how to block it. Everything runs on `127.0.0.1` — **no file ever leaves your machine.**

* **Windows** — double-click **`APKInspect.cmd`**. If Python is missing it installs it for
  you, then opens the app in your browser. (It creates an icon **in this folder** — never on
  your Desktop.)
* **macOS** — double-click **`APKInspect.command`** (first time only: right-click → **Open**
  to clear Gatekeeper). It builds an **`APKInspect.app`** with the real icon.
* **Linux** — run **`./APKInspect.command`** from a terminal.

No sample handy? Click **“try a sample scan”** on the drop zone.

| Scanner | Threat Book |
|---|---|
| ![Scanner view](assets/screenshots/scanner.png) | ![Threat Book](assets/screenshots/threat-book.png) |

![Results view](assets/screenshots/results.png)

## Install

**The only requirement is Python 3.8 or newer.** There are *no* third-party packages.
Get Python from [python.org/downloads](https://www.python.org/downloads/) (on Windows, tick
*“Add Python to PATH”*).

You have two ways to set it up:

* **Click and go** — double-click **`APKInspect.cmd`** (Windows). It downloads Python for you
  if it's missing and runs straight from the folder. Nothing else to install.
* **Install it yourself** — double-click **`Install APKInspect.cmd`** (Windows), or run
  `pip install .` on any OS. This adds the `apkinspect` and `apkinspect-gui` commands so you
  can run them from any terminal.

Or run it from the folder without installing anything:

```bash
python  -m apkinspect path/to/app.apk     # Windows
python3 -m apkinspect path/to/app.apk     # macOS / Linux
python  -m apkinspect.web                 # graphical app
```

### CLI options

| Option | Purpose |
|---|---|
| `--json` / `--sarif` | Machine-readable output (SARIF 2.1.0 for GitHub code scanning / SAST tooling). |
| `--quiet` / `--no-color` | Trim output / disable ANSI colour. |
| `--no-secrets` | Skip the secret/API-key sweep (faster). |
| `--min-score N` | **CI gate:** exit non-zero if any file scores below `N`. |
| `--fail-on SEV` | **CI gate:** exit non-zero on any finding at/above `CRITICAL\|HIGH\|MEDIUM\|LOW`. |
| `--baseline FILE` / `--write-baseline FILE` | Suppress accepted findings; gate only on **new** issues. |
| `-o FILE` | Write the report to a file. |

Exit codes: `0` ok · `1` a CI gate failed · `2` a file could not be scanned. Full list: `apkinspect --help`.

```bash
# Fail a pipeline if any build scores under 70 or has a HIGH+ issue
apkinspect build/*.apk --min-score 70 --fail-on HIGH
```

## What it checks

Every check has a stable `id` and is exercised by an automated test.

* **Hard-coded secrets & exposed backends** (`secrets.py`) — AWS/GCP/Stripe/GitHub/Slack/
  Twilio/OpenAI keys, **Firebase Realtime DB URLs**, DB connection strings, and more, swept
  across DEX, `resources.arsc`, `assets/`, native libs, and manifest meta-data. Secret values
  are **redacted** in the report.
* **Exported components & deep links** (`manifest.py`) — activities/services/receivers/
  **providers** reachable by any app, and BROWSABLE intent-filters accepting cleartext
  `http://` web links (deep-link hijacking / MITM).
* **Config & network posture** (`manifest.py`, `nsc.py`) — `debuggable`, `usesCleartextTraffic`,
  `allowBackup`, plus the compiled **network-security-config** (cleartext / user-CA trust).
* **App signing** (`signing.py`) — Android **debug certificate**, weak **MD5/SHA-1** algorithms,
  RSA keys **< 2048 bits**, and **v1-only** signing (Janus / CVE-2017-13156).
* **Dangerous permissions** (`permissions.py`) — runtime-dangerous and powerful permissions,
  each with a severity and rationale.

## Scoring

A perfect app starts at **100**; each finding multiplies the score by `(1 - impact)`, where
impact scales with severity and repeated findings in a category decay so a long tail of minor
issues can't underflow the score.

| score | grade | risk |
|---|---|---|
| 90–100 | A | minimal |
| 75–89 | B | low |
| 60–74 | C | moderate |
| 40–59 | D | high |
| 0–39 | F | critical |

## Develop & test

97 unit/integration tests build **synthetic APK/AAB archives with planted issues** and assert
that every check fires. CI runs them on Python 3.8–3.12.

```bash
python -m unittest discover -s tests -v   # run the suite
python tools/make_samples.py              # generate samples/{vulnerable,clean}.apk + .aab
python -m apkinspect samples/vulnerable.apk
```

## Limitations

* **Static analysis** flags the *presence/exposure* of issues, not proven exploitability —
  a flagged Firebase URL or exported component may be intentional and safe; verify it.
* **AAB manifests are best-effort** (protobuf-decoded generically).
* **Signing analysis reads, it does not verify** — it inspects the v1 certificate's fields and
  detects a v2/v3 block, but does not cryptographically verify signatures.

## License

MIT — see [LICENSE](LICENSE).
