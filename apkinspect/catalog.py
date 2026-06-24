"""The threat catalogue: the encyclopedia behind the "Threat Book" in the GUI
and the single source of truth for what each finding means and how to fix it.

Each entry maps one or more finding ``ids`` (as produced by the scanner) to a
plain-language explanation:

* ``what``   - what the issue is
* ``risk``   - why it is dangerous / what an attacker can do
* ``detect`` - how APKInspect finds it
* ``block``  - how to fix or block it
"""
from __future__ import annotations

SEVERITY_META = {
    "CRITICAL": {"label": "Critical", "color": "#ff4d6d", "order": 0},
    "HIGH": {"label": "High", "color": "#ff8c42", "order": 1},
    "MEDIUM": {"label": "Medium", "color": "#ffd166", "order": 2},
    "LOW": {"label": "Low", "color": "#4cc9f0", "order": 3},
    "INFO": {"label": "Info", "color": "#9aa5b1", "order": 4},
}

CATEGORY_META = {
    "secret": {"label": "Secrets & Keys", "icon": "key"},
    "component": {"label": "Exported Components", "icon": "door"},
    "network": {"label": "Network & Backends", "icon": "globe"},
    "config": {"label": "Build Configuration", "icon": "gear"},
    "permission": {"label": "Permissions", "icon": "shield"},
    "signing": {"label": "App Signing", "icon": "badge"},
}

THREATS: list[dict] = [
    # ---------------------------------------------------------------- secrets
    {
        "key": "private-key", "ids": ["SECRET_PRIVATE_KEY"],
        "title": "Embedded private key", "severity": "CRITICAL", "category": "secret",
        "what": "A PEM-encoded private key (RSA/EC/DSA/OpenSSH/PGP) is shipped inside the app.",
        "risk": "Anyone can unzip the APK and extract the key, then impersonate your servers, "
                "decrypt traffic, forge signatures, or sign malicious updates.",
        "detect": "APKInspect scans every packaged file for '-----BEGIN ... PRIVATE KEY-----' blocks.",
        "block": "Never bundle private keys. Rotate the exposed key immediately and move all "
                 "signing/decryption to a server you control; the app should only hold public keys.",
    },
    {
        "key": "gcp-sa", "ids": ["SECRET_GCP_SERVICE_ACCOUNT"],
        "title": "Google service-account JSON", "severity": "CRITICAL", "category": "secret",
        "what": "A Google Cloud service-account credential file is embedded in the app.",
        "risk": "Service accounts often have broad backend permissions; a leaked one can read/write "
                "your cloud storage, databases and other GCP resources.",
        "detect": "We look for the '\"type\": \"service_account\"' marker in bundled JSON.",
        "block": "Delete the credential from the bundle, rotate the key in IAM, and have the device "
                 "authenticate as the user (Firebase Auth / OAuth) rather than as a service account.",
    },
    {
        "key": "aws", "ids": ["SECRET_AWS_ACCESS_KEY_ID", "SECRET_AWS_SECRET_KEY"],
        "title": "AWS credentials", "severity": "CRITICAL", "category": "secret",
        "what": "An AWS access key id (AKIA…) and/or secret access key is hard-coded in the app.",
        "risk": "Attackers can use the keys to access S3 buckets, spin up resources on your bill, "
                "or pivot deeper into your AWS account.",
        "detect": "We match the AKIA/ASIA key-id format and context-gated 40-char secret keys.",
        "block": "Rotate the key in IAM now. Use short-lived STS credentials via Cognito, or proxy "
                 "AWS calls through your backend so long-lived keys never reach the client.",
    },
    {
        "key": "stripe", "ids": ["SECRET_STRIPE_LIVE"],
        "title": "Stripe live secret key", "severity": "CRITICAL", "category": "secret",
        "what": "A live Stripe secret key (sk_live_/rk_live_) is present in the app.",
        "risk": "The secret key can create charges, issue refunds and read customer data. Only the "
                "publishable key (pk_) is safe on a client.",
        "detect": "We match the sk_live_/rk_live_ key prefixes.",
        "block": "Roll the key in the Stripe dashboard immediately and keep all secret-key calls "
                 "on your server.",
    },
    {
        "key": "sendgrid", "ids": ["SECRET_SENDGRID"],
        "title": "SendGrid API key", "severity": "CRITICAL", "category": "secret",
        "what": "A SendGrid mail API key is embedded in the app.",
        "risk": "Attackers can send mail as your domain (phishing/spam) and harm your sender reputation.",
        "detect": "We match the 'SG.xxxx.yyyy' key shape.",
        "block": "Revoke and recreate the key, and send mail from a backend service only.",
    },
    {
        "key": "github", "ids": ["SECRET_GITHUB_TOKEN"],
        "title": "GitHub token", "severity": "CRITICAL", "category": "secret",
        "what": "A GitHub personal/OAuth/app token (ghp_/gho_/ghu_/ghs_/ghr_) is bundled.",
        "risk": "Depending on scope, it grants read/write to your repositories and CI secrets.",
        "detect": "We match the ghX_ token prefixes followed by 36 characters.",
        "block": "Revoke the token on GitHub immediately and audit recent activity.",
    },
    {
        "key": "google-api", "ids": ["SECRET_GOOGLE_API_KEY"],
        "title": "Google API key", "severity": "HIGH", "category": "secret",
        "what": "A Google API key (AIza…) is present — commonly for Maps, Places or Firebase.",
        "risk": "An unrestricted key can be lifted and used to rack up billable API calls on your "
                "project, or abuse enabled services.",
        "detect": "We match the 'AIza' + 35-char key format across files and manifest meta-data.",
        "block": "In Google Cloud Console restrict the key by application (package + signing cert) "
                 "and by API. Restricted keys are safe to ship; unrestricted ones are not.",
    },
    {
        "key": "fcm", "ids": ["SECRET_FCM_SERVER_KEY"],
        "title": "Firebase Cloud Messaging server key", "severity": "HIGH", "category": "secret",
        "what": "A legacy FCM server key is embedded in the app.",
        "risk": "Anyone with the key can send push notifications to all of your users.",
        "detect": "We match the legacy 'AAAA…:…' FCM server-key shape.",
        "block": "Rotate the key and migrate to the FCM HTTP v1 API, which authenticates with "
                 "short-lived OAuth tokens issued server-side.",
    },
    {
        "key": "firebase-db", "ids": ["SECRET_FIREBASE_DB_URL"],
        "title": "Firebase Realtime Database exposure", "severity": "HIGH", "category": "network",
        "what": "A Firebase Realtime Database URL (…firebaseio.com / …firebasedatabase.app) is present.",
        "risk": "If the database security rules are open (a very common mistake), anyone who reads "
                "this URL can dump or overwrite your entire dataset — no app required.",
        "detect": "We extract the database URL and surface it in full so you can test it.",
        "block": "Open '<db-url>/.json' in a browser: if you see data, your rules are public. Lock "
                 "rules to 'auth != null' (or stricter) and never rely on the URL being secret.",
    },
    {
        "key": "firebase-storage", "ids": ["SECRET_FIREBASE_STORAGE"],
        "title": "Cloud Storage bucket exposure", "severity": "MEDIUM", "category": "network",
        "what": "A Firebase Storage / Google Cloud Storage bucket reference is present.",
        "risk": "Misconfigured Storage rules let anyone download (or upload) user files.",
        "detect": "We match appspot.com / firebasestorage.app bucket hosts.",
        "block": "Require authentication in Storage rules and scope access per-user/path.",
    },
    {
        "key": "slack", "ids": ["SECRET_SLACK_TOKEN", "SECRET_SLACK_WEBHOOK"],
        "title": "Slack token / webhook", "severity": "HIGH", "category": "secret",
        "what": "A Slack API token (xox…) or incoming-webhook URL is embedded.",
        "risk": "Tokens can read/post in your workspace; webhook URLs let anyone post into a channel.",
        "detect": "We match xox[baprs]- tokens and hooks.slack.com webhook URLs.",
        "block": "Revoke the token / regenerate the webhook in Slack admin and keep them server-side.",
    },
    {
        "key": "twilio", "ids": ["SECRET_TWILIO_KEY"],
        "title": "Twilio key", "severity": "HIGH", "category": "secret",
        "what": "A Twilio API key (SK…) is embedded in the app.",
        "risk": "Attackers can place billable calls and send SMS through your account.",
        "detect": "We match the 'SK' + 32 hex-char key format.",
        "block": "Rotate the Twilio key and route messaging through your backend.",
    },
    {
        "key": "mailgun", "ids": ["SECRET_MAILGUN"],
        "title": "Mailgun key", "severity": "HIGH", "category": "secret",
        "what": "A Mailgun API key (key-…) is embedded.",
        "risk": "Allows sending mail as your domain and reading mail logs.",
        "detect": "We match the 'key-' + 32-char format.",
        "block": "Rotate the key and send mail only from a backend.",
    },
    {
        "key": "google-oauth", "ids": ["SECRET_GOOGLE_OAUTH"],
        "title": "Google OAuth client id", "severity": "LOW", "category": "secret",
        "what": "A Google OAuth client id (…apps.googleusercontent.com) is present.",
        "risk": "Client ids are public by design and low-risk — but a matching client *secret* must "
                "never be shipped alongside it.",
        "detect": "We surface the client id so you can confirm no secret accompanies it.",
        "block": "Use an Android OAuth client (no secret) configured with your signing certificate.",
    },
    {
        "key": "jwt", "ids": ["SECRET_JWT"],
        "title": "JSON Web Token", "severity": "LOW", "category": "secret",
        "what": "A JWT (eyJ….eyJ….…) is embedded in the app.",
        "risk": "If it is a long-lived or privileged token it can be replayed to access APIs as that "
                "identity; many JWTs, however, are harmless config.",
        "detect": "We match the three base64url segments of a JWT.",
        "block": "Avoid shipping bearer tokens; if one is required keep its lifetime short and rotate it.",
    },
    {
        "key": "generic-cred", "ids": ["SECRET_HARDCODED_CREDENTIAL"],
        "title": "Hard-coded credential", "severity": "MEDIUM", "category": "secret",
        "what": "A high-entropy value is assigned to a key/secret/password/token variable in the code.",
        "risk": "Embedded credentials are trivially extracted from the APK and reused by attackers.",
        "detect": "We match 'api_key=/secret=/password=' patterns and keep only values that look "
                  "random (placeholders and low-entropy strings are filtered out).",
        "block": "Move secrets out of the binary: fetch them at runtime over an authenticated channel, "
                 "or use a server-side proxy. Do not just obfuscate — that only slows attackers down.",
    },
    {
        "key": "llm-keys", "ids": ["SECRET_OPENAI_KEY", "SECRET_ANTHROPIC_KEY"],
        "title": "LLM provider API key", "severity": "HIGH", "category": "secret",
        "what": "An OpenAI (sk-…) or Anthropic (sk-ant-…) API key is embedded in the app.",
        "risk": "These keys are billed per token; a leaked key lets anyone run inference on your "
                "account and exhaust your quota or budget.",
        "detect": "We match the provider-specific 'sk-'/'sk-ant-' key prefixes.",
        "block": "Revoke the key in the provider console and proxy all model calls through a backend "
                 "that holds the key server-side.",
    },
    {
        "key": "azure-storage", "ids": ["SECRET_AZURE_STORAGE_KEY"],
        "title": "Azure Storage account key", "severity": "HIGH", "category": "secret",
        "what": "An Azure Storage 'AccountKey=…' shared key is present in the app.",
        "risk": "The account key grants full read/write to the storage account's blobs, tables and "
                "queues.",
        "detect": "We match the base64 'AccountKey=' value in a connection string.",
        "block": "Rotate the key in Azure and use short-lived SAS tokens or managed identity instead.",
    },
    {
        "key": "square", "ids": ["SECRET_SQUARE_TOKEN"],
        "title": "Square access token", "severity": "HIGH", "category": "secret",
        "what": "A Square access token (sq0atp-/sq0csp-/EAAA…) is embedded in the app.",
        "risk": "Square tokens can read transactions and move money through your account.",
        "detect": "We match the Square token prefixes.",
        "block": "Revoke the token in the Square developer dashboard and keep it server-side.",
    },
    {
        "key": "npm", "ids": ["SECRET_NPM_TOKEN"],
        "title": "npm access token", "severity": "HIGH", "category": "secret",
        "what": "An npm automation/publish token (npm_…) is bundled in the app.",
        "risk": "Depending on scope it can publish or yank packages and read private registries.",
        "detect": "We match the 'npm_' + 36-char token format.",
        "block": "Revoke it with 'npm token revoke' and keep tokens out of shipped artifacts.",
    },
    {
        "key": "db-uri", "ids": ["SECRET_DB_CONNECTION_STRING"],
        "title": "Database connection string", "severity": "HIGH", "category": "secret",
        "what": "A database URI with an embedded username and password (postgres/mysql/mongodb/redis) "
                "is present in the app.",
        "risk": "Anyone extracting it can connect directly to your database and read or destroy data.",
        "detect": "We match 'scheme://user:pass@host' connection strings.",
        "block": "Never let a client talk to the database directly — put a backend API in front and "
                 "rotate the exposed credentials.",
    },
    # -------------------------------------------------------------- components
    {
        "key": "exported", "ids": ["COMPONENT_EXPORTED"],
        "title": "Exported component without permission", "severity": "HIGH", "category": "component",
        "what": "An activity, service, receiver or content provider is reachable by other apps with no "
                "permission check (set explicitly via android:exported, or implicitly by declaring an "
                "intent-filter).",
        "risk": "Any installed app can invoke it — launching internal screens, sending crafted intents, "
                "or (for providers) reading/writing your data directly.",
        "detect": "We evaluate each component's exported state and whether a guarding permission exists; "
                  "the launcher entry point is excluded as it is meant to be public.",
        "block": "Set android:exported=\"false\" for anything that does not need to be public. If it "
                 "must be exported, guard it with a signature-level android:permission and validate "
                 "every incoming intent / URI.",
    },
    {
        "key": "http-deeplink", "ids": ["COMPONENT_HTTP_DEEPLINK"],
        "title": "Cleartext http:// deep link", "severity": "HIGH", "category": "component",
        "what": "A BROWSABLE intent-filter accepts the 'http' scheme, so the activity opens from web "
                "links over unencrypted HTTP.",
        "risk": "A network attacker can tamper with the link/response (MITM), and other apps can hijack "
                "the deep link to feed your activity malicious data.",
        "detect": "We inspect intent-filters for BROWSABLE + an 'http' <data> scheme.",
        "block": "Use https only, enable Android App Links with android:autoVerify=\"true\", and validate "
                 "all data carried by the incoming intent.",
    },
    {
        "key": "provider-granturi", "ids": ["COMPONENT_PROVIDER_GRANTURI"],
        "title": "Exported provider grants URI permissions", "severity": "MEDIUM", "category": "component",
        "what": "An unprotected exported content provider sets grantUriPermissions=\"true\".",
        "risk": "Combined with weak path rules, other apps may be granted access to arbitrary files or "
                "database rows behind the provider.",
        "detect": "We flag exported providers with grantUriPermissions and no guarding permission.",
        "block": "Require a permission, and scope <grant-uri-permission> / <path-permission> entries as "
                 "narrowly as possible.",
    },
    {
        "key": "exported-perm", "ids": ["COMPONENT_EXPORTED_WEAKPERM", "COMPONENT_EXPORTED_PERM"],
        "title": "Exported component with weak permission", "severity": "LOW", "category": "component",
        "what": "A component is exported and guarded by a permission, but the permission is normal/"
                "dangerous level (any app can request it) or its level could not be confirmed.",
        "risk": "Normal/dangerous permissions are granted freely, so the guard provides little real "
                "protection against other apps.",
        "detect": "We resolve the protectionLevel of the guarding permission declared in the manifest.",
        "block": "Use a signature-level custom permission so only apps signed with your key can call it.",
    },
    # ------------------------------------------------------------------ config
    {
        "key": "debuggable", "ids": ["MANIFEST_DEBUGGABLE"],
        "title": "Debuggable application", "severity": "HIGH", "category": "config",
        "what": "android:debuggable=\"true\" is set on the application.",
        "risk": "Anyone can attach a debugger (jdwp) to the running app on any device, read memory, and "
                "execute code in its context — a serious leak if it reaches production.",
        "detect": "We read the debuggable flag from the application element.",
        "block": "Remove the flag for release builds (the release build type already defaults to false).",
    },
    {
        "key": "allowbackup", "ids": ["MANIFEST_ALLOWBACKUP", "MANIFEST_ALLOWBACKUP_DEFAULT"],
        "title": "Backups allowed", "severity": "MEDIUM", "category": "config",
        "what": "android:allowBackup is true or left unset (which defaults to true).",
        "risk": "App private data can be copied off the device via 'adb backup' or cloud backup, "
                "exposing tokens and databases on an unlocked/rooted device.",
        "detect": "We read allowBackup and flag it when not explicitly disabled.",
        "block": "Set android:allowBackup=\"false\", or define dataExtractionRules/fullBackupContent to "
                 "exclude sensitive files.",
    },
    {
        "key": "cleartext", "ids": ["MANIFEST_CLEARTEXT", "MANIFEST_CLEARTEXT_DEFAULT"],
        "title": "Cleartext (HTTP) traffic", "severity": "MEDIUM", "category": "network",
        "what": "The app permits unencrypted HTTP — explicitly (usesCleartextTraffic=\"true\") or by "
                "default (targetSdk < 28 with no network security config).",
        "risk": "Traffic can be read and modified by anyone on the network path (public Wi-Fi, rogue "
                "router), enabling credential theft and content injection.",
        "detect": "We read usesCleartextTraffic, targetSdkVersion and the presence of a network config.",
        "block": "Use HTTPS everywhere. Add a network security config that disables cleartext, and "
                 "raise targetSdkVersion so the secure default applies.",
    },
    {
        "key": "testonly", "ids": ["MANIFEST_TESTONLY"],
        "title": "Test-only build", "severity": "LOW", "category": "config",
        "what": "android:testOnly=\"true\" marks the build as not intended for distribution.",
        "risk": "Test-only apps relax some protections and should never ship to users.",
        "detect": "We read the testOnly flag.",
        "block": "Remove android:testOnly for production builds.",
    },
    {
        "key": "old-minsdk", "ids": ["MANIFEST_OLD_MINSDK"],
        "title": "Low minimum SDK", "severity": "LOW", "category": "config",
        "what": "minSdkVersion is below 24, so the app runs on old Android releases.",
        "risk": "Older platforms miss modern mitigations (scoped storage, stricter TLS, runtime "
                "permissions enforcement), widening the attack surface.",
        "detect": "We read minSdkVersion from <uses-sdk>.",
        "block": "Raise minSdkVersion as far as your audience allows.",
    },
    # ------------------------------------------------------------- permissions
    {
        "key": "dangerous-permission", "ids": ["PERMISSION_DANGEROUS"],
        "title": "Sensitive permission requested", "severity": "MEDIUM", "category": "permission",
        "what": "The app requests a privacy-sensitive or powerful permission (e.g. SYSTEM_ALERT_WINDOW, "
                "REQUEST_INSTALL_PACKAGES, READ_SMS, location, camera, microphone).",
        "risk": "Each such permission expands what the app — or an attacker who compromises it — can do, "
                "from reading 2FA SMS to drawing tap-jacking overlays or installing other APKs.",
        "detect": "We compare requested permissions against a curated catalogue, each with its own "
                  "severity and rationale.",
        "block": "Request only what you genuinely need, prefer narrower alternatives (e.g. photo picker "
                 "instead of broad storage), and request at runtime with clear justification.",
    },
    # --------------------------------------------------------- network config
    {
        "key": "nsc-cleartext", "ids": ["NETWORK_NSC_CLEARTEXT"],
        "title": "Network security config permits cleartext", "severity": "MEDIUM", "category": "network",
        "what": "The app's network security config sets cleartextTrafficPermitted=\"true\" for a "
                "base-config or domain-config.",
        "risk": "Cleartext HTTP can be read and modified by anyone on the network path, even on Android "
                "9+ where it is off by default.",
        "detect": "We locate and parse the compiled network-security-config and read its cleartext flag.",
        "block": "Set cleartextTrafficPermitted=\"false\" and use HTTPS; scope any unavoidable exception "
                 "to a single domain.",
    },
    {
        "key": "nsc-user-ca", "ids": ["NETWORK_NSC_USER_CA"],
        "title": "Trusts user-installed CAs", "severity": "MEDIUM", "category": "network",
        "what": "The network security config trust-anchors include <certificates src=\"user\"/>.",
        "risk": "Trusting user-added CAs lets anyone who can install a certificate on the device "
                "intercept the app's TLS traffic (man-in-the-middle).",
        "detect": "We parse the config's trust-anchors and flag a 'user' certificate source outside "
                  "debug-overrides.",
        "block": "Trust only the system CA store (src=\"system\") in production; relax trust for local "
                 "debugging inside a <debug-overrides> block instead.",
    },
    # ---------------------------------------------------------------- signing
    {
        "key": "signing-debug", "ids": ["SIGNING_DEBUG_CERT"],
        "title": "Signed with the Android debug key", "severity": "HIGH", "category": "signing",
        "what": "The APK is signed with the public Android debug certificate (CN=Android Debug).",
        "risk": "The debug key is well known and shared, so anyone can re-sign a tampered build with the "
                "same identity — defeating update integrity and any signature-level permission.",
        "detect": "We read the signer certificate's subject from the v1 signature (or scan for the debug "
                  "subject in the signing block).",
        "block": "Sign release builds with a private release keystore; never ship a debug-signed APK.",
    },
    {
        "key": "signing-weak-algo", "ids": ["SIGNING_WEAK_ALGORITHM"],
        "title": "Weak certificate signature algorithm", "severity": "MEDIUM", "category": "signing",
        "what": "The signing certificate uses an MD5- or SHA-1-based signature algorithm.",
        "risk": "MD5/SHA-1 are collision-prone and deprecated, weakening the trust in the certificate.",
        "detect": "We read the certificate's signatureAlgorithm OID from the v1 PKCS#7 block.",
        "block": "Re-issue the signing certificate with SHA-256 or stronger.",
    },
    {
        "key": "signing-short-key", "ids": ["SIGNING_SHORT_KEY"],
        "title": "Short signing key", "severity": "MEDIUM", "category": "signing",
        "what": "The signing key is an RSA key shorter than 2048 bits.",
        "risk": "Short RSA keys are easier to factor, undermining the integrity guarantee of the signature.",
        "detect": "We read the RSA modulus size from the signer certificate's public key.",
        "block": "Use an RSA key of at least 2048 bits, or an elliptic-curve P-256 key.",
    },
    {
        "key": "signing-v1-only", "ids": ["SIGNING_V1_ONLY"],
        "title": "Legacy v1-only signing", "severity": "MEDIUM", "category": "signing",
        "what": "The APK has only a v1 (JAR) signature; no APK Signature Scheme v2/v3 block is present.",
        "risk": "v1-only signing is malleable (e.g. the Janus vulnerability, CVE-2017-13156) and gives "
                "weaker tamper protection than whole-file v2+ signing.",
        "detect": "We check for the 'APK Sig Block 42' signing block alongside the META-INF v1 signature.",
        "block": "Enable APK Signature Scheme v2+ — it is the default in current Android build tooling.",
    },
]

_BY_ID: dict[str, dict] = {}
for _t in THREATS:
    for _i in _t["ids"]:
        _BY_ID[_i] = _t


def for_finding_id(finding_id: str) -> dict | None:
    """Return the catalogue entry that explains a given finding id."""
    return _BY_ID.get(finding_id)


def as_payload() -> dict:
    """JSON-serialisable catalogue for the web UI."""
    return {
        "threats": THREATS,
        "severities": SEVERITY_META,
        "categories": CATEGORY_META,
    }
