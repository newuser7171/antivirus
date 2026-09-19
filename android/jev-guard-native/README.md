# Jev Guard — Android personal preview 0.1.0

A native Android APK inspection app with optional Jev/TypeSafe evidence review and VirusTotal hash reputation lookup. Android 9 (API 28) or later; target API 35. No bundled API credentials, ads, analytics, or backend.

## Install and use

1. Download [Jev-Guard-0.1.0.apk](downloads/Jev-Guard-0.1.0.apk?raw=true) and open it on your Android phone and allow installation from the browser/file app if Android requests it.
2. Open Jev Guard → Choose an APK, or Apps → select an installed application.
3. Local inspection works immediately without an account.
4. For Jev review, add your TypeSafe API key under Settings. For reputation lookup, add your own VirusTotal API key. Keys are not interchangeable. Provider access and quotas apply.
5. Open a report and choose its separate cloud-check button. Each request shows what will be sent and asks for confirmation.
6. Open History to revisit results, export JSON reports, or clear local scan history.

## What this version does

- Parses Android APK metadata using Android PackageManager.
- Calculates SHA-256, lists requested permissions, certificate fingerprints, version and target SDK.
- Flags declared capabilities for manual review. Permissions are not evidence of granted access or observed activity.
- Lists installed applications, including an optional system-app filter.
- Looks up an existing VirusTotal report by SHA-256. Never uploads APK bytes.
- Sends a reduced metadata/evidence summary to Jev, using `jev-latest`, for a three-way review-priority judgment. Shows model confidence separately from malware risk.
- Stores at most 50 reports privately on-device. Encrypts personal API keys using Android Keystore AES-GCM. Android backups are disabled.

## Limits

This is an experimental inspection tool, not a validated antivirus product or a replacement for Android's built-in protection. It does not inspect executable behavior, independently verify APK signature integrity, monitor installations, block malicious processes, scan private data, automatically remove apps, or prove a file safe. Certificate identity is not a publisher trust check. Unknown/error results never become clean results. Jev confidence is not malware probability.

Installed applications are inspected one at a time. For split installations, only the base APK is inspected and a partial-coverage note is shown. Select single `.apk` files, not `.xapk`, `.apks`, or `.aab` bundles. APK inspection is limited to 300 MiB per file.

No live provider request has been validated with an account key during development. Add your keys to test access. Authentication, timeout, rate-limit, malformed-response and unknown-hash states are handled without fabricating successful results. There is no automatic retry loop; use the button again after a rate limit subsides. Refreshing VirusTotal clears the older Jev assessment so it can be rerun with current evidence.

## Rebuild

Install Java 17 and the Android command-line tools. Accept the SDK licenses, then install:

```
sdkmanager 'platforms;android-35' 'build-tools;35.0.0'
export ANDROID_SDK_ROOT=/path/to/android-sdk
./build.sh
```

The dependency-free build uses Android's aapt2, D8, zipalign and apksigner. Output: `build/Jev-Guard-0.1.0.apk`. Signing keys are deliberately excluded from GitHub. The build creates a new local development key on first use. Reuse your original private signing key locally if you need in-place updates to the downloadable preview; otherwise Android requires uninstalling the old build before installing a differently signed one.

To publish a production product, first establish malware-detection validation, harden parsing and background lifecycle handling, obtain suitable API licensing, and use a separate private production signing identity. QUERY_ALL_PACKAGES is declared for the installed-app inspection feature; store distribution has its own eligibility requirements.

## Tests

`tests/CoreTests.java` covers capability rules, evidence minimization, missing/malformed API data, engine verdict distinctions, and Jev response parsing. It runs against the JVM `org.json` implementation (only a test dependency, not bundled in the APK).

See `VERIFICATION.md` for the validation performed on this build.

## API references

- TypeSafe: https://docs.typesafe.ai/api
- Choice primitive: https://docs.typesafe.ai/primitives/choice
- VirusTotal file reports: https://docs.virustotal.com/reference/file-info
- Android PackageManager: https://developer.android.com/reference/android/content/pm/PackageManager

Independent project; not affiliated with TypeSafe or VirusTotal.
