# Verification — Jev Guard 0.1.0

## Build checks

- Compiled all Java sources against Android API 35 using Java 17.
- Converted bytecode with Android D8, minimum API 28.
- APK aligned with zipalign and verified with apksigner (v3 signing, one signer).
- APK manifest inspected: package ai.jevguard, version 0.1.0, min API 28, target API 35, launchable MainActivity.
- Declared permissions: INTERNET and QUERY_ALL_PACKAGES only. No storage, microphone, location, accessibility-service, install-packages, or device-admin permission requested by Jev Guard.
- Backup disabled; cleartext network traffic disabled; no credentials embedded.

## Core checks

16 JVM checks passed covering:

- Absent capability flags do not fabricate findings.
- Contacts-plus-network combination is recognized.
- Unknown, engine detection, suspicious, and zero-detection outcomes remain distinct.
- Reduced Jev evidence excludes hashes, labels, certificates and arbitrary key fields.
- Request includes the unknown/insufficient-evidence branch.
- Documented Jev response fields parse correctly.
- Unexpected labels, invalid confidence and invalid distributions fail closed.
- VirusTotal engine counts are preserved; missing statistics fail closed.

## Live services

No user API credentials were supplied. Actual successful Jev and VirusTotal calls were not tested. Request and response contracts were checked against the providers' documentation. This release does not claim malware-detection efficacy or false-positive validation.

## Device validation

Passed on an Android 11 / API 30 x86_64 emulator using software emulation:

- Signed APK installed successfully.
- Package metadata, SHA-256, certificate identity and requested permissions parsed from the installed APK.
- Android Keystore encryption/decryption and key removal worked.
- Invalid APK data was rejected.
- Reports saved successfully.
- Scan, Apps, History and Settings screens opened without a test failure.

This is a smoke test, not comprehensive device or security testing. The user's physical phone, Android 16, live API authentication and real malware efficacy were not tested.

The final screenshot was obstructed by a System UI “not responding” dialog in the slow software emulator. The app-specific instrumentation checks passed, and no AndroidRuntime crash was logged. Visual review on a physical device remains recommended.
