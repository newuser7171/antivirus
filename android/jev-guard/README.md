# Jev Guard for Android

Experimental Android companion to the Jev antivirus project.

## Current MVP
- Native Android APK picker
- Local streaming SHA-256 calculation
- No broad storage permission required
- Cloud/reputation status is explicitly reported as UNKNOWN when unavailable

## Build
Open `android/jev-guard` in Android Studio, let Gradle sync, then build the debug APK.

Command-line builds can use `./gradlew assembleDebug` once a Gradle wrapper is generated/committed.

## Next
Add APK metadata/signature inspection, local heuristics, scan history, Android Keystore-backed secrets, optional VirusTotal hash lookup, and optional Jev/TypeSafe analysis.

> Jev Guard is experimental and does not replace Android/Google Play Protect or a full endpoint security product.
