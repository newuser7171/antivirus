#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
SDK="${ANDROID_SDK_ROOT:-/tmp/jev-sdk}"
BT="$SDK/build-tools/35.0.0"
ANDROID="$SDK/platforms/android-35/android.jar"
mkdir -p build/device-classes build/device-dex
java com.sun.tools.javac.Main -source 8 -target 8 -cp "$ANDROID:build/classes" -d build/device-classes tests/device/DeviceChecks.java
java sun.tools.jar.Main cf build/device-tests.jar -C build/device-classes .
"$BT/d8" --lib "$ANDROID" --classpath build/classes.jar --min-api 28 --output build/device-dex build/device-tests.jar
"$BT/aapt2" link -o build/test-res.apk -I "$ANDROID" --manifest tests/device/AndroidManifest.xml
cp build/test-res.apk build/test-unsigned.apk
(cd build/device-dex && zip -q ../test-unsigned.apk classes.dex)
"$BT/zipalign" -f 4 build/test-unsigned.apk build/test-aligned.apk
"$BT/apksigner" sign --ks development-signing.jks --ks-pass pass:android --key-pass pass:android --out build/device-tests.apk build/test-aligned.apk
