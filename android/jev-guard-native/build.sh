#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-/tmp/jev-sdk}}"
BT="$SDK/build-tools/35.0.0"
ANDROID="$SDK/platforms/android-35/android.jar"
mkdir -p build/classes build/dex
"$BT/aapt2" compile --dir app/src/main/res -o build/resources.zip
"$BT/aapt2" link -o build/resources.apk -I "$ANDROID" --manifest app/src/main/AndroidManifest.xml --min-sdk-version 28 --target-sdk-version 35 build/resources.zip
java com.sun.tools.javac.Main -encoding UTF-8 -source 8 -target 8 -Xlint:-options -classpath "$ANDROID" -d build/classes app/src/main/java/ai/jevguard/*.java
java sun.tools.jar.Main cf build/classes.jar -C build/classes .
"$BT/d8" --lib "$ANDROID" --min-api 28 --output build/dex build/classes.jar
cp build/resources.apk build/unsigned.apk
(cd build/dex && zip -q ../unsigned.apk classes.dex)
"$BT/zipalign" -f -p 4 build/unsigned.apk build/aligned.apk
if [ ! -f development-signing.jks ]; then
 keytool -genkeypair -keystore development-signing.jks -storepass android -keypass android -alias jevguard -keyalg RSA -keysize 3072 -validity 10000 -dname 'CN=Jev Guard Personal Preview' >/dev/null 2>&1
fi
"$BT/apksigner" sign --ks development-signing.jks --ks-key-alias jevguard --ks-pass pass:android --key-pass pass:android --out build/Jev-Guard-0.1.0.apk build/aligned.apk
"$BT/apksigner" verify --verbose build/Jev-Guard-0.1.0.apk
"$BT/aapt" dump badging build/Jev-Guard-0.1.0.apk | head -15
