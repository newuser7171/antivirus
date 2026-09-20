#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
adb install --no-incremental -r app/build/outputs/apk/debug/app-debug.apk
adb install --no-incremental -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
mkdir -p build
adb shell am instrument -w ai.jevguard.test/ai.jevguard.DeviceChecks | tee build/device-result.txt
grep -q 'PASS: device' build/device-result.txt
