#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
adb install --no-incremental -r app/build/outputs/apk/debug/app-debug.apk
adb install --no-incremental -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
# Permission is granted only to this disposable CI emulator.
adb shell appops set app.veil.vpn ACTIVATE_VPN allow
mkdir -p app/build/device-results
adb shell am instrument -w app.veil.vpn.test/app.veil.vpn.DeviceChecks | tee app/build/device-results/result.txt
grep -q 'DEVICE CHECKS PASSED' app/build/device-results/result.txt
