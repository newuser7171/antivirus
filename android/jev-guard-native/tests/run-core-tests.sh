#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build/tests
if [ ! -f build/json-20240303.jar ]; then
 curl --fail -L -o build/json-20240303.jar https://repo.maven.apache.org/maven2/org/json/json/20240303/json-20240303.jar
fi
java com.sun.tools.javac.Main -cp build/json-20240303.jar -d build/tests app/src/main/java/ai/jevguard/Api.java app/src/main/java/ai/jevguard/RiskRules.java app/src/main/java/ai/jevguard/ApkEvidence.java tests/CoreTests.java
java -cp build/tests:build/json-20240303.jar ai.jevguard.CoreTests
