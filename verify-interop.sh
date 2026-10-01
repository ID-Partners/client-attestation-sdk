#!/usr/bin/env bash
# Build every port's credential from the shared vectors and verify them through the real Java AS-side
# ClientAttestationVerifier. Requires: python3, node/npm, go, a JDK + Maven, and the AS-side verifier
# (client-attestation 0.1.0, not on Maven Central) installed in ~/.m2: build the sibling client-attestation
# repo with `mvn -o install` first.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

# Start from nothing, so a port that fails to emit can't pass on a stale file from an earlier run.
rm -rf vectors/out

echo "== emit: python =="
( cd python && PYTHONPATH=src python3 emit.py )

echo "== emit: typescript =="
( cd typescript && npm ci --silent && npm run --silent emit )

echo "== emit: go =="
( cd go && go run ./cmd/emit )

echo "== resolve the verifier classpath (java/pom.xml, interop profile) =="
VERIFIER="$HOME/.m2/repository/com/pingidentity/ps/oidf/client-attestation/0.1.0/client-attestation-0.1.0.jar"
if [ ! -f "$VERIFIER" ]; then
  echo "missing the AS-side verifier (client-attestation 0.1.0) - it is not on Maven Central."
  echo "Install it first: (cd ../client-attestation && mvn -o install)"
  exit 1
fi
mvn -q -B -f java/pom.xml -Pinterop dependency:build-classpath \
  -Dmdep.includeScope=test -Dmdep.outputFile="$ROOT/interop/out/classpath.txt"
CP="$(cat interop/out/classpath.txt)"

echo "== compile + run the interop verifier =="
mkdir -p interop/out
JH="$(/usr/libexec/java_home 2>/dev/null || echo "${JAVA_HOME:-}")"
"$JH/bin/javac" -cp "$CP" -d interop/out interop/VerifyInterop.java
"$JH/bin/java" -cp "$CP:interop/out" VerifyInterop "$ROOT/vectors"
