#!/bin/bash
set -e

echo "[*] Generating coverage report..."

bazel coverage //tests:all_tests --test_output=errors --instrumentation_filter='//lib[/:]' 2>&1 | tail -20

echo "[*] Processing coverage data..."
mkdir -p coverage

COVERAGE_FILES=$(find bazel-out ~/.cache/bazel -name "coverage.dat" 2>/dev/null | head -10 || true)
if [ -z "$COVERAGE_FILES" ]; then
    echo "[!] No coverage.dat found"
    exit 0
fi

for f in $COVERAGE_FILES; do
    echo "    $f"
done

echo "[*] Coverage data found"
echo "[*] Done"
