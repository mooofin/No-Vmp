#!/bin/bash
set -e

echo "[*] Generating coverage report..."

bazel coverage //tests:all_tests --test_output=all

LATEST=$(find bazel-out -name "coverage.dat" | head -1)
if [ -z "$LATEST" ]; then
    echo "[-] No coverage.dat found"
    exit 1
fi

echo "[*] Processing coverage data..."
mkdir -p coverage

llvm-cov export \
    -format=lcov \
    -instr-profile=$(find bazel-out -name "*.profdata" | head -1) \
    bazel-out/*/test/tests/rkey_test.runfiles/_main/tests/rkey_test \
    > coverage/coverage.lcov 2>/dev/null || true

if [ -f coverage/coverage.lcov ] && [ -s coverage/coverage.lcov ]; then
    genhtml coverage/coverage.lcov -o coverage/ --ignore-errors source
    echo "[*] Coverage report: coverage/index.html"
else
    echo "[!] lcov generation skipped (no data)"
fi

echo "[*] Done"
