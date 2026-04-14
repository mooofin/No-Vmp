#!/bin/bash
# Run tests and save outputs to test_outputs/ directory

set -e

mkdir -p test_outputs

echo "[*] Running all tests..."
bazel test //tests:all_tests --test_output=all "$@" 2>&1 | tee test_outputs/test_run.txt

echo ""
echo "[*] Test outputs saved to test_outputs/test_run.txt"

# Copy detailed logs if available
if [ -d ~/.cache/bazel ]; then
    find ~/.cache/bazel -path "*/testlogs/tests/*/test.log" -exec cp {} test_outputs/ \; 2>/dev/null || true
fi

bazel test //tests:all_tests 2>&1 | grep -E "(PASSED|FAILED|test)" | tee test_outputs/summary.txt
