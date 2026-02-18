#!/bin/bash
# Build and run security property tests
# Usage: ./run-security-tests.sh

set -e

BUILD_DIR="build-security-tests"

echo "=== Ecliptix PQ-OPAQUE Security Property Tests ==="
echo ""

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

echo "[1/2] Building..."
cmake ../security_tests -DCMAKE_BUILD_TYPE=Release 2>&1
cmake --build . --parallel "$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)" 2>&1

echo ""
echo "[2/2] Running security tests..."
./security_tests --reporter compact 2>&1

echo ""
echo "=== SECURITY TESTS COMPLETE ==="
