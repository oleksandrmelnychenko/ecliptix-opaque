#!/bin/bash
# Build and test script for Ecliptix.Security.OPAQUE
# Run from project root: ./build-and-test.sh

set -e

echo "=== Ecliptix.Security.OPAQUE — Build & Test ==="
echo ""

BUILD_DIR="build-test"

# Clean previous build
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

echo "[1/3] Configuring CMake..."
cmake .. \
    -DCMAKE_BUILD_TYPE=Debug \
    -DBUILD_TESTS=ON \
    -DBUILD_CLIENT=ON \
    -DBUILD_SERVER=ON \
    -DBUILD_SHARED_LIBS=OFF \
    -DENABLE_HARDENING=ON \
    -DRUN_TESTS_BEFORE_BUILD=OFF \
    2>&1

echo ""
echo "[2/3] Building..."
cmake --build . --parallel "$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)" 2>&1

echo ""
echo "[3/3] Running tests..."
cd tests
if [ -f ./opaque_tests ]; then
    ./opaque_tests --reporter compact 2>&1
    echo ""
    echo "=== ALL TESTS PASSED ==="
else
    echo "ERROR: test binary not found"
    ls -la
    exit 1
fi
