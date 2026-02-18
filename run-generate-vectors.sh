#!/bin/bash
# Generate test vectors JSON
# Usage: ./run-generate-vectors.sh > test_vectors/test_vectors.json

set -e

BUILD_DIR="build-test-vectors"

echo "=== Generating Test Vectors ===" >&2

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

cmake ../test_vectors -DCMAKE_BUILD_TYPE=Release 2>&1 >&2
cmake --build . --parallel "$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)" 2>&1 >&2

echo "Running generator..." >&2
./generate_test_vectors
