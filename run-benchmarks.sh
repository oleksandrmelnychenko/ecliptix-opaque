#!/bin/bash
# Build and run all benchmarks for Hybrid PQ-OPAQUE
# Run from project root: ./run-benchmarks.sh
#
# IMPORTANT: Run in Release mode for meaningful results!
# Results go to stdout — redirect to file for paper:
#   ./run-benchmarks.sh > benchmark_results.txt 2>&1

set -e

BENCH_DIR="benchmarks"
BUILD_DIR="build-benchmarks"

echo "=== Ecliptix PQ-OPAQUE Benchmark Suite ==="
echo ""

# Clean and build
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

echo "[1/2] Configuring CMake (Release mode)..."
cmake "../$BENCH_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    2>&1

echo ""
echo "[2/2] Building benchmarks..."
cmake --build . --parallel "$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)" 2>&1

echo ""
echo "================================================================"
echo "  BENCHMARK RESULTS"
echo "================================================================"
echo ""

echo ">>> Micro Primitives <<<"
./bench_micro

echo ""
echo ">>> Protocol Phases <<<"
./bench_protocol

echo ""
echo ">>> Throughput <<<"
./bench_throughput

echo ""
echo ">>> Wire Overhead <<<"
./bench_overhead

echo ""
echo "================================================================"
echo "  ALL BENCHMARKS COMPLETE"
echo "================================================================"
