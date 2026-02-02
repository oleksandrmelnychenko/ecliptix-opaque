#!/bin/bash
#
# macOS Build Script for Ecliptix.Security.OPAQUE
# Builds universal (arm64 + x86_64) client library
#
# Usage:
#   ./build-macos.sh [Release|Debug] [arch]
#
# Examples:
#   ./build-macos.sh Release           # Build universal binary
#   ./build-macos.sh Release arm64     # Build arm64 only
#   ./build-macos.sh Release x86_64    # Build x86_64 only
#   ./build-macos.sh Release universal # Build universal binary (explicit)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

BUILD_TYPE="${1:-Release}"
ARCH="${2:-universal}"

echo "macOS Build - Ecliptix.Security.OPAQUE"
echo "========================================"
echo "Build Type: ${BUILD_TYPE}"
echo "Architecture: ${ARCH}"
echo ""

# Check dependencies
if ! command -v cmake &> /dev/null; then
    echo "Error: CMake not found. Install with: brew install cmake"
    exit 1
fi

# Check for libsodium
if ! brew list libsodium &> /dev/null; then
    echo "Installing libsodium..."
    brew install libsodium
fi

SODIUM_PREFIX=$(brew --prefix libsodium)
echo "Using libsodium from: ${SODIUM_PREFIX}"

# Check for liboqs
if ! brew list liboqs &> /dev/null; then
    echo "Installing liboqs..."
    brew install liboqs
fi

OQS_PREFIX=$(brew --prefix liboqs)
echo "Using liboqs from: ${OQS_PREFIX}"

# Validate architecture
case "${ARCH}" in
    universal|arm64|x86_64)
        ;;
    *)
        echo "Error: Invalid architecture '${ARCH}'. Use: universal, arm64, or x86_64"
        exit 1
        ;;
esac

# Set output directories
BUILD_DIR="${SCRIPT_DIR}/build-macos-${ARCH}"
OUTPUT_DIR="${SCRIPT_DIR}/dist/macos"
INSTALL_DIR="${BUILD_DIR}/install"

mkdir -p "${OUTPUT_DIR}"

echo ""
echo "Building macOS client library (${ARCH})..."
echo "========================================"

# Clean previous build
rm -rf "${BUILD_DIR}"

# Clear vcpkg to use Homebrew dependencies
unset VCPKG_ROOT

# Configure based on architecture
if [[ "${ARCH}" == "universal" ]]; then
    CMAKE_ARCH_FLAGS="-DCMAKE_OSX_ARCHITECTURES=arm64;x86_64"
else
    CMAKE_ARCH_FLAGS="-DCMAKE_OSX_ARCHITECTURES=${ARCH}"
fi

cmake -B "${BUILD_DIR}" \
    -DCMAKE_TOOLCHAIN_FILE="${SCRIPT_DIR}/cmake/macos-toolchain.cmake" \
    -DMACOS_ARCH="${ARCH}" \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
    -DBUILD_CLIENT=ON \
    -DBUILD_SERVER=OFF \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_TESTS=OFF \
    -DBUILD_DOTNET_INTEROP=ON \
    -DENABLE_HARDENING=ON \
    -DBUILD_STATIC_SODIUM=ON \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=11.0 \
    ${CMAKE_ARCH_FLAGS} \
    -DCMAKE_INSTALL_PREFIX="${INSTALL_DIR}"

cmake --build "${BUILD_DIR}" --config "${BUILD_TYPE}" --parallel

echo "Build completed!"

# Find the built library
STATIC_LIB=$(find "${BUILD_DIR}" -name "libeop.agent.a" | head -1)

if [[ -z "${STATIC_LIB}" ]] || [[ ! -f "${STATIC_LIB}" ]]; then
    echo "Error: Static library not found!"
    exit 1
fi

echo "Found library: ${STATIC_LIB}"

# Copy to output directory
mkdir -p "${OUTPUT_DIR}/lib"
mkdir -p "${OUTPUT_DIR}/include"
cp "${STATIC_LIB}" "${OUTPUT_DIR}/lib/"
cp -r "${SCRIPT_DIR}/include/opaque/"* "${OUTPUT_DIR}/include/"

# Verify architecture
echo ""
echo "Verifying library..."
echo "========================================"
lipo -info "${OUTPUT_DIR}/lib/libeop.agent.a"

# Display sizes
echo ""
echo "Library size:"
ls -lh "${OUTPUT_DIR}/lib/libeop.agent.a"

echo ""
echo "macOS Build Complete!"
echo "========================================"
echo "Output directory: ${OUTPUT_DIR}"
echo "Static library: ${OUTPUT_DIR}/lib/libeop.agent.a"
echo "Headers: ${OUTPUT_DIR}/include/"
echo ""
echo "To link in your project:"
echo "  -L${OUTPUT_DIR}/lib -leop.agent"
echo ""
