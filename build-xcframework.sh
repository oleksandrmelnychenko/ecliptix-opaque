#!/bin/bash
#
# XCFramework Build Script for Ecliptix.Security.OPAQUE
# Creates a combined XCFramework for iOS + macOS Swift Package distribution
#
# Usage:
#   ./build-xcframework.sh [Release|Debug]
#
# This script:
# 1. Builds iOS Device (arm64)
# 2. Builds iOS Simulator (arm64 + x86_64)
# 3. Builds macOS (arm64 + x86_64 universal)
# 4. Combines all into a single XCFramework
# 5. Creates a zipped archive with checksum for SPM

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

BUILD_TYPE="${1:-Release}"

echo "XCFramework Build - Ecliptix.Security.OPAQUE"
echo "=============================================="
echo "Build Type: ${BUILD_TYPE}"
echo ""

# Check dependencies
if ! command -v cmake &> /dev/null; then
    echo "Error: CMake not found. Install with: brew install cmake"
    exit 1
fi

if ! command -v xcodebuild &> /dev/null; then
    echo "Error: Xcode command line tools not found."
    exit 1
fi

# Check for libsodium
if ! brew list libsodium &> /dev/null; then
    echo "Installing libsodium..."
    brew install libsodium
fi

SODIUM_PREFIX=$(brew --prefix libsodium)
echo "Using libsodium from: ${SODIUM_PREFIX}"

# Define directories
IOS_DEVICE_BUILD="${SCRIPT_DIR}/build-ios-device"
IOS_SIM_BUILD="${SCRIPT_DIR}/build-ios-simulator"
MACOS_BUILD="${SCRIPT_DIR}/build-macos-universal"
OUTPUT_DIR="${SCRIPT_DIR}/dist/apple"
XCFRAMEWORK_DIR="${OUTPUT_DIR}/EcliptixOPAQUE.xcframework"
HEADERS_DIR="${SCRIPT_DIR}/include/opaque"

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf "${IOS_DEVICE_BUILD}" "${IOS_SIM_BUILD}" "${MACOS_BUILD}"
rm -rf "${SCRIPT_DIR}/build-macos-arm64" "${SCRIPT_DIR}/build-macos-x86_64"
rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"

# Clear vcpkg
unset VCPKG_ROOT

# ============================================
# iOS Device Build (arm64)
# ============================================
echo ""
echo "Building iOS Device (arm64)..."
echo "=============================================="

cmake -B "${IOS_DEVICE_BUILD}" \
    -DCMAKE_TOOLCHAIN_FILE="${SCRIPT_DIR}/cmake/ios-toolchain.cmake" \
    -DPLATFORM=OS64 \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
    -DBUILD_CLIENT=ON \
    -DBUILD_SERVER=OFF \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_TESTS=OFF \
    -DBUILD_DOTNET_INTEROP=OFF \
    -DENABLE_HARDENING=ON \
    -DBUILD_STATIC_SODIUM=ON \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=17.0 \
    -DCMAKE_OSX_ARCHITECTURES=arm64

cmake --build "${IOS_DEVICE_BUILD}" --config "${BUILD_TYPE}" --parallel

echo "iOS Device build completed!"

# ============================================
# iOS Simulator Build (arm64 + x86_64)
# ============================================
echo ""
echo "Building iOS Simulator (arm64 + x86_64)..."
echo "=============================================="

cmake -B "${IOS_SIM_BUILD}" \
    -DCMAKE_TOOLCHAIN_FILE="${SCRIPT_DIR}/cmake/ios-toolchain.cmake" \
    -DPLATFORM=SIMULATOR64 \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
    -DBUILD_CLIENT=ON \
    -DBUILD_SERVER=OFF \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_TESTS=OFF \
    -DBUILD_DOTNET_INTEROP=OFF \
    -DENABLE_HARDENING=ON \
    -DBUILD_STATIC_SODIUM=ON \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=17.0 \
    -DCMAKE_OSX_ARCHITECTURES="arm64;x86_64"

cmake --build "${IOS_SIM_BUILD}" --config "${BUILD_TYPE}" --parallel

echo "iOS Simulator build completed!"

# ============================================
# macOS Build (arm64 and x86_64 separately, then lipo)
# ============================================
MACOS_ARM64_BUILD="${SCRIPT_DIR}/build-macos-arm64"
MACOS_X64_BUILD="${SCRIPT_DIR}/build-macos-x86_64"

echo ""
echo "Building macOS arm64..."
echo "=============================================="

cmake -B "${MACOS_ARM64_BUILD}" \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
    -DBUILD_CLIENT=ON \
    -DBUILD_SERVER=OFF \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_TESTS=OFF \
    -DBUILD_DOTNET_INTEROP=OFF \
    -DENABLE_HARDENING=ON \
    -DBUILD_STATIC_SODIUM=ON \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=11.0 \
    -DCMAKE_OSX_ARCHITECTURES=arm64

cmake --build "${MACOS_ARM64_BUILD}" --config "${BUILD_TYPE}" --parallel

echo "macOS arm64 build completed!"

echo ""
echo "Building macOS x86_64..."
echo "=============================================="

cmake -B "${MACOS_X64_BUILD}" \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
    -DBUILD_CLIENT=ON \
    -DBUILD_SERVER=OFF \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_TESTS=OFF \
    -DBUILD_DOTNET_INTEROP=OFF \
    -DENABLE_HARDENING=ON \
    -DBUILD_STATIC_SODIUM=ON \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=11.0 \
    -DCMAKE_OSX_ARCHITECTURES=x86_64

cmake --build "${MACOS_X64_BUILD}" --config "${BUILD_TYPE}" --parallel

echo "macOS x86_64 build completed!"

# Create universal binary with lipo
echo ""
echo "Creating macOS universal binary with lipo..."
echo "=============================================="

MACOS_ARM64_LIB=$(find "${MACOS_ARM64_BUILD}" -name "libeop.agent.a" | head -1)
MACOS_X64_LIB=$(find "${MACOS_X64_BUILD}" -name "libeop.agent.a" | head -1)

mkdir -p "${MACOS_BUILD}"
lipo -create "${MACOS_ARM64_LIB}" "${MACOS_X64_LIB}" -output "${MACOS_BUILD}/libeop.agent.a"

echo "macOS Universal build completed!"
lipo -info "${MACOS_BUILD}/libeop.agent.a"

# ============================================
# Locate Built Libraries
# ============================================
echo ""
echo "Locating built libraries..."

IOS_DEVICE_LIB=$(find "${IOS_DEVICE_BUILD}" -name "libeop.agent.a" | head -1)
IOS_SIM_LIB=$(find "${IOS_SIM_BUILD}" -name "libeop.agent.a" | head -1)
MACOS_LIB="${MACOS_BUILD}/libeop.agent.a"

if [[ -z "${IOS_DEVICE_LIB}" ]] || [[ ! -f "${IOS_DEVICE_LIB}" ]]; then
    echo "Error: iOS Device library not found!"
    exit 1
fi

if [[ -z "${IOS_SIM_LIB}" ]] || [[ ! -f "${IOS_SIM_LIB}" ]]; then
    echo "Error: iOS Simulator library not found!"
    exit 1
fi

if [[ -z "${MACOS_LIB}" ]] || [[ ! -f "${MACOS_LIB}" ]]; then
    echo "Error: macOS library not found!"
    exit 1
fi

echo "iOS Device: ${IOS_DEVICE_LIB}"
echo "iOS Simulator: ${IOS_SIM_LIB}"
echo "macOS: ${MACOS_LIB}"

# Verify headers
if [[ ! -d "${HEADERS_DIR}" ]]; then
    echo "Error: Headers directory not found: ${HEADERS_DIR}"
    exit 1
fi

# ============================================
# Create XCFramework
# ============================================
echo ""
echo "Creating XCFramework..."
echo "=============================================="

xcodebuild -create-xcframework \
    -library "${IOS_DEVICE_LIB}" \
    -headers "${HEADERS_DIR}" \
    -library "${IOS_SIM_LIB}" \
    -headers "${HEADERS_DIR}" \
    -library "${MACOS_LIB}" \
    -headers "${HEADERS_DIR}" \
    -output "${XCFRAMEWORK_DIR}"

echo "XCFramework created!"

# ============================================
# Verify XCFramework
# ============================================
echo ""
echo "Verifying XCFramework..."
echo "=============================================="

if [[ -d "${XCFRAMEWORK_DIR}" ]]; then
    echo "XCFramework structure:"
    ls -la "${XCFRAMEWORK_DIR}"
    echo ""

    echo "iOS Device architectures:"
    lipo -info "${XCFRAMEWORK_DIR}/"*-arm64_arm64*/libeop.agent.a 2>/dev/null || \
    lipo -info "${XCFRAMEWORK_DIR}/"*-arm64*/libeop.agent.a 2>/dev/null || \
    echo "  (iOS Device slice)"

    echo ""
    echo "iOS Simulator architectures:"
    lipo -info "${XCFRAMEWORK_DIR}/"*-arm64_x86_64-simulator*/libeop.agent.a 2>/dev/null || \
    lipo -info "${XCFRAMEWORK_DIR}/"*-simulator*/libeop.agent.a 2>/dev/null || \
    echo "  (iOS Simulator slice)"

    echo ""
    echo "macOS architectures:"
    lipo -info "${XCFRAMEWORK_DIR}/"*-macos*/libeop.agent.a 2>/dev/null || \
    lipo -info "${XCFRAMEWORK_DIR}/"*-x86_64*/libeop.agent.a 2>/dev/null || \
    echo "  (macOS slice)"
else
    echo "Error: XCFramework creation failed!"
    exit 1
fi

# ============================================
# Create Archive and Checksum
# ============================================
echo ""
echo "Creating archive..."
echo "=============================================="

cd "${OUTPUT_DIR}"
zip -r EcliptixOPAQUE.xcframework.zip EcliptixOPAQUE.xcframework

echo "Computing checksum..."
CHECKSUM=$(swift package compute-checksum EcliptixOPAQUE.xcframework.zip)

# Save checksum to file
echo "${CHECKSUM}" > EcliptixOPAQUE.xcframework.zip.sha256

echo ""
echo "XCFramework Build Complete!"
echo "=============================================="
echo ""
echo "Output Directory: ${OUTPUT_DIR}"
echo "XCFramework: ${XCFRAMEWORK_DIR}"
echo "Archive: ${OUTPUT_DIR}/EcliptixOPAQUE.xcframework.zip"
echo "Checksum: ${CHECKSUM}"
echo ""
echo "For Swift Package Manager (remote binary):"
echo "  .binaryTarget("
echo "      name: \"EcliptixOPAQUE\","
echo "      url: \"https://github.com/.../EcliptixOPAQUE.xcframework.zip\","
echo "      checksum: \"${CHECKSUM}\""
echo "  )"
echo ""
echo "For local development:"
echo "  .binaryTarget("
echo "      name: \"EcliptixOPAQUE\","
echo "      path: \"EcliptixOPAQUE.xcframework\""
echo "  )"
echo ""
