#!/bin/bash
#
# XCFramework Build Script for Ecliptix.Security.OPAQUE
# Creates a combined XCFramework for iOS + macOS Swift Package distribution
#
# This script:
# 1. Builds iOS dependencies (libsodium + liboqs) if needed
# 2. Builds the OPAQUE library for iOS Device, Simulator, and macOS
# 3. Merges all static libraries (opaque + sodium + oqs) into one fat library
# 4. Creates a single XCFramework with all dependencies bundled
# 5. Creates a zipped archive with checksum for SPM
#
# Usage: ./build-xcframework.sh [Release|Debug]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

BUILD_TYPE="${1:-Release}"

echo "========================================"
echo "XCFramework Build - Ecliptix OPAQUE"
echo "========================================"
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

# Paths
DEPS_DIR="${SCRIPT_DIR}/.deps/ios"
IOS_DEVICE_BUILD="${SCRIPT_DIR}/build-ios-device"
IOS_SIM_BUILD="${SCRIPT_DIR}/build-ios-simulator"
MACOS_ARM64_BUILD="${SCRIPT_DIR}/build-macos-arm64"
MACOS_X64_BUILD="${SCRIPT_DIR}/build-macos-x86_64"
OUTPUT_DIR="${SCRIPT_DIR}/dist/apple"
XCFRAMEWORK_DIR="${OUTPUT_DIR}/EcliptixOPAQUE.xcframework"
HEADERS_DIR="${SCRIPT_DIR}/include/opaque"

# ============================================
# Step 1: Build iOS Dependencies
# ============================================
echo ""
echo "Step 1: Building iOS Dependencies..."
echo "========================================"

if [[ ! -f "${DEPS_DIR}/iphoneos-arm64/lib/liboqs.a" ]] || \
   [[ ! -f "${DEPS_DIR}/iphonesimulator-fat/lib/liboqs.a" ]]; then
    echo "iOS dependencies not found. Building..."
    chmod +x "${SCRIPT_DIR}/scripts/build-ios-deps.sh"
    "${SCRIPT_DIR}/scripts/build-ios-deps.sh" "${BUILD_TYPE}"
else
    echo "iOS dependencies found. Skipping build."
fi

# Verify dependencies exist
if [[ ! -f "${DEPS_DIR}/iphoneos-arm64/lib/libsodium.a" ]] || \
   [[ ! -f "${DEPS_DIR}/iphoneos-arm64/lib/liboqs.a" ]]; then
    echo "Error: iOS device dependencies not found!"
    exit 1
fi

if [[ ! -f "${DEPS_DIR}/iphonesimulator-fat/lib/libsodium.a" ]] || \
   [[ ! -f "${DEPS_DIR}/iphonesimulator-fat/lib/liboqs.a" ]]; then
    echo "Error: iOS simulator dependencies not found!"
    exit 1
fi

echo "iOS dependencies verified."

# ============================================
# Step 2: Clean Previous Builds
# ============================================
echo ""
echo "Step 2: Cleaning previous builds..."
echo "========================================"

rm -rf "${IOS_DEVICE_BUILD}" "${IOS_SIM_BUILD}"
rm -rf "${MACOS_ARM64_BUILD}" "${MACOS_X64_BUILD}"
rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"

unset VCPKG_ROOT

# ============================================
# Step 3: Build OPAQUE for iOS Device (arm64)
# ============================================
echo ""
echo "Step 3: Building OPAQUE for iOS Device (arm64)..."
echo "========================================"

DEVICE_DEPS="${DEPS_DIR}/iphoneos-arm64"

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
    -DCMAKE_OSX_ARCHITECTURES=arm64 \
    -DSODIUM_INCLUDE_DIRS="${DEVICE_DEPS}/include" \
    -DSODIUM_LIBRARY_DIRS="${DEVICE_DEPS}/lib" \
    -DSODIUM_LIBRARIES="${DEVICE_DEPS}/lib/libsodium.a" \
    -DOQS_INCLUDE_DIRS="${DEVICE_DEPS}/include" \
    -DOQS_LIBRARY_DIRS="${DEVICE_DEPS}/lib" \
    -DOQS_LIBRARIES="${DEVICE_DEPS}/lib/liboqs.a" \
    -DIOS_DEPS_DIR="${DEVICE_DEPS}"

cmake --build "${IOS_DEVICE_BUILD}" --config "${BUILD_TYPE}" --parallel

echo "iOS Device build completed!"

# ============================================
# Step 4: Build OPAQUE for iOS Simulator
# ============================================
echo ""
echo "Step 4: Building OPAQUE for iOS Simulator (arm64+x86_64)..."
echo "========================================"

SIM_DEPS="${DEPS_DIR}/iphonesimulator-fat"

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
    -DCMAKE_OSX_ARCHITECTURES="arm64;x86_64" \
    -DSODIUM_INCLUDE_DIRS="${SIM_DEPS}/include" \
    -DSODIUM_LIBRARY_DIRS="${SIM_DEPS}/lib" \
    -DSODIUM_LIBRARIES="${SIM_DEPS}/lib/libsodium.a" \
    -DOQS_INCLUDE_DIRS="${SIM_DEPS}/include" \
    -DOQS_LIBRARY_DIRS="${SIM_DEPS}/lib" \
    -DOQS_LIBRARIES="${SIM_DEPS}/lib/liboqs.a" \
    -DIOS_DEPS_DIR="${SIM_DEPS}"

cmake --build "${IOS_SIM_BUILD}" --config "${BUILD_TYPE}" --parallel

echo "iOS Simulator build completed!"

# ============================================
# Step 5: Build OPAQUE for macOS
# ============================================
echo ""
echo "Step 5: Building OPAQUE for macOS (arm64)..."
echo "========================================"

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

echo ""
echo "Building OPAQUE for macOS (x86_64)..."
echo "========================================"

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

echo "macOS builds completed!"

# ============================================
# Step 6: Locate Built Libraries
# ============================================
echo ""
echo "Step 6: Locating built libraries..."
echo "========================================"

IOS_DEVICE_LIB=$(find "${IOS_DEVICE_BUILD}" -name "libeop.agent.a" | head -1)
IOS_SIM_LIB=$(find "${IOS_SIM_BUILD}" -name "libeop.agent.a" | head -1)
MACOS_ARM64_LIB=$(find "${MACOS_ARM64_BUILD}" -name "libeop.agent.a" | head -1)
MACOS_X64_LIB=$(find "${MACOS_X64_BUILD}" -name "libeop.agent.a" | head -1)

# Verify all libraries exist
for lib in "${IOS_DEVICE_LIB}" "${IOS_SIM_LIB}" "${MACOS_ARM64_LIB}" "${MACOS_X64_LIB}"; do
    if [[ -z "${lib}" ]] || [[ ! -f "${lib}" ]]; then
        echo "Error: Library not found: ${lib}"
        exit 1
    fi
done

echo "iOS Device:     ${IOS_DEVICE_LIB}"
echo "iOS Simulator:  ${IOS_SIM_LIB}"
echo "macOS arm64:    ${MACOS_ARM64_LIB}"
echo "macOS x86_64:   ${MACOS_X64_LIB}"

# ============================================
# Step 7: Merge Static Libraries
# ============================================
echo ""
echo "Step 7: Merging static libraries (bundling dependencies)..."
echo "========================================"

MERGED_DIR="${OUTPUT_DIR}/merged"
mkdir -p "${MERGED_DIR}"

# iOS Device - merge opaque + sodium + oqs
echo "Merging iOS Device libraries..."
libtool -static -o "${MERGED_DIR}/libeop-ios-device.a" \
    "${IOS_DEVICE_LIB}" \
    "${DEPS_DIR}/iphoneos-arm64/lib/libsodium.a" \
    "${DEPS_DIR}/iphoneos-arm64/lib/liboqs.a"

# iOS Simulator - merge opaque + sodium + oqs
echo "Merging iOS Simulator libraries..."
libtool -static -o "${MERGED_DIR}/libeop-ios-simulator.a" \
    "${IOS_SIM_LIB}" \
    "${DEPS_DIR}/iphonesimulator-fat/lib/libsodium.a" \
    "${DEPS_DIR}/iphonesimulator-fat/lib/liboqs.a"

# macOS - get sodium and oqs from Homebrew, create universal binary
echo "Merging macOS libraries..."
HOMEBREW_PREFIX=$(brew --prefix)
SODIUM_MACOS="${HOMEBREW_PREFIX}/opt/libsodium/lib/libsodium.a"
OQS_MACOS="${HOMEBREW_PREFIX}/opt/liboqs/lib/liboqs.a"

if [[ ! -f "${SODIUM_MACOS}" ]]; then
    echo "Error: macOS libsodium not found at ${SODIUM_MACOS}"
    echo "Install with: brew install libsodium"
    exit 1
fi

if [[ ! -f "${OQS_MACOS}" ]]; then
    echo "Error: macOS liboqs not found at ${OQS_MACOS}"
    echo "Install with: brew install liboqs"
    exit 1
fi

# Create macOS universal binary first
lipo -create "${MACOS_ARM64_LIB}" "${MACOS_X64_LIB}" -output "${MERGED_DIR}/libeop-macos-universal.a"

# Merge with dependencies
libtool -static -o "${MERGED_DIR}/libeop-macos.a" \
    "${MERGED_DIR}/libeop-macos-universal.a" \
    "${SODIUM_MACOS}" \
    "${OQS_MACOS}"

echo "Library merging completed!"

# Show sizes
echo ""
echo "Merged library sizes:"
ls -lh "${MERGED_DIR}"/*.a

# ============================================
# Step 8: Create XCFramework
# ============================================
echo ""
echo "Step 8: Creating XCFramework..."
echo "========================================"

if [[ ! -d "${HEADERS_DIR}" ]]; then
    echo "Error: Headers directory not found: ${HEADERS_DIR}"
    exit 1
fi

xcodebuild -create-xcframework \
    -library "${MERGED_DIR}/libeop-ios-device.a" \
    -headers "${HEADERS_DIR}" \
    -library "${MERGED_DIR}/libeop-ios-simulator.a" \
    -headers "${HEADERS_DIR}" \
    -library "${MERGED_DIR}/libeop-macos.a" \
    -headers "${HEADERS_DIR}" \
    -output "${XCFRAMEWORK_DIR}"

echo "XCFramework created!"

# ============================================
# Step 9: Verify XCFramework
# ============================================
echo ""
echo "Step 9: Verifying XCFramework..."
echo "========================================"

if [[ -d "${XCFRAMEWORK_DIR}" ]]; then
    echo "XCFramework structure:"
    ls -la "${XCFRAMEWORK_DIR}"
    echo ""

    for slice in "${XCFRAMEWORK_DIR}"/*/; do
        slice_name=$(basename "${slice}")
        lib_file=$(find "${slice}" -name "*.a" | head -1)
        if [[ -n "${lib_file}" ]]; then
            echo "${slice_name}:"
            lipo -info "${lib_file}" 2>/dev/null || echo "  (single arch)"
            # Verify no undefined symbols for sodium/oqs
            nm -u "${lib_file}" 2>/dev/null | grep -E "sodium_|OQS_" | head -5 || echo "  All dependencies bundled!"
        fi
    done
else
    echo "Error: XCFramework creation failed!"
    exit 1
fi

# ============================================
# Step 10: Create Archive and Checksum
# ============================================
echo ""
echo "Step 10: Creating archive..."
echo "========================================"

cd "${OUTPUT_DIR}"
zip -r EcliptixOPAQUE.xcframework.zip EcliptixOPAQUE.xcframework

echo "Computing checksum..."
CHECKSUM=$(swift package compute-checksum EcliptixOPAQUE.xcframework.zip)

# Save checksum to file
echo "${CHECKSUM}" > EcliptixOPAQUE.xcframework.zip.sha256

# Cleanup merged dir
rm -rf "${MERGED_DIR}"

echo ""
echo "========================================"
echo "XCFramework Build Complete!"
echo "========================================"
echo ""
echo "Output:"
echo "  XCFramework: ${XCFRAMEWORK_DIR}"
echo "  Archive:     ${OUTPUT_DIR}/EcliptixOPAQUE.xcframework.zip"
echo "  Checksum:    ${CHECKSUM}"
echo ""
echo "Swift Package Manager (remote):"
echo "  .binaryTarget("
echo "      name: \"EcliptixOPAQUEBinary\","
echo "      url: \"https://github.com/.../EcliptixOPAQUE.xcframework.zip\","
echo "      checksum: \"${CHECKSUM}\""
echo "  )"
echo ""
echo "Swift Package Manager (local):"
echo "  .binaryTarget("
echo "      name: \"EcliptixOPAQUEBinary\","
echo "      path: \"EcliptixOPAQUE.xcframework\""
echo "  )"
echo ""
