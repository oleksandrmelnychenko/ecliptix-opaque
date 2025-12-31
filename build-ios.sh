#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

BUILD_TYPE="${1:-Release}"
BUILD_CLIENT="${2:-ON}"

echo "🍎 Building Ecliptix OPAQUE Library for iOS"
echo "Build Type: ${BUILD_TYPE}"
echo "Build Client: ${BUILD_CLIENT}"
echo ""

# Check for required tools
if ! command -v cmake &> /dev/null; then
    echo "❌ CMake not found. Please install CMake first:"
    echo "   brew install cmake"
    exit 1
fi

if ! command -v xcodebuild &> /dev/null; then
    echo "❌ Xcode command line tools not found. Please install Xcode."
    exit 1
fi

# Check for libsodium
if ! brew list libsodium &> /dev/null; then
    echo "⚠️  libsodium not found. Installing via Homebrew..."
    brew install libsodium
fi

# Get libsodium paths
SODIUM_PREFIX=$(brew --prefix libsodium)
echo "📦 Using libsodium from: ${SODIUM_PREFIX}"

# Output directories
IOS_OUTPUT_DIR="${SCRIPT_DIR}/dist/ios"
DEVICE_BUILD_DIR="${SCRIPT_DIR}/build-ios-device"
SIMULATOR_BUILD_DIR="${SCRIPT_DIR}/build-ios-simulator"
XCFRAMEWORK_DIR="${IOS_OUTPUT_DIR}/EcliptixOPAQUE.xcframework"

mkdir -p "${IOS_OUTPUT_DIR}"

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -rf "${DEVICE_BUILD_DIR}" "${SIMULATOR_BUILD_DIR}" "${XCFRAMEWORK_DIR}"

# ==============================================================================
# Build for iOS Device (arm64)
# ==============================================================================
echo ""
echo "📱 Building for iOS Device (arm64)..."
echo "=================================================="

# Unset VCPKG env vars to force pkg-config path
unset VCPKG_ROOT

cmake -B "${DEVICE_BUILD_DIR}" \
    -DCMAKE_TOOLCHAIN_FILE="${SCRIPT_DIR}/cmake/ios-toolchain.cmake" \
    -DPLATFORM=OS64 \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
    -DBUILD_CLIENT="${BUILD_CLIENT}" \
    -DBUILD_SERVER=OFF \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_TESTS=OFF \
    -DBUILD_DOTNET_INTEROP=OFF \
    -DENABLE_HARDENING=ON \
    -DBUILD_STATIC_SODIUM=ON \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=17.0 \
    -DCMAKE_OSX_ARCHITECTURES=arm64 \
    -DCMAKE_INSTALL_PREFIX="${DEVICE_BUILD_DIR}/install"

cmake --build "${DEVICE_BUILD_DIR}" --config "${BUILD_TYPE}" --parallel

echo "✅ iOS Device build completed!"

# ==============================================================================
# Build for iOS Simulator (arm64 + x86_64)
# ==============================================================================
echo ""
echo "🖥️  Building for iOS Simulator (arm64 + x86_64)..."
echo "=================================================="

cmake -B "${SIMULATOR_BUILD_DIR}" \
    -DCMAKE_TOOLCHAIN_FILE="${SCRIPT_DIR}/cmake/ios-toolchain.cmake" \
    -DPLATFORM=SIMULATOR64 \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
    -DBUILD_CLIENT="${BUILD_CLIENT}" \
    -DBUILD_SERVER=OFF \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_TESTS=OFF \
    -DBUILD_DOTNET_INTEROP=OFF \
    -DENABLE_HARDENING=ON \
    -DBUILD_STATIC_SODIUM=ON \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=17.0 \
    -DCMAKE_OSX_ARCHITECTURES="arm64;x86_64" \
    -DCMAKE_INSTALL_PREFIX="${SIMULATOR_BUILD_DIR}/install"

cmake --build "${SIMULATOR_BUILD_DIR}" --config "${BUILD_TYPE}" --parallel

echo "✅ iOS Simulator build completed!"

# ==============================================================================
# Find the built libraries
# ==============================================================================
echo ""
echo "🔍 Locating built libraries..."

# Find client library (static)
if [[ "${BUILD_CLIENT}" == "ON" ]]; then
    DEVICE_LIB=$(find "${DEVICE_BUILD_DIR}" -name "libopaque_client.a" | head -1)
    SIMULATOR_LIB=$(find "${SIMULATOR_BUILD_DIR}" -name "libopaque_client.a" | head -1)
    LIB_NAME="opaque_client"
else
    echo "❌ Server builds for iOS are not supported (only client)"
    exit 1
fi

if [[ -z "${DEVICE_LIB}" ]] || [[ ! -f "${DEVICE_LIB}" ]]; then
    echo "❌ Device library not found!"
    echo "Expected to find libopaque_client.a in ${DEVICE_BUILD_DIR}"
    exit 1
fi

if [[ -z "${SIMULATOR_LIB}" ]] || [[ ! -f "${SIMULATOR_LIB}" ]]; then
    echo "❌ Simulator library not found!"
    echo "Expected to find libopaque_client.a in ${SIMULATOR_BUILD_DIR}"
    exit 1
fi

echo "📦 Device library: ${DEVICE_LIB}"
echo "📦 Simulator library: ${SIMULATOR_LIB}"

# ==============================================================================
# Create XCFramework
# ==============================================================================
echo ""
echo "📦 Creating XCFramework..."
echo "=================================================="

# Prepare header files
HEADERS_DIR="${SCRIPT_DIR}/include/opaque"
if [[ ! -d "${HEADERS_DIR}" ]]; then
    echo "❌ Headers directory not found: ${HEADERS_DIR}"
    exit 1
fi

# Create XCFramework
xcodebuild -create-xcframework \
    -library "${DEVICE_LIB}" \
    -headers "${HEADERS_DIR}" \
    -library "${SIMULATOR_LIB}" \
    -headers "${HEADERS_DIR}" \
    -output "${XCFRAMEWORK_DIR}"

echo "✅ XCFramework created successfully!"

# ==============================================================================
# Verify XCFramework
# ==============================================================================
echo ""
echo "🔍 Verifying XCFramework..."
echo "=================================================="

if [[ -d "${XCFRAMEWORK_DIR}" ]]; then
    echo "✅ XCFramework structure:"
    ls -la "${XCFRAMEWORK_DIR}"
    echo ""

    # Show architectures
    echo "📊 Device architectures:"
    lipo -info "${XCFRAMEWORK_DIR}/"*-arm64/libopaque_client.a 2>/dev/null || echo "  (info not available)"

    echo ""
    echo "📊 Simulator architectures:"
    lipo -info "${XCFRAMEWORK_DIR}/"*-simulator/libopaque_client.a 2>/dev/null || echo "  (info not available)"
else
    echo "❌ XCFramework creation failed!"
    exit 1
fi

# ==============================================================================
# Create checksum
# ==============================================================================
echo ""
echo "🔐 Computing checksum..."
CHECKSUM=$(swift package compute-checksum "${XCFRAMEWORK_DIR}.zip" 2>/dev/null || echo "")

if [[ -z "${CHECKSUM}" ]]; then
    # Create zip for checksum
    cd "${IOS_OUTPUT_DIR}"
    zip -r EcliptixOPAQUE.xcframework.zip EcliptixOPAQUE.xcframework
    CHECKSUM=$(swift package compute-checksum EcliptixOPAQUE.xcframework.zip)
    echo "📦 Created: ${IOS_OUTPUT_DIR}/EcliptixOPAQUE.xcframework.zip"
fi

echo "Checksum: ${CHECKSUM}"

# ==============================================================================
# Summary
# ==============================================================================
echo ""
echo "🎉 iOS Build Complete!"
echo "=================================================="
echo "📦 XCFramework: ${XCFRAMEWORK_DIR}"
echo "📦 Archive: ${IOS_OUTPUT_DIR}/EcliptixOPAQUE.xcframework.zip"
echo "🔐 Checksum: ${CHECKSUM}"
echo ""
echo "📋 Next Steps:"
echo "1. Copy XCFramework to your iOS project:"
echo "   cp -r ${XCFRAMEWORK_DIR} /path/to/ios/project/Packages/EcliptixOPAQUE/"
echo ""
echo "2. Or use the zipped version with Package.swift:"
echo "   .binaryTarget("
echo "       name: \"EcliptixOPAQUE\","
echo "       path: \"Packages/EcliptixOPAQUE/EcliptixOPAQUE.xcframework\""
echo "   )"
echo ""
echo "3. Checksum (if using remote URL):"
echo "   checksum: \"${CHECKSUM}\""
echo ""
