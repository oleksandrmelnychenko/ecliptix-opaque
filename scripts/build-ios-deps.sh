#!/bin/bash
#
# Build iOS dependencies (libsodium + liboqs) for XCFramework
#
# This script builds static libraries for:
# - iOS Device (arm64)
# - iOS Simulator (arm64 + x86_64)
#
# Usage: ./scripts/build-ios-deps.sh [Release|Debug]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
cd "${PROJECT_DIR}"

BUILD_TYPE="${1:-Release}"
DEPS_DIR="${PROJECT_DIR}/.deps/ios"
LIBSODIUM_VERSION="1.0.20"
LIBOQS_VERSION="0.11.0"

echo "========================================"
echo "Building iOS Dependencies"
echo "========================================"
echo "Build Type: ${BUILD_TYPE}"
echo "Output: ${DEPS_DIR}"
echo ""

mkdir -p "${DEPS_DIR}"

# ============================================
# Build libsodium for iOS
# ============================================
build_libsodium() {
    local PLATFORM=$1
    local ARCH=$2
    local OUTPUT_DIR=$3

    echo ""
    echo "Building libsodium for ${PLATFORM} (${ARCH})..."
    echo "----------------------------------------"

    local SODIUM_SRC="${DEPS_DIR}/libsodium-${LIBSODIUM_VERSION}"
    local SODIUM_BUILD="${DEPS_DIR}/build-sodium-${PLATFORM}-${ARCH}"

    # Always use fresh download (clean any cached version)
    if [[ -d "${SODIUM_SRC}" ]]; then
        echo "Removing cached libsodium..."
        rm -rf "${SODIUM_SRC}"
    fi

    echo "Downloading libsodium ${LIBSODIUM_VERSION}-stable..."
    curl -sL "https://download.libsodium.org/libsodium/releases/libsodium-${LIBSODIUM_VERSION}-stable.tar.gz" | tar xz -C "${DEPS_DIR}"
    # Rename to expected directory name
    mv "${DEPS_DIR}/libsodium-stable" "${SODIUM_SRC}"

    echo "Verifying libsodium configure exists..."
    ls -la "${SODIUM_SRC}/configure" || { echo "ERROR: configure not found!"; exit 1; }

    mkdir -p "${SODIUM_BUILD}"
    cd "${SODIUM_BUILD}"

    local SDK
    local MIN_VERSION="17.0"

    if [[ "${PLATFORM}" == "iphoneos" ]]; then
        SDK=$(xcrun --sdk iphoneos --show-sdk-path)
        export CFLAGS="-arch ${ARCH} -isysroot ${SDK} -mios-version-min=${MIN_VERSION} -fembed-bitcode -O2"
        export LDFLAGS="-arch ${ARCH} -isysroot ${SDK} -mios-version-min=${MIN_VERSION}"
        HOST="arm-apple-darwin"
    else
        SDK=$(xcrun --sdk iphonesimulator --show-sdk-path)
        export CFLAGS="-arch ${ARCH} -isysroot ${SDK} -mios-simulator-version-min=${MIN_VERSION} -O2"
        export LDFLAGS="-arch ${ARCH} -isysroot ${SDK} -mios-simulator-version-min=${MIN_VERSION}"
        if [[ "${ARCH}" == "arm64" ]]; then
            HOST="arm-apple-darwin"
        else
            HOST="x86_64-apple-darwin"
        fi
    fi

    export CC="$(xcrun --find clang)"
    export CXX="$(xcrun --find clang++)"

    "${SODIUM_SRC}/configure" \
        --host="${HOST}" \
        --prefix="${OUTPUT_DIR}" \
        --disable-shared \
        --enable-static \
        --disable-debug \
        --disable-dependency-tracking

    make -j$(sysctl -n hw.ncpu)
    make install

    unset CFLAGS LDFLAGS CC CXX
    cd "${PROJECT_DIR}"

    echo "libsodium built for ${PLATFORM} (${ARCH})"
}

# ============================================
# Build liboqs for iOS
# ============================================
build_liboqs() {
    local PLATFORM=$1
    local ARCH=$2
    local OUTPUT_DIR=$3

    echo ""
    echo "Building liboqs for ${PLATFORM} (${ARCH})..."
    echo "----------------------------------------"

    local OQS_SRC="${DEPS_DIR}/liboqs-${LIBOQS_VERSION}"
    local OQS_BUILD="${DEPS_DIR}/build-oqs-${PLATFORM}-${ARCH}"

    # Download if not exists
    if [[ ! -d "${OQS_SRC}" ]]; then
        echo "Downloading liboqs ${LIBOQS_VERSION}..."
        curl -sL "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VERSION}.tar.gz" | tar xz -C "${DEPS_DIR}"
    fi

    rm -rf "${OQS_BUILD}"
    mkdir -p "${OQS_BUILD}"

    local SDK
    local SYSROOT
    local MIN_VERSION="17.0"
    local CMAKE_SYSTEM_NAME="iOS"

    if [[ "${PLATFORM}" == "iphoneos" ]]; then
        SDK=$(xcrun --sdk iphoneos --show-sdk-path)
        SYSROOT="${SDK}"
    else
        SDK=$(xcrun --sdk iphonesimulator --show-sdk-path)
        SYSROOT="${SDK}"
    fi

    cd "${OQS_BUILD}"

    cmake "${OQS_SRC}" \
        -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
        -DCMAKE_SYSTEM_NAME=iOS \
        -DCMAKE_OSX_SYSROOT="${SYSROOT}" \
        -DCMAKE_OSX_ARCHITECTURES="${ARCH}" \
        -DCMAKE_OSX_DEPLOYMENT_TARGET="${MIN_VERSION}" \
        -DCMAKE_INSTALL_PREFIX="${OUTPUT_DIR}" \
        -DCMAKE_SYSTEM_PROCESSOR="${ARCH}" \
        -DBUILD_SHARED_LIBS=OFF \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_USE_OPENSSL=OFF \
        -DOQS_DIST_BUILD=OFF \
        -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON \
        -DOQS_USE_CPU_EXTENSIONS=OFF \
        -DOQS_MINIMAL_BUILD="KEM_ml_kem_768"

    cmake --build . --config "${BUILD_TYPE}" --parallel
    cmake --install . --config "${BUILD_TYPE}"

    cd "${PROJECT_DIR}"

    echo "liboqs built for ${PLATFORM} (${ARCH})"
}

# ============================================
# Main Build Process
# ============================================

# iOS Device (arm64)
DEVICE_DIR="${DEPS_DIR}/iphoneos-arm64"
mkdir -p "${DEVICE_DIR}"
build_libsodium "iphoneos" "arm64" "${DEVICE_DIR}"
build_liboqs "iphoneos" "arm64" "${DEVICE_DIR}"

# iOS Simulator arm64
SIM_ARM64_DIR="${DEPS_DIR}/iphonesimulator-arm64"
mkdir -p "${SIM_ARM64_DIR}"
build_libsodium "iphonesimulator" "arm64" "${SIM_ARM64_DIR}"
build_liboqs "iphonesimulator" "arm64" "${SIM_ARM64_DIR}"

# iOS Simulator x86_64
SIM_X64_DIR="${DEPS_DIR}/iphonesimulator-x86_64"
mkdir -p "${SIM_X64_DIR}"
build_libsodium "iphonesimulator" "x86_64" "${SIM_X64_DIR}"
build_liboqs "iphonesimulator" "x86_64" "${SIM_X64_DIR}"

# Create fat libraries for simulator
echo ""
echo "Creating fat libraries for simulator..."
echo "----------------------------------------"

SIM_FAT_DIR="${DEPS_DIR}/iphonesimulator-fat"
mkdir -p "${SIM_FAT_DIR}/lib"
cp -r "${SIM_ARM64_DIR}/include" "${SIM_FAT_DIR}/"

lipo -create \
    "${SIM_ARM64_DIR}/lib/libsodium.a" \
    "${SIM_X64_DIR}/lib/libsodium.a" \
    -output "${SIM_FAT_DIR}/lib/libsodium.a"

lipo -create \
    "${SIM_ARM64_DIR}/lib/liboqs.a" \
    "${SIM_X64_DIR}/lib/liboqs.a" \
    -output "${SIM_FAT_DIR}/lib/liboqs.a"

echo ""
echo "========================================"
echo "iOS Dependencies Build Complete!"
echo "========================================"
echo ""
echo "Device (arm64):"
echo "  libsodium: ${DEVICE_DIR}/lib/libsodium.a"
echo "  liboqs:    ${DEVICE_DIR}/lib/liboqs.a"
echo ""
echo "Simulator (arm64+x86_64):"
echo "  libsodium: ${SIM_FAT_DIR}/lib/libsodium.a"
echo "  liboqs:    ${SIM_FAT_DIR}/lib/liboqs.a"
echo ""
echo "Next: Run ./build-xcframework.sh to build the combined XCFramework"
