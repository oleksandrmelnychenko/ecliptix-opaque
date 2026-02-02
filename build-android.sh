#!/bin/bash
#
# Android Build Script for Ecliptix.Security.OPAQUE
# Builds client library (eop.agent.so) for Android architectures
#
# Usage:
#   ./build-android.sh [Release|Debug] [ABI|all]
#
# Examples:
#   ./build-android.sh Release all          # Build all ABIs in Release mode
#   ./build-android.sh Release arm64-v8a    # Build only arm64-v8a
#   ./build-android.sh Debug armeabi-v7a    # Build armeabi-v7a in Debug mode
#
# Requirements:
#   - Docker (for cross-compilation)
#   - OR: Android NDK r26d+ installed locally

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
BUILD_TYPE="${1:-Release}"
TARGET_ABI="${2:-all}"

# Supported ABIs
SUPPORTED_ABIS=("arm64-v8a" "armeabi-v7a" "x86_64")

# Project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}"
DIST_DIR="${PROJECT_ROOT}/dist/android"

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}  Ecliptix.Security.OPAQUE - Android Build${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""
echo -e "${GREEN}Build Type:${NC} ${BUILD_TYPE}"
echo -e "${GREEN}Target ABI:${NC} ${TARGET_ABI}"
echo ""

# Function to print status
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Function to build for a specific ABI using Docker
build_abi_docker() {
    local abi=$1
    local build_type=$2

    echo ""
    echo -e "${BLUE}Building for ${abi}...${NC}"

    local image_name="eop-android-${abi}"
    local container_name="eop-android-build-${abi}"

    # Build the Docker image
    docker build -f "${PROJECT_ROOT}/Dockerfile.android" \
        --build-arg ABI="${abi}" \
        --build-arg BUILD_TYPE="${build_type}" \
        --build-arg API_LEVEL=24 \
        -t "${image_name}" \
        "${PROJECT_ROOT}"

    # Create output directory
    mkdir -p "${DIST_DIR}/${abi}/lib"
    mkdir -p "${DIST_DIR}/${abi}/include"

    # Extract artifacts from the image
    docker rm -f "${container_name}" 2>/dev/null || true
    docker create --name "${container_name}" "${image_name}"

    # Copy the library
    docker cp "${container_name}:/workspace/dist/android/${abi}/lib/." "${DIST_DIR}/${abi}/lib/"

    # Copy headers (only once, they're the same for all ABIs)
    if [ ! -f "${DIST_DIR}/include/opaque/opaque.h" ]; then
        mkdir -p "${DIST_DIR}/include"
        docker cp "${container_name}:/workspace/dist/android/${abi}/include/." "${DIST_DIR}/include/"
    fi

    docker rm -f "${container_name}"

    # Verify the library
    if [ -f "${DIST_DIR}/${abi}/lib/libeop.agent.so" ]; then
        print_status "Built libeop.agent.so for ${abi}"
        file "${DIST_DIR}/${abi}/lib/libeop.agent.so"
    else
        print_error "Failed to build libeop.agent.so for ${abi}"
        return 1
    fi
}

# Function to build for a specific ABI using local NDK
build_abi_local() {
    local abi=$1
    local build_type=$2

    echo ""
    echo -e "${BLUE}Building locally for ${abi}...${NC}"

    # Check for NDK
    if [ -z "${ANDROID_NDK_HOME}" ] && [ -z "${ANDROID_NDK}" ]; then
        print_error "ANDROID_NDK_HOME or ANDROID_NDK environment variable not set"
        return 1
    fi

    local ndk_path="${ANDROID_NDK_HOME:-${ANDROID_NDK}}"
    local build_dir="${PROJECT_ROOT}/build-android-${abi}"
    local install_dir="${DIST_DIR}/${abi}"

    # Clean build directory
    rm -rf "${build_dir}"
    mkdir -p "${build_dir}"

    # Configure
    cmake -B "${build_dir}" -S "${PROJECT_ROOT}" -G Ninja \
        -DCMAKE_TOOLCHAIN_FILE="${ndk_path}/build/cmake/android.toolchain.cmake" \
        -DANDROID_ABI="${abi}" \
        -DANDROID_PLATFORM=android-24 \
        -DCMAKE_BUILD_TYPE="${build_type}" \
        -DCMAKE_INSTALL_PREFIX="${install_dir}" \
        -DBUILD_CLIENT=ON \
        -DBUILD_SERVER=OFF \
        -DBUILD_SHARED_LIBS=ON \
        -DBUILD_DOTNET_INTEROP=ON \
        -DBUILD_ANDROID_JNI=ON \
        -DBUILD_TESTS=OFF \
        -DENABLE_HARDENING=ON

    # Build
    cmake --build "${build_dir}" -j$(nproc 2>/dev/null || sysctl -n hw.ncpu)

    # Install
    cmake --install "${build_dir}"

    # Verify
    if [ -f "${install_dir}/lib/libeop.agent.so" ]; then
        print_status "Built libeop.agent.so for ${abi}"
        file "${install_dir}/lib/libeop.agent.so"
    else
        print_error "Failed to build libeop.agent.so for ${abi}"
        return 1
    fi
}

# Check if Docker is available
USE_DOCKER=true
if ! command -v docker &> /dev/null; then
    print_warning "Docker not found, will attempt local build"
    USE_DOCKER=false
fi

# Determine which ABIs to build
if [ "${TARGET_ABI}" = "all" ]; then
    abis_to_build=("${SUPPORTED_ABIS[@]}")
else
    # Validate the requested ABI
    valid_abi=false
    for supported in "${SUPPORTED_ABIS[@]}"; do
        if [ "${TARGET_ABI}" = "${supported}" ]; then
            valid_abi=true
            break
        fi
    done

    if [ "${valid_abi}" = false ]; then
        print_error "Unsupported ABI: ${TARGET_ABI}"
        echo "Supported ABIs: ${SUPPORTED_ABIS[*]}"
        exit 1
    fi

    abis_to_build=("${TARGET_ABI}")
fi

# Build each ABI
for abi in "${abis_to_build[@]}"; do
    if [ "${USE_DOCKER}" = true ]; then
        build_abi_docker "${abi}" "${BUILD_TYPE}"
    else
        build_abi_local "${abi}" "${BUILD_TYPE}"
    fi
done

# Summary
echo ""
echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}  Build Complete${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""
echo -e "${GREEN}Output directory:${NC} ${DIST_DIR}"
echo ""
echo "Libraries built:"
for abi in "${abis_to_build[@]}"; do
    if [ -f "${DIST_DIR}/${abi}/lib/libeop.agent.so" ]; then
        size=$(ls -lh "${DIST_DIR}/${abi}/lib/libeop.agent.so" | awk '{print $5}')
        echo -e "  ${GREEN}✓${NC} ${abi}: libeop.agent.so (${size})"
    else
        echo -e "  ${RED}✗${NC} ${abi}: FAILED"
    fi
done

echo ""
echo "Directory structure:"
echo "  dist/android/"
for abi in "${abis_to_build[@]}"; do
    echo "    ${abi}/"
    echo "      lib/libeop.agent.so"
done
echo "    include/"
echo "      opaque/*.h"
