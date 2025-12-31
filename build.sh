#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

TARGET="${1:-native}"
BUILD_TYPE="${2:-Release}"
RUN_TESTS="${3:-ON}"
MACOS_DEPLOYMENT_TARGET="${MACOS_DEPLOYMENT_TARGET:-12.0}"

echo "🔨 Building Ecliptix OPAQUE Library"
echo "Target: ${TARGET}"
echo "Build Type: ${BUILD_TYPE}"
echo "Run Tests: ${RUN_TESTS}"
echo ""

case "${TARGET}" in
    "client"|"client-macos")
        echo "🖥️  Building CLIENT library for Avalonia Desktop (macOS)..."

        BUILD_DIR="build-client-macos-$(echo ${BUILD_TYPE} | tr '[:upper:]' '[:lower:]')"
        INSTALL_DIR="dist/client/macos"

        mkdir -p "${BUILD_DIR}" "${INSTALL_DIR}"

        cmake -B "${BUILD_DIR}" \
            -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
            -DCMAKE_OSX_DEPLOYMENT_TARGET="${MACOS_DEPLOYMENT_TARGET}" \
            -DBUILD_CLIENT=ON \
            -DBUILD_SERVER=OFF \
            -DBUILD_SHARED_LIBS=ON \
            -DBUILD_DOTNET_INTEROP=ON \
            -DBUILD_TESTS="${RUN_TESTS}" \
            -DENABLE_HARDENING=ON \
            -DBUILD_STATIC_SODIUM=ON \
            -DCMAKE_INSTALL_PREFIX="${INSTALL_DIR}"

        cmake --build "${BUILD_DIR}" --parallel

        if [[ "${RUN_TESTS}" == "ON" ]]; then
            echo "🧪 Running CLIENT tests..."
            ctest --test-dir "${BUILD_DIR}" --output-on-failure --parallel
        fi

        cmake --install "${BUILD_DIR}"

        echo "✅ CLIENT macOS build completed!"
        echo "📦 Client library: ${INSTALL_DIR}/lib/libopaque_client.dylib"
        ;;

    "client-windows")
        echo "🪟 Building CLIENT library for Avalonia Desktop (Windows)..."

        if ! command -v docker &> /dev/null; then
            echo "❌ Docker required for Windows builds"
            exit 1
        fi

        docker build -f Dockerfile.windows -t ecliptix-opaque-client-windows \
            --build-arg BUILD_TARGET=client .
        docker run --rm -v "$(pwd)/dist:/workspace/dist" \
            ecliptix-opaque-client-windows

        echo "✅ CLIENT Windows build completed!"
        echo "📦 Client library: dist/client/windows/bin/libopaque_client.dll"
        ;;

    "client-linux")
        echo "🐧 Building CLIENT library for Avalonia Desktop (Linux)..."

        if ! command -v docker &> /dev/null; then
            echo "❌ Docker required for Linux builds"
            exit 1
        fi

        docker build -f Dockerfile.linux -t ecliptix-opaque-client-linux \
            --build-arg BUILD_TARGET=client .
        docker run --rm -v "$(pwd)/dist:/workspace/dist" \
            ecliptix-opaque-client-linux

        echo "✅ CLIENT Linux build completed!"
        echo "📦 Client library: dist/client/linux/lib/libopaque_client.so"
        ;;

    "client-all")
        echo "🌍 Building CLIENT library for all desktop platforms..."

        "${0}" client-macos "${BUILD_TYPE}" "${RUN_TESTS}"
        "${0}" client-windows "${BUILD_TYPE}" "${RUN_TESTS}"
        "${0}" client-linux "${BUILD_TYPE}" "${RUN_TESTS}"

        echo "✅ All CLIENT builds completed!"
        ;;

    "server"|"server-linux")
        echo "🖥️  Building SERVER library for ASP.NET Core (Linux)..."

        if ! command -v docker &> /dev/null; then
            echo "❌ Docker required for Linux server builds"
            exit 1
        fi

        docker build -f Dockerfile.linux -t ecliptix-opaque-server-linux \
            --build-arg BUILD_TARGET=server .
        docker run --rm -v "$(pwd)/dist:/workspace/dist" \
            ecliptix-opaque-server-linux

        echo "✅ SERVER Linux build completed!"
        echo "📦 Server library: dist/server/linux/lib/libopaque_server.so"
        ;;

    "server-windows")
        echo "🪟 Building SERVER library for ASP.NET Core (Windows)..."

        if ! command -v docker &> /dev/null; then
            echo "❌ Docker required for Windows builds"
            exit 1
        fi

        docker build -f Dockerfile.windows -t ecliptix-opaque-server-windows \
            --build-arg BUILD_TARGET=server .
        docker run --rm -v "$(pwd)/dist:/workspace/dist" \
            ecliptix-opaque-server-windows

        echo "✅ SERVER Windows build completed!"
        echo "📦 Server library: dist/server/windows/bin/libopaque_server.dll"
        ;;

    "server-all")
        echo "🌍 Building SERVER library for all platforms..."

        "${0}" server-linux "${BUILD_TYPE}" "${RUN_TESTS}"
        "${0}" server-windows "${BUILD_TYPE}" "${RUN_TESTS}"

        echo "✅ All SERVER builds completed!"
        ;;

    "all-platforms")
        echo "🌐 Building ALL libraries for ALL platforms..."

        "${0}" client-all "${BUILD_TYPE}" "${RUN_TESTS}"
        "${0}" server-all "${BUILD_TYPE}" "${RUN_TESTS}"

        echo "✅ Complete multi-platform build finished!"
        ;;

    "legacy-native"|"native"|"macos")
        echo "🍎 Building natively for macOS..."

        if ! command -v cmake &> /dev/null; then
            echo "❌ CMake not found. Please install CMake first."
            exit 1
        fi

        if ! pkg-config --exists libsodium; then
            echo "❌ libsodium not found. Please install libsodium first:"
            echo "   brew install libsodium"
            exit 1
        fi

        BUILD_DIR="build-macos-$(echo ${BUILD_TYPE} | tr '[:upper:]' '[:lower:]')"
        INSTALL_DIR="dist/macos"

        mkdir -p "${BUILD_DIR}" "${INSTALL_DIR}"

        cmake -B "${BUILD_DIR}" \
            -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
            -DCMAKE_OSX_DEPLOYMENT_TARGET="${MACOS_DEPLOYMENT_TARGET}" \
            -DBUILD_CLIENT=ON \
            -DBUILD_SERVER=ON \
            -DBUILD_SHARED_LIBS=ON \
            -DBUILD_DOTNET_INTEROP=ON \
            -DBUILD_TESTS="${RUN_TESTS}" \
            -DENABLE_HARDENING=ON \
            -DBUILD_STATIC_SODIUM=ON \
            -DCMAKE_INSTALL_PREFIX="${INSTALL_DIR}"

        cmake --build "${BUILD_DIR}" --parallel

        if [[ "${RUN_TESTS}" == "ON" ]]; then
            echo "🧪 Running tests..."
            ctest --test-dir "${BUILD_DIR}" --output-on-failure --parallel
        fi

        cmake --install "${BUILD_DIR}"

        echo "✅ macOS build completed successfully!"
        echo "📦 Libraries installed in: ${INSTALL_DIR}"
        ;;

    "linux")
        echo "🐧 Building for Linux using Docker..."

        if ! command -v docker &> /dev/null; then
            echo "❌ Docker not found. Please install Docker first."
            exit 1
        fi

        docker-compose --profile linux build
        docker-compose --profile linux up ecliptix-opaque-linux

        echo "✅ Linux build completed successfully!"
        echo "📦 Libraries installed in: dist/linux"
        ;;

    "windows")
        echo "🪟 Building for Windows using Docker..."

        if ! command -v docker &> /dev/null; then
            echo "❌ Docker not found. Please install Docker first."
            exit 1
        fi

        docker-compose --profile windows build
        docker-compose --profile windows up ecliptix-opaque-windows

        echo "✅ Windows build completed successfully!"
        echo "📦 Libraries installed in: dist/windows"
        ;;

    "all")
        echo "🌍 Building for all platforms..."

        "${0}" native "${BUILD_TYPE}" "${RUN_TESTS}"
        "${0}" linux "${BUILD_TYPE}" "${RUN_TESTS}"
        "${0}" windows "${BUILD_TYPE}" "${RUN_TESTS}"

        echo "✅ All platform builds completed successfully!"
        ;;

    *)
        echo "❌ Unknown target: ${TARGET}"
        echo ""
        echo "🎯 Available targets:"
        echo "  Client builds (Avalonia Desktop):"
        echo "    client, client-macos, client-windows, client-linux, client-all"
        echo ""
        echo "  Server builds (ASP.NET Core):"
        echo "    server, server-linux, server-windows, server-all"
        echo ""
        echo "  Complete builds:"
        echo "    all-platforms"
        echo ""
        echo "  Legacy:"
        echo "    native, macos, linux, windows"
        echo ""
        echo "Usage: $0 [target] [Debug|Release] [ON|OFF]"
        exit 1
        ;;
esac

echo ""
echo "🎉 Build process completed!"
echo ""
echo "📋 Available libraries:"
find dist -name "*.dylib" -o -name "*.so" -o -name "*.dll" 2>/dev/null | sort || true
