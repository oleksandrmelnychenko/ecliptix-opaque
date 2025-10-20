#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

TARGET="${1:-native}"
BUILD_TYPE="${2:-Release}"
RUN_TESTS="${3:-ON}"

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
            -DBUILD_CLIENT=ON \
            -DBUILD_SERVER=OFF \
            -DBUILD_SHARED_LIBS=ON \
            -DBUILD_DOTNET_INTEROP=ON \
            -DBUILD_TESTS="${RUN_TESTS}" \
            -DENABLE_HARDENING=ON \
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

        mkdir -p dist/client/windows

        docker build -f Dockerfile.windows -t ecliptix-opaque-client-windows \
            --build-arg BUILD_TARGET=client .
        docker run --rm -v "$(pwd)/dist:/workspace/dist" \
            ecliptix-opaque-client-windows

        echo "✅ CLIENT Windows build completed!"
        echo "📦 Checking artifacts..."
        ls -la dist/client/windows/ || echo "⚠️  Artifacts not found!"
        ;;

    "client-linux")
        echo "🐧 Building CLIENT library for Avalonia Desktop (Linux)..."

        if ! command -v docker &> /dev/null; then
            echo "❌ Docker required for Linux builds"
            exit 1
        fi

        mkdir -p dist/client/linux

        docker build -f Dockerfile.linux -t ecliptix-opaque-client-linux \
            --build-arg BUILD_TARGET=client .
        docker run --rm -v "$(pwd)/dist:/workspace/dist" \
            ecliptix-opaque-client-linux

        echo "✅ CLIENT Linux build completed!"
        echo "📦 Checking artifacts..."
        ls -la dist/client/linux/ || echo "⚠️  Artifacts not found!"
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

        mkdir -p dist/server/linux

        docker build -f Dockerfile.linux -t ecliptix-opaque-server-linux \
            --build-arg BUILD_TARGET=server .
        docker run --rm -v "$(pwd)/dist:/workspace/dist" \
            ecliptix-opaque-server-linux

        echo "✅ SERVER Linux build completed!"
        echo "📦 Checking artifacts..."
        ls -la dist/server/linux/ || echo "⚠️  Artifacts not found!"
        ;;

    "server-windows")
        echo "🪟 Building SERVER library for ASP.NET Core (Windows)..."

        if ! command -v docker &> /dev/null; then
            echo "❌ Docker required for Windows builds"
            exit 1
        fi

        mkdir -p dist/server/windows

        docker build -f Dockerfile.windows -t ecliptix-opaque-server-windows \
            --build-arg BUILD_TARGET=server .
        docker run --rm -v "$(pwd)/dist:/workspace/dist" \
            ecliptix-opaque-server-windows

        echo "✅ SERVER Windows build completed!"
        echo "📦 Checking artifacts..."
        ls -la dist/server/windows/ || echo "⚠️  Artifacts not found!"
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

    *)
        echo "❌ Unknown target: ${TARGET}"
        echo ""
        echo "🎯 Available targets:"
        echo ""
        echo "  Client builds (Avalonia Desktop + Future Mobile):"
        echo "    client         - Build client for current platform"
        echo "    client-macos   - Build client for macOS"
        echo "    client-windows - Build client for Windows (Docker)"
        echo "    client-linux   - Build client for Linux (Docker)"
        echo "    client-all     - Build client for all platforms"
        echo ""
        echo "  Server builds (ASP.NET Core):"
        echo "    server         - Build server for Linux (Docker)"
        echo "    server-linux   - Build server for Linux (Docker)"
        echo "    server-windows - Build server for Windows (Docker)"
        echo "    server-all     - Build server for all platforms"
        echo ""
        echo "  Complete builds:"
        echo "    all-platforms  - Build everything for all platforms"
        echo ""
        echo "Usage: $0 [target] [Debug|Release] [ON|OFF]"
        echo ""
        echo "Examples:"
        echo "  $0 client                # Build client for current platform"
        echo "  $0 server-linux          # Build server for Linux"
        echo "  $0 all-platforms Release # Build everything in Release mode"
        exit 1
        ;;
esac

echo ""
echo "🎉 Build process completed!"
echo ""
echo "📋 Available libraries:"
find dist -name "*.dylib" -o -name "*.so" -o -name "*.dll" 2>/dev/null | sort || true