#!/bin/bash
set -euo pipefail


SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
NUGET_DIR="$SCRIPT_DIR"
DIST_DIR="$PROJECT_ROOT/dist"

VERSION="1.0.0"
CONFIG="Release"
SKIP_BUILD=false
SKIP_PROTECT=false
SKIP_SIGN=false
MACOS_MIN_VERSION="${MACOS_MIN_VERSION:-12.0}"



RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-build) SKIP_BUILD=true; shift ;;
        --skip-protect) SKIP_PROTECT=true; shift ;;
        --skip-sign) SKIP_SIGN=true; shift ;;
        --version) VERSION="$2"; shift 2 ;;
        --config) CONFIG="$2"; shift 2 ;;
        --macos-min) MACOS_MIN_VERSION="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

log_info "Building Ecliptix.Security.OPAQUE v${VERSION} NuGet Package"
log_info "Configuration: ${CONFIG}"
log_info "macOS minimum version: ${MACOS_MIN_VERSION}"

build_native_libraries() {
    log_info "Building native libraries for all platforms..."

    cd "$PROJECT_ROOT"

    if [[ -f "build.sh" ]]; then
        MACOS_DEPLOYMENT_TARGET="${MACOS_MIN_VERSION}" ./build.sh all-platforms "${CONFIG}"
    else
        log_warn "build.sh not found, building manually..."

        if [[ "$(uname)" == "Darwin" ]]; then
            log_info "Building macOS libraries..."
            mkdir -p build-macos && cd build-macos
            cmake .. -DCMAKE_BUILD_TYPE="${CONFIG}" -DBUILD_CLIENT=ON -DBUILD_SERVER=ON
            cmake --build . --config "${CONFIG}" -j$(sysctl -n hw.ncpu)
            cd "$PROJECT_ROOT"
        fi

        if command -v docker &> /dev/null; then
            log_info "Building Linux libraries via Docker..."
            docker build -f Dockerfile.linux -t opaque-linux-builder .
            docker run --rm -v "$DIST_DIR:/workspace/dist" opaque-linux-builder
        fi

        if command -v docker &> /dev/null; then
            log_info "Building Windows libraries via Docker..."
            docker build -f Dockerfile.windows -t opaque-windows-builder .
            docker run --rm -v "$DIST_DIR:/workspace/dist" opaque-windows-builder
        fi
    fi
}

apply_protection() {
    log_info "Applying code protection/obfuscation..."

    if [[ -n "${VMPROTECT_PATH:-}" ]] && [[ -f "$VMPROTECT_PATH" ]]; then
        log_info "Applying VMProtect to Windows binaries..."

        for dll in \
            "$DIST_DIR"/client/windows/bin/*.dll \
            "$DIST_DIR"/client/windows/lib/*.dll \
            "$DIST_DIR"/server/windows/bin/*.dll \
            "$DIST_DIR"/server/windows/lib/*.dll; do
            if [[ -f "$dll" ]]; then
                local output_dll="${dll%.dll}_protected.dll"
                "$VMPROTECT_PATH" "$dll" "$output_dll" \
                    --vm-code-level ultra \
                    --mutation-level ultra \
                    --anti-debug \
                    --anti-vm \
                    --strip-debug \
                    --pack-resources
                mv "$output_dll" "$dll"
                log_success "Protected: $(basename "$dll")"
            fi
        done
    elif [[ -n "${THEMIDA_PATH:-}" ]] && [[ -f "$THEMIDA_PATH" ]]; then
        log_info "Applying Themida protection to Windows binaries..."

        for dll in \
            "$DIST_DIR"/client/windows/bin/*.dll \
            "$DIST_DIR"/client/windows/lib/*.dll \
            "$DIST_DIR"/server/windows/bin/*.dll \
            "$DIST_DIR"/server/windows/lib/*.dll; do
            if [[ -f "$dll" ]]; then
                "$THEMIDA_PATH" /protect "$dll" /output "${dll%.dll}_protected.dll" \
                    /virtualmachine FISH_WHITE \
                    /antidebug CHECK_DEBUGGER \
                    /compression ON
                mv "${dll%.dll}_protected.dll" "$dll"
                log_success "Protected: $(basename "$dll")"
            fi
        done
    else
        log_warn "No protection tool configured (VMPROTECT_PATH or THEMIDA_PATH)"
        log_warn "Applying compile-time hardening only..."


        if command -v strip &> /dev/null; then
            log_info "Stripping debug symbols..."
            find "$DIST_DIR" -name "*.so" -exec strip --strip-all {} \; 2>/dev/null || true
            find "$DIST_DIR" -name "*.dylib" -exec strip -x {} \; 2>/dev/null || true
        fi
    fi
}

sign_binaries() {
    log_info "Signing native binaries..."

    if [[ -n "${WINDOWS_SIGN_CERT_PATH:-}" ]]; then
        log_info "Signing Windows DLLs with Authenticode..."

        if command -v signtool &> /dev/null; then
            for dll in "$NUGET_DIR"/runtimes/win-*/native/*.dll; do
                if [[ -f "$dll" ]]; then
                    signtool sign /fd SHA256 /f "$WINDOWS_SIGN_CERT_PATH" \
                        /p "$WINDOWS_SIGN_CERT_PASSWORD" \
                        /tr http://timestamp.digicert.com /td SHA256 \
                        /d "Ecliptix Security OPAQUE" "$dll"
                    log_success "Signed: $(basename "$dll")"
                fi
            done
        elif command -v osslsigncode &> /dev/null; then
            for dll in "$NUGET_DIR"/runtimes/win-*/native/*.dll; do
                if [[ -f "$dll" ]]; then
                    osslsigncode sign -pkcs12 "$WINDOWS_SIGN_CERT_PATH" \
                        -pass "$WINDOWS_SIGN_CERT_PASSWORD" \
                        -n "Ecliptix Security OPAQUE" \
                        -h sha256 \
                        -t http://timestamp.digicert.com \
                        -in "$dll" -out "${dll}.signed"
                    mv "${dll}.signed" "$dll"
                    log_success "Signed: $(basename "$dll")"
                fi
            done
        else
            log_warn "signtool/osslsigncode not found, skipping Windows signing"
        fi
    else
        log_warn "WINDOWS_SIGN_CERT_PATH not set, skipping Authenticode signing"
    fi

    if [[ -n "${APPLE_SIGN_IDENTITY:-}" ]]; then
        log_info "Signing macOS dylibs..."

        for dylib in "$NUGET_DIR"/runtimes/osx-*/native/*.dylib; do
            if [[ -f "$dylib" ]]; then
                codesign --force --sign "$APPLE_SIGN_IDENTITY" \
                    --options runtime \
                    --timestamp \
                    "$dylib"
                log_success "Signed: $(basename "$dylib")"
            fi
        done
    else
        log_warn "APPLE_SIGN_IDENTITY not set, skipping macOS signing"
    fi

    log_info "Computing checksums for Linux binaries..."
    for so in "$NUGET_DIR"/runtimes/linux-*/native/*.so; do
        if [[ -f "$so" ]]; then
            sha256sum "$so" > "${so}.sha256"
            log_success "Checksum: $(basename "$so")"
        fi
    done
}

copy_to_nuget_structure() {
    log_info "Copying built libraries to NuGet package structure..."

    if [[ -d "$DIST_DIR/client/windows" ]]; then
        cp -f "$DIST_DIR/client/windows/bin/"*.dll "$NUGET_DIR/runtimes/win-x64/native/" 2>/dev/null || true
        cp -f "$DIST_DIR/client/windows/lib/"*.dll "$NUGET_DIR/runtimes/win-x64/native/" 2>/dev/null || true
        cp -f "$DIST_DIR/server/windows/bin/"*.dll "$NUGET_DIR/runtimes/win-x64/native/" 2>/dev/null || true
        cp -f "$DIST_DIR/server/windows/lib/"*.dll "$NUGET_DIR/runtimes/win-x64/native/" 2>/dev/null || true
    fi

    if [[ -d "$DIST_DIR/client/linux" ]]; then
        cp -f "$DIST_DIR/client/linux/lib/"*.so "$NUGET_DIR/runtimes/linux-x64/native/" 2>/dev/null || true
        cp -f "$DIST_DIR/server/linux/lib/"*.so "$NUGET_DIR/runtimes/linux-x64/native/" 2>/dev/null || true
    fi

    if [[ -d "$DIST_DIR/client/macos" ]]; then
        ARCH=$(uname -m)
        if [[ "$ARCH" == "arm64" ]]; then
            TARGET_DIR="osx-arm64"
        else
            TARGET_DIR="osx-x64"
        fi
        cp -f "$DIST_DIR/client/macos/lib/"*.dylib "$NUGET_DIR/runtimes/$TARGET_DIR/native/" 2>/dev/null || true
        cp -f "$DIST_DIR/server/macos/lib/"*.dylib "$NUGET_DIR/runtimes/$TARGET_DIR/native/" 2>/dev/null || true
    fi

    log_success "Libraries copied to NuGet structure"
}

create_nuget_package() {
    log_info "Creating NuGet package..."

    cd "$NUGET_DIR"

    sed -i.bak "s|<version>.*</version>|<version>${VERSION}</version>|" Ecliptix.Security.OPAQUE.nuspec
    rm -f Ecliptix.Security.OPAQUE.nuspec.bak

    mkdir -p "$PROJECT_ROOT/docs"
    if [[ ! -f "$PROJECT_ROOT/docs/README.md" ]]; then
        cat > "$PROJECT_ROOT/docs/README.md" << 'DOCEOF'
# Ecliptix.Security.OPAQUE

Native OPAQUE implementation with ML-KEM-768 integration.

## Usage

```csharp
[DllImport("eop.agent", CallingConvention = CallingConvention.Cdecl)]
static extern IntPtr opaque_client_create(byte[] serverPublicKey, int keyLength);

[DllImport("eop.relay", CallingConvention = CallingConvention.Cdecl)]
static extern int opaque_server_create_with_keys(byte[] privateKey, int privateKeyLen, byte[] publicKey, int publicKeyLen, out IntPtr handle);
```
DOCEOF
    fi

    if command -v nuget &> /dev/null; then
        nuget pack Ecliptix.Security.OPAQUE.nuspec -OutputDirectory ./output
    elif command -v dotnet &> /dev/null; then
        cat > temp.csproj << 'CSPROJEOF'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>netstandard2.0</TargetFramework>
    <NuspecFile>Ecliptix.Security.OPAQUE.nuspec</NuspecFile>
  </PropertyGroup>
</Project>
CSPROJEOF
        dotnet pack temp.csproj -o ./output
        rm -f temp.csproj
    else
        log_error "Neither 'nuget' nor 'dotnet' CLI found!"
        exit 1
    fi

    log_success "NuGet package created in: $NUGET_DIR/output/"
}

sign_nuget_package() {
    log_info "Signing NuGet package..."

    if [[ -z "${NUGET_SIGN_CERT_PATH:-}" ]]; then
        log_warn "NUGET_SIGN_CERT_PATH not set, skipping NuGet package signing"
        return
    fi

    local nupkg="$NUGET_DIR/output/Ecliptix.Security.OPAQUE.${VERSION}.nupkg"

    if command -v nuget &> /dev/null; then
        nuget sign "$nupkg" \
            -CertificatePath "$NUGET_SIGN_CERT_PATH" \
            -CertificatePassword "$NUGET_SIGN_CERT_PASSWORD" \
            -Timestamper http://timestamp.digicert.com
    elif command -v dotnet &> /dev/null; then
        dotnet nuget sign "$nupkg" \
            --certificate-path "$NUGET_SIGN_CERT_PATH" \
            --certificate-password "$NUGET_SIGN_CERT_PASSWORD" \
            --timestamper http://timestamp.digicert.com
    fi

    log_success "NuGet package signed"
}

main() {
    log_info "=========================================="
    log_info "Starting NuGet Package Build Pipeline"
    log_info "=========================================="

    if [[ "$SKIP_BUILD" != true ]]; then
        build_native_libraries
    else
        log_warn "Skipping native build (--skip-build)"
    fi

    copy_to_nuget_structure

    if [[ "$SKIP_PROTECT" != true ]]; then
        apply_protection
    else
        log_warn "Skipping protection (--skip-protect)"
    fi

    if [[ "$SKIP_SIGN" != true ]]; then
        sign_binaries
    else
        log_warn "Skipping binary signing (--skip-sign)"
    fi

    create_nuget_package

    if [[ "$SKIP_SIGN" != true ]]; then
        sign_nuget_package
    fi

    log_info "=========================================="
    log_success "Build Complete!"
    log_info "=========================================="
    log_info "Package: $NUGET_DIR/output/Ecliptix.Security.OPAQUE.${VERSION}.nupkg"
    log_info ""
    log_info "To publish to NuGet.org:"
    log_info "  nuget push output/Ecliptix.Security.OPAQUE.${VERSION}.nupkg -Source https://api.nuget.org/v3/index.json -ApiKey YOUR_API_KEY"
    log_info ""
    log_info "Or to a private feed:"
    log_info "  nuget push output/Ecliptix.Security.OPAQUE.${VERSION}.nupkg -Source https://your-feed.example.com/nuget -ApiKey YOUR_API_KEY"
}

main "$@"
