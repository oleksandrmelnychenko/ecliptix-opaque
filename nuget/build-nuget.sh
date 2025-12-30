#!/bin/bash
set -euo pipefail

# =============================================================================
# Ecliptix.Security.OPAQUE - NuGet Package Builder
# =============================================================================
# This script builds, protects, signs, and packages the native libraries
# for distribution as a NuGet package.
#
# Usage:
#   ./build-nuget.sh [options]
#
# Options:
#   --skip-build        Skip native library compilation
#   --skip-protect      Skip obfuscation/protection step
#   --skip-sign         Skip code signing
#   --version X.Y.Z     Set package version (default: 1.0.0)
#   --config Release    Build configuration (default: Release)
#   --macos-min 12.0    Minimum macOS deployment target for native builds
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
NUGET_DIR="$SCRIPT_DIR"
DIST_DIR="$PROJECT_ROOT/dist"

# Default options
VERSION="1.0.0"
CONFIG="Release"
SKIP_BUILD=false
SKIP_PROTECT=false
SKIP_SIGN=false
MACOS_MIN_VERSION="${MACOS_MIN_VERSION:-12.0}"

# Code signing configuration (set via environment variables)
# WINDOWS_SIGN_CERT_PATH - Path to .pfx certificate
# WINDOWS_SIGN_CERT_PASSWORD - Certificate password
# APPLE_SIGN_IDENTITY - macOS signing identity (e.g., "Developer ID Application: Company Name")
# NUGET_SIGN_CERT_PATH - NuGet signing certificate
# NUGET_SIGN_CERT_PASSWORD - NuGet certificate password

# Obfuscation tool configuration
# VMPROTECT_PATH - Path to VMProtect CLI
# THEMIDA_PATH - Path to Themida CLI

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Parse arguments
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

# =============================================================================
# Step 1: Build Native Libraries (all platforms)
# =============================================================================
build_native_libraries() {
    log_info "Building native libraries for all platforms..."

    cd "$PROJECT_ROOT"

    # Build using existing build.sh
    if [[ -f "build.sh" ]]; then
        MACOS_DEPLOYMENT_TARGET="${MACOS_MIN_VERSION}" ./build.sh all-platforms "${CONFIG}"
    else
        log_warn "build.sh not found, building manually..."

        # macOS (current platform)
        if [[ "$(uname)" == "Darwin" ]]; then
            log_info "Building macOS libraries..."
            mkdir -p build-macos && cd build-macos
            cmake .. -DCMAKE_BUILD_TYPE="${CONFIG}" -DBUILD_CLIENT=ON -DBUILD_SERVER=ON
            cmake --build . --config "${CONFIG}" -j$(sysctl -n hw.ncpu)
            cd "$PROJECT_ROOT"
        fi

        # Linux (via Docker)
        if command -v docker &> /dev/null; then
            log_info "Building Linux libraries via Docker..."
            docker build -f Dockerfile.linux -t opaque-linux-builder .
            docker run --rm -v "$DIST_DIR:/workspace/dist" opaque-linux-builder
        fi

        # Windows (via Docker)
        if command -v docker &> /dev/null; then
            log_info "Building Windows libraries via Docker..."
            docker build -f Dockerfile.windows -t opaque-windows-builder .
            docker run --rm -v "$DIST_DIR:/workspace/dist" opaque-windows-builder
        fi
    fi
}

# =============================================================================
# Step 2: Apply Code Protection/Obfuscation
# =============================================================================
apply_protection() {
    log_info "Applying code protection/obfuscation..."

    # VMProtect (Windows DLLs)
    if [[ -n "${VMPROTECT_PATH:-}" ]] && [[ -f "$VMPROTECT_PATH" ]]; then
        log_info "Applying VMProtect to Windows binaries..."

        for dll in "$DIST_DIR"/client/windows/lib/*.dll "$DIST_DIR"/server/windows/lib/*.dll; do
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

        for dll in "$DIST_DIR"/client/windows/lib/*.dll "$DIST_DIR"/server/windows/lib/*.dll; do
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

        # For macOS/Linux, we rely on compile-time hardening:
        # - -fstack-protector-strong
        # - -D_FORTIFY_SOURCE=2
        # - -fPIC, -fPIE
        # - RELRO, BIND_NOW
        # - Symbol stripping

        # Strip debug symbols from all binaries
        if command -v strip &> /dev/null; then
            log_info "Stripping debug symbols..."
            find "$DIST_DIR" -name "*.so" -exec strip --strip-all {} \; 2>/dev/null || true
            find "$DIST_DIR" -name "*.dylib" -exec strip -x {} \; 2>/dev/null || true
        fi
    fi
}

# =============================================================================
# Step 3: Sign Native Binaries
# =============================================================================
sign_binaries() {
    log_info "Signing native binaries..."

    # Windows Authenticode Signing
    if [[ -n "${WINDOWS_SIGN_CERT_PATH:-}" ]]; then
        log_info "Signing Windows DLLs with Authenticode..."

        # Use signtool (requires Windows SDK or osslsigncode on Linux/Mac)
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

    # macOS Code Signing
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

    # Linux binaries don't have a standard signing mechanism
    # but we can compute and store SHA256 hashes
    log_info "Computing checksums for Linux binaries..."
    for so in "$NUGET_DIR"/runtimes/linux-*/native/*.so; do
        if [[ -f "$so" ]]; then
            sha256sum "$so" > "${so}.sha256"
            log_success "Checksum: $(basename "$so")"
        fi
    done
}

# =============================================================================
# Step 4: Copy Built Libraries to NuGet Structure
# =============================================================================
copy_to_nuget_structure() {
    log_info "Copying built libraries to NuGet package structure..."

    # Windows x64
    if [[ -d "$DIST_DIR/client/windows" ]]; then
        cp -f "$DIST_DIR/client/windows/lib/"*.dll "$NUGET_DIR/runtimes/win-x64/native/" 2>/dev/null || true
        cp -f "$DIST_DIR/server/windows/lib/"*.dll "$NUGET_DIR/runtimes/win-x64/native/" 2>/dev/null || true
    fi

    # Linux x64
    if [[ -d "$DIST_DIR/client/linux" ]]; then
        cp -f "$DIST_DIR/client/linux/lib/"*.so "$NUGET_DIR/runtimes/linux-x64/native/" 2>/dev/null || true
        cp -f "$DIST_DIR/server/linux/lib/"*.so "$NUGET_DIR/runtimes/linux-x64/native/" 2>/dev/null || true
    fi

    # macOS (determine architecture)
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

# =============================================================================
# Step 5: Create NuGet Package
# =============================================================================
create_nuget_package() {
    log_info "Creating NuGet package..."

    cd "$NUGET_DIR"

    # Update version in nuspec
    sed -i.bak "s|<version>.*</version>|<version>${VERSION}</version>|" Ecliptix.Security.OPAQUE.nuspec
    rm -f Ecliptix.Security.OPAQUE.nuspec.bak

    # Create documentation if not exists
    mkdir -p "$PROJECT_ROOT/docs"
    if [[ ! -f "$PROJECT_ROOT/docs/README.md" ]]; then
        cat > "$PROJECT_ROOT/docs/README.md" << 'DOCEOF'
# Ecliptix.Security.OPAQUE

High-performance native implementation of the OPAQUE Password-Authenticated Key Exchange (PAKE) protocol.

## Features

- **Secure Password Authentication**: Passwords never leave the client device
- **Ristretto255 Elliptic Curve**: Modern, secure cryptographic primitives
- **Cross-Platform**: Windows, Linux, macOS, iOS support
- **P/Invoke Ready**: Native C exports for .NET integration

## Usage

```csharp
// Example P/Invoke declarations
[DllImport("opaque_client", CallingConvention = CallingConvention.Cdecl)]
private static extern IntPtr opaque_client_create(byte[] serverPublicKey, int keyLength);

[DllImport("opaque_client", CallingConvention = CallingConvention.Cdecl)]
private static extern void opaque_client_destroy(IntPtr handle);
```

## Security

This library implements the OPAQUE protocol as specified in the IETF draft.
All cryptographic operations use libsodium primitives.

## License

MIT License - See LICENSE file for details.
DOCEOF
    fi

    # Pack with NuGet CLI
    if command -v nuget &> /dev/null; then
        nuget pack Ecliptix.Security.OPAQUE.nuspec -OutputDirectory ./output
    elif command -v dotnet &> /dev/null; then
        # Create a minimal .csproj for dotnet pack
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

# =============================================================================
# Step 6: Sign NuGet Package
# =============================================================================
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

# =============================================================================
# Main Execution
# =============================================================================
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
