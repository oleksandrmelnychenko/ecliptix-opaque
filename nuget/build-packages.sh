#!/bin/bash
set -euo pipefail


SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DIST_DIR="$PROJECT_ROOT/dist"
OUTPUT_DIR="$SCRIPT_DIR/output"

VERSION="1.0.0"
CONFIG="Release"
SKIP_NATIVE=false
SKIP_PROTECT=false
SKIP_SIGN=false
BUILD_AGENT=true
BUILD_RELAY=true
AUTO_PUBLISH=false

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${CYAN}==>${NC} $1"; }

while [[ $# -gt 0 ]]; do
    case $1 in
        --version) VERSION="$2"; shift 2 ;;
        --config) CONFIG="$2"; shift 2 ;;
        --skip-native) SKIP_NATIVE=true; shift ;;
        --skip-protect) SKIP_PROTECT=true; shift ;;
        --skip-sign) SKIP_SIGN=true; shift ;;
        --agent-only) BUILD_RELAY=false; shift ;;
        --relay-only) BUILD_AGENT=false; shift ;;
        --publish) AUTO_PUBLISH=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo ""
echo "=============================================="
echo "  Ecliptix.Security.OPAQUE Package Builder"
echo "=============================================="
echo "  Version:     ${VERSION}"
echo "  Config:      ${CONFIG}"
echo "  Agent:       ${BUILD_AGENT}"
echo "  Relay:       ${BUILD_RELAY}"
echo "=============================================="
echo ""

mkdir -p "$OUTPUT_DIR"

copy_native_libraries() {
    local package=$1
    local lib_name=$2

    log_step "Copying native libraries for ${package}..."

    local pkg_dir="$SCRIPT_DIR/$package"

    local rids=(win-x64 linux-x64 osx-x64 osx-arm64)

    for rid in "${rids[@]}"; do
        local src_platform=""
        local ext=""
        case "$rid" in
            win-x64)
                src_platform="windows"
                ext=".dll"
                ;;
            linux-x64)
                src_platform="linux"
                ext=".so"
                ;;
            osx-x64|osx-arm64)
                src_platform="macos"
                ext=".dylib"
                ;;
            *)
                log_warn "  ${rid}: Unsupported RID"
                continue
                ;;
        esac
        local src_file=""
        local candidates=()

        if [[ "$src_platform" == "windows" ]]; then
            if [[ "$lib_name" == "client" ]]; then
                candidates=(
                    "$DIST_DIR/client/windows/bin/eop.agent${ext}"
                    "$DIST_DIR/client/windows/lib/eop.agent${ext}"
                )
            else
                candidates=(
                    "$DIST_DIR/server/windows/bin/eop.relay${ext}"
                    "$DIST_DIR/server/windows/lib/eop.relay${ext}"
                )
            fi
        else
            if [[ "$lib_name" == "client" ]]; then
                candidates=(
                    "$DIST_DIR/client/${src_platform}/lib/libeop.agent${ext}"
                )
            else
                candidates=(
                    "$DIST_DIR/server/${src_platform}/lib/libeop.relay${ext}"
                )
            fi
        fi

        for candidate in "${candidates[@]}"; do
            if [[ -f "$candidate" ]]; then
                src_file="$candidate"
                break
            fi
        done

        local dest_dir="$pkg_dir/runtimes/${rid}/native"
        mkdir -p "$dest_dir"

        if [[ -n "$src_file" ]]; then
            cp "$src_file" "$dest_dir/"
            log_success "  ${rid}: $(basename "$src_file")"
        else
            log_warn "  ${rid}: Not found (checked: ${candidates[*]})"
        fi
    done
}

apply_protection() {
    local package=$1

    if [[ "$SKIP_PROTECT" == true ]]; then
        log_warn "Skipping protection (--skip-protect)"
        return
    fi

    log_step "Applying protection to ${package}..."

    local pkg_dir="$SCRIPT_DIR/$package"

    if command -v strip &> /dev/null; then
        for so in "$pkg_dir"/runtimes/linux-*/native/*.so; do
            if [[ -f "$so" ]]; then
                strip --strip-all "$so" 2>/dev/null || true
                log_success "  Stripped: $(basename "$so")"
            fi
        done
        for dylib in "$pkg_dir"/runtimes/osx-*/native/*.dylib; do
            if [[ -f "$dylib" ]]; then
                strip -x "$dylib" 2>/dev/null || true
                log_success "  Stripped: $(basename "$dylib")"
            fi
        done
    fi

    if [[ -n "${VMPROTECT_PATH:-}" ]] && [[ -f "${VMPROTECT_PATH}" ]]; then
        for dll in "$pkg_dir"/runtimes/win-*/native/*.dll; do
            if [[ -f "$dll" ]]; then
                log_info "  Applying VMProtect to $(basename "$dll")..."
                "$VMPROTECT_PATH" "$dll" "${dll}.protected" \
                    --vm-code-level medium --mutation-level medium --anti-debug || true
                if [[ -f "${dll}.protected" ]]; then
                    mv "${dll}.protected" "$dll"
                    log_success "  Protected: $(basename "$dll")"
                fi
            fi
        done
    fi
}

sign_binaries() {
    local package=$1

    if [[ "$SKIP_SIGN" == true ]]; then
        log_warn "Skipping signing (--skip-sign)"
        return
    fi

    log_step "Signing binaries for ${package}..."

    local pkg_dir="$SCRIPT_DIR/$package"

    if [[ -n "${WINDOWS_SIGN_CERT_PATH:-}" ]]; then
        if command -v osslsigncode &> /dev/null; then
            for dll in "$pkg_dir"/runtimes/win-*/native/*.dll; do
                if [[ -f "$dll" ]]; then
                    osslsigncode sign -pkcs12 "$WINDOWS_SIGN_CERT_PATH" \
                        -pass "${WINDOWS_SIGN_CERT_PASSWORD:-}" \
                        -n "Ecliptix Security OPAQUE" -h sha256 \
                        -t http://timestamp.digicert.com \
                        -in "$dll" -out "${dll}.signed" 2>/dev/null || true
                    if [[ -f "${dll}.signed" ]]; then
                        mv "${dll}.signed" "$dll"
                        log_success "  Signed: $(basename "$dll")"
                    fi
                fi
            done
        fi
    fi

    if [[ -n "${APPLE_SIGN_IDENTITY:-}" ]]; then
        for dylib in "$pkg_dir"/runtimes/osx-*/native/*.dylib; do
            if [[ -f "$dylib" ]]; then
                codesign --force --sign "$APPLE_SIGN_IDENTITY" \
                    --options runtime --timestamp "$dylib" 2>/dev/null || true
                log_success "  Signed: $(basename "$dylib")"
            fi
        done
    fi
}

build_package() {
    local package=$1
    local lib_name=$2

    log_step "Building ${package} v${VERSION}..."

    local pkg_dir="$SCRIPT_DIR/$package"
    cd "$pkg_dir"

    if [[ -f "${package}.csproj" ]]; then
        sed -i.bak "s|<Version>.*</Version>|<Version>${VERSION}</Version>|" "${package}.csproj"
        rm -f "${package}.csproj.bak"
    fi

    dotnet pack -c "$CONFIG" -o "$OUTPUT_DIR" \
        /p:Version="$VERSION" \
        /p:PackageVersion="$VERSION" \
        --no-build --no-restore 2>/dev/null || \
    dotnet pack -c "$CONFIG" -o "$OUTPUT_DIR" \
        /p:Version="$VERSION" \
        /p:PackageVersion="$VERSION" \
        --no-build 2>/dev/null || \
    dotnet pack -c "$CONFIG" -o "$OUTPUT_DIR" \
        /p:Version="$VERSION" \
        /p:PackageVersion="$VERSION"

    log_success "Built: ${package}.${VERSION}.nupkg"
}

sign_nuget_package() {
    local package=$1

    if [[ "$SKIP_SIGN" == true ]]; then
        return
    fi

    if [[ -z "${NUGET_SIGN_CERT_PATH:-}" ]]; then
        log_warn "NUGET_SIGN_CERT_PATH not set, skipping package signing"
        return
    fi

    local nupkg="$OUTPUT_DIR/${package}.${VERSION}.nupkg"

    if [[ -f "$nupkg" ]]; then
        log_step "Signing NuGet package ${package}..."
        dotnet nuget sign "$nupkg" \
            --certificate-path "$NUGET_SIGN_CERT_PATH" \
            --certificate-password "${NUGET_SIGN_CERT_PASSWORD:-}" \
            --timestamper http://timestamp.digicert.com 2>/dev/null || true
        log_success "Signed: $(basename "$nupkg")"
    fi
}

main() {
    if [[ "$BUILD_AGENT" == true ]]; then
        echo ""
        log_info "========== AGENT PACKAGE =========="

        if [[ "$SKIP_NATIVE" != true ]]; then
            copy_native_libraries "Ecliptix.OPAQUE.Agent" "client"
        fi

        apply_protection "Ecliptix.OPAQUE.Agent"
        sign_binaries "Ecliptix.OPAQUE.Agent"
        build_package "Ecliptix.OPAQUE.Agent" "client"
        sign_nuget_package "Ecliptix.OPAQUE.Agent"
    fi

    if [[ "$BUILD_RELAY" == true ]]; then
        echo ""
        log_info "========== RELAY PACKAGE =========="

        if [[ "$SKIP_NATIVE" != true ]]; then
            copy_native_libraries "Ecliptix.OPAQUE.Relay" "server"
        fi

        apply_protection "Ecliptix.OPAQUE.Relay"
        sign_binaries "Ecliptix.OPAQUE.Relay"
        build_package "Ecliptix.OPAQUE.Relay" "server"
        sign_nuget_package "Ecliptix.OPAQUE.Relay"
    fi

    if [[ "$AUTO_PUBLISH" == true ]]; then
        publish_to_private
    fi

    echo ""
    echo "=============================================="
    log_success "Build Complete!"
    echo "=============================================="
    echo ""
    echo "Output packages:"
    ls -la "$OUTPUT_DIR"/*.nupkg 2>/dev/null || echo "  (no packages found)"
    echo ""
    echo "=== PUBLISH TO PRIVATE REPOSITORY ==="
    echo ""
    echo "GitHub Packages:"
    echo "  export NUGET_TOKEN=ghp_your_token"
    echo "  dotnet nuget push $OUTPUT_DIR/*.nupkg -s https://nuget.pkg.github.com/YOUR_ORG/index.json -k \$NUGET_TOKEN"
    echo ""
    echo "Azure Artifacts:"
    echo "  dotnet nuget push $OUTPUT_DIR/*.nupkg -s https://pkgs.dev.azure.com/YOUR_ORG/_packaging/YOUR_FEED/nuget/v3/index.json -k YOUR_PAT"
    echo ""
    echo "GitLab Package Registry:"
    echo "  dotnet nuget push $OUTPUT_DIR/*.nupkg -s https://gitlab.com/api/v4/projects/PROJECT_ID/packages/nuget/index.json -k YOUR_TOKEN"
    echo ""
    echo "Self-hosted (BaGet/ProGet):"
    echo "  dotnet nuget push $OUTPUT_DIR/*.nupkg -s https://your-server.com/nuget/v3/index.json -k YOUR_API_KEY"
    echo ""
}

publish_to_private() {
    local feed_url="${NUGET_FEED_URL:-}"
    local api_key="${NUGET_API_KEY:-${NUGET_TOKEN:-}}"

    if [[ -z "$feed_url" ]]; then
        log_warn "NUGET_FEED_URL not set. Set it to publish automatically."
        return
    fi

    if [[ -z "$api_key" ]]; then
        log_warn "NUGET_API_KEY or NUGET_TOKEN not set. Cannot publish."
        return
    fi

    log_step "Publishing to private repository..."

    for nupkg in "$OUTPUT_DIR"/*.nupkg; do
        if [[ -f "$nupkg" ]]; then
            dotnet nuget push "$nupkg" -s "$feed_url" -k "$api_key" --skip-duplicate
            log_success "Published: $(basename "$nupkg")"
        fi
    done
}

main "$@"
