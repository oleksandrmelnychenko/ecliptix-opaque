# Build Instructions

This document covers native builds, tests, and packaging for Ecliptix.Security.OPAQUE.

## Requirements

- CMake 3.20+
- C++23 compiler (GCC 13+, Clang 17+, or MSVC 19.36+)
- libsodium 1.0.20+
- liboqs 0.10.0+
- pkg-config (macOS/Linux)

## Quick Build (macOS/Linux)

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

## Windows (vcpkg)

```powershell
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg install libsodium:x64-windows liboqs:x64-windows
set VCPKG_ROOT=C:\path\to\vcpkg
cmake -B build -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build --output-on-failure -C Release
```

## macOS (Homebrew)

```bash
brew install libsodium liboqs pkg-config cmake
cmake -B build -DBUILD_STATIC_SODIUM=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

## Linux (Debian/Ubuntu)

```bash
sudo apt-get update
sudo apt-get install build-essential cmake pkg-config libsodium-dev liboqs-dev
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

If liboqs is not packaged for your distro, build it from source and ensure pkg-config can find it.

## Build Script Shortcuts

```bash
./build.sh client-macos Release ON
./build.sh server-linux Release OFF
./build.sh all-platforms Release OFF
```

## iOS Build

```bash
./build-ios.sh Release ON
```

## CMake Options

```bash
cmake -B build \
  -DBUILD_CLIENT=ON \
  -DBUILD_SERVER=ON \
  -DBUILD_SHARED_LIBS=ON \
  -DBUILD_DOTNET_INTEROP=ON \
  -DENABLE_HARDENING=ON \
  -DBUILD_TESTS=ON \
  -DBUILD_STATIC_SODIUM=OFF
```

## CI/CD Pipeline

| Workflow | Trigger | Jobs |
|----------|---------|------|
| **CI** (`ci.yml`) | push/PR to `main`, `develop` | Build & Test (Linux, macOS, Windows), Lint, Docs |
| **Benchmarks** (`benchmarks.yml`) | push to `main` (benchmarks/src), weekly Mon 06:00 UTC, manual | Benchmarks on Linux, macOS, Windows; combined report artifact |
| **Security Scan** (`security-scan.yml`) | push/PR, weekly, manual | CodeQL, Dependency Review, SBOM, Secret Scan, License/Policy checks |
| **Build & Publish** (`build-and-publish.yml`) | tags `v*`, manual | Native libs (macOS, Linux, Windows, Android, XCFramework), NuGet, GitHub Release |

CI and Benchmarks both build with `BUILD_BENCHMARKS=ON`, run tests, then run benchmarks and upload logs as artifacts.

## Outputs

- Client library: `libeop.agent` (macOS/Linux) or `eop.agent.dll` (Windows)
- Server library: `libeop.relay` (macOS/Linux) or `eop.relay.dll` (Windows)
- Tests: `tests/test_opaque_protocol`
- Benchmarks: `bench_micro`, `bench_protocol`, `bench_throughput`, `bench_overhead` (when `BUILD_BENCHMARKS=ON`)

## Install

```bash
cmake --install build
```

