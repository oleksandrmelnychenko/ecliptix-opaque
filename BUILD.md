# Build Instructions

This document provides instructions for building the Ecliptix.Security.OPAQUE library on different platforms.

## Requirements

- **C++ Compiler**: GCC 13+, Clang 17+, or MSVC 19.36+ (C++23 support required)
- **CMake**: 3.20 or later
- **libsodium**: Cryptographic library dependency

## Platform-Specific Instructions

### Windows (vcpkg)

#### 1. Install vcpkg

If you haven't installed vcpkg yet:

```powershell
# Clone vcpkg
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg

# Bootstrap vcpkg
.\bootstrap-vcpkg.bat

# Integrate with Visual Studio (optional)
.\vcpkg integrate install
```

#### 2. Install libsodium

```powershell
# Install libsodium (x64)
.\vcpkg install libsodium:x64-windows

# For static linking (recommended for deployment)
.\vcpkg install libsodium:x64-windows-static
```

#### 3. Configure CMake with vcpkg toolchain

```powershell
# Create build directory
mkdir build
cd build

# Configure with vcpkg toolchain
cmake .. -DCMAKE_TOOLCHAIN_FILE=[path to vcpkg]/scripts/buildsystems/vcpkg.cmake -DCMAKE_BUILD_TYPE=Release

# Example:
# cmake .. -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake -DCMAKE_BUILD_TYPE=Release
```

#### 4. Build

```powershell
# Build all targets
cmake --build . --config Release

# Run tests
ctest -C Release --output-on-failure
```

#### Visual Studio Integration

If you're using Visual Studio:

1. Open the project folder in Visual Studio
2. Visual Studio will automatically detect CMakeLists.txt
3. Configure CMake settings (Tools → Options → CMake)
4. Set the vcpkg toolchain file in CMakeSettings.json:

```json
{
  "configurations": [
    {
      "name": "x64-Release",
      "generator": "Ninja",
      "configurationType": "Release",
      "buildRoot": "${projectDir}\\out\\build\\${name}",
      "installRoot": "${projectDir}\\out\\install\\${name}",
      "cmakeCommandArgs": "-DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake",
      "buildCommandArgs": "",
      "ctestCommandArgs": ""
    }
  ]
}
```

### macOS

#### 1. Install Dependencies

Using Homebrew:

```bash
# Install libsodium
brew install libsodium pkg-config cmake
```

#### 2. Build

```bash
# Create build directory
mkdir build && cd build

# Configure (optionally with static libsodium)
cmake .. -DBUILD_STATIC_SODIUM=ON

# Build
cmake --build . -j8

# Run tests
ctest --output-on-failure
```

### Linux

#### 1. Install Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install build-essential cmake pkg-config libsodium-dev
```

**Fedora/RHEL:**
```bash
sudo dnf install gcc-c++ cmake pkg-config libsodium-devel
```

**Arch Linux:**
```bash
sudo pacman -S base-devel cmake pkg-config libsodium
```

#### 2. Build

```bash
# Create build directory
mkdir build && cd build

# Configure
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build . -j$(nproc)

# Run tests
ctest --output-on-failure
```

## CMake Build Options

Configure the build with these options:

```bash
cmake .. \
  -DBUILD_CLIENT=ON \              # Build client (initiator) library
  -DBUILD_SERVER=ON \              # Build server (responder) library
  -DBUILD_SHARED_LIBS=ON \         # Build shared libraries (.dll/.so/.dylib)
  -DBUILD_DOTNET_INTEROP=ON \      # Build .NET interop layer
  -DENABLE_HARDENING=ON \          # Enable security hardening flags
  -DBUILD_TESTS=ON \               # Build unit tests
  -DBUILD_STATIC_SODIUM=OFF        # Link libsodium statically (macOS/Linux)
```

## Outputs

After building, you'll find:

**Libraries:**
- `build/cmake/client/libopaque_client.{dll,so,dylib}` - Initiator (client) library
- `build/cmake/server/libopaque_server.{dll,so,dylib}` - Responder (server) library

**Tests:**
- `build/tests/test_opaque_protocol` - Protocol test executable

## Troubleshooting

### Windows: "libsodium not found"

Make sure you:
1. Installed libsodium via vcpkg
2. Specified the vcpkg toolchain file in CMake configuration
3. Are building for the correct architecture (x64)

### macOS: "pkg-config not found"

Install pkg-config:
```bash
brew install pkg-config
```

### Linux: Compiler doesn't support C++23

Update your compiler:
```bash
# Ubuntu/Debian (add toolchain repository)
sudo add-apt-repository ppa:ubuntu-toolchain-r/test
sudo apt-get update
sudo apt-get install gcc-13 g++-13

# Set as default
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-13 100
sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-13 100
```

### Linker warnings on macOS

If you see warnings about libsodium being built for a newer macOS version, these are harmless. To suppress them, match your deployment target:

```bash
cmake .. -DCMAKE_OSX_DEPLOYMENT_TARGET=14.0
```

## Cross-Compilation

### Windows on Linux (MinGW)

```bash
# Install MinGW toolchain
sudo apt-get install mingw-w64

# Build with MinGW toolchain
cmake .. -DCMAKE_TOOLCHAIN_FILE=../cmake/mingw-toolchain.cmake
cmake --build .
```

## Installation

To install the libraries system-wide:

```bash
cd build
sudo cmake --install .
```

This installs:
- Headers to `/usr/local/include/opaque/`
- Libraries to `/usr/local/lib/`
