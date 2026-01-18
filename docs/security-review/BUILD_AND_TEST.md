# Build and Test

## Prerequisites
- CMake 3.20+
- C++23 compiler
- libsodium 1.0.20+
- liboqs 0.10.0+ (ML-KEM-768)
- Optional: Docker for Linux/Windows builds

## Native macOS build
```sh
./build.sh native Release ON
```

## Client and server builds (macOS)
```sh
./build.sh client-macos Release ON
./build.sh server-linux Release OFF
```

## Multi-platform builds (Docker required)
```sh
./build.sh client-all Release OFF
./build.sh server-all Release OFF
```

## CMake manual build (example)
```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_CLIENT=ON -DBUILD_SERVER=ON -DBUILD_TESTS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure --parallel
```

## Tests
- Unit and integration tests are under tests/
- Test runner is Catch2
- Typical run:
```sh
ctest --test-dir build --output-on-failure --parallel
```

## Notes
- BUILD_STATIC_SODIUM toggles static linking of libsodium
- ENABLE_HARDENING enables compiler hardening flags
- BUILD_DOTNET_INTEROP enables C API exports
