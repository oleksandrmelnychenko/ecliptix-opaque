# macOS Universal Binary Toolchain for Ecliptix.Security.OPAQUE
#
# This toolchain builds universal (fat) binaries for both arm64 and x86_64.
# Usage:
#   cmake -DCMAKE_TOOLCHAIN_FILE=cmake/macos-toolchain.cmake \
#         -DMACOS_ARCH=universal ...
#
# Options:
#   MACOS_ARCH - Target architecture (arm64, x86_64, or universal)
#   MACOS_DEPLOYMENT_TARGET - Minimum macOS version (default: 11.0)

cmake_minimum_required(VERSION 3.20)

# Platform settings
set(CMAKE_SYSTEM_NAME Darwin)

# Default deployment target
if(NOT MACOS_DEPLOYMENT_TARGET)
    set(MACOS_DEPLOYMENT_TARGET "11.0" CACHE STRING "Minimum macOS deployment target")
endif()

# Default architecture
if(NOT MACOS_ARCH)
    set(MACOS_ARCH "universal" CACHE STRING "Target architecture (arm64, x86_64, universal)")
endif()

# Set architectures based on MACOS_ARCH
if(MACOS_ARCH STREQUAL "universal")
    set(CMAKE_OSX_ARCHITECTURES "arm64;x86_64" CACHE STRING "Build architectures for macOS")
elseif(MACOS_ARCH STREQUAL "arm64")
    set(CMAKE_OSX_ARCHITECTURES "arm64" CACHE STRING "Build architectures for macOS")
elseif(MACOS_ARCH STREQUAL "x86_64")
    set(CMAKE_OSX_ARCHITECTURES "x86_64" CACHE STRING "Build architectures for macOS")
else()
    message(FATAL_ERROR "Invalid MACOS_ARCH: ${MACOS_ARCH}. Use arm64, x86_64, or universal.")
endif()

# Set deployment target
set(CMAKE_OSX_DEPLOYMENT_TARGET "${MACOS_DEPLOYMENT_TARGET}" CACHE STRING "Minimum macOS deployment target")

# Use Clang for better cross-architecture support
set(CMAKE_C_COMPILER clang CACHE STRING "C Compiler")
set(CMAKE_CXX_COMPILER clang++ CACHE STRING "C++ Compiler")

# Position independent code
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Security hardening flags
set(CMAKE_C_FLAGS_INIT "-fstack-protector-strong")
set(CMAKE_CXX_FLAGS_INIT "-fstack-protector-strong")

# Release optimizations
set(CMAKE_C_FLAGS_RELEASE_INIT "-O3 -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE_INIT "-O3 -DNDEBUG")

# Enable LTO for release builds
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)

# Set RPATH behavior
set(CMAKE_MACOSX_RPATH ON)
set(CMAKE_INSTALL_RPATH "@loader_path")
set(CMAKE_BUILD_WITH_INSTALL_RPATH ON)

# Marker for conditionals in CMakeLists.txt
set(MACOS_UNIVERSAL_BUILD ON)
set(MACOS_TOOLCHAIN_LOADED ON)

# Log configuration
message(STATUS "macOS Universal Toolchain Configuration:")
message(STATUS "  Architectures: ${CMAKE_OSX_ARCHITECTURES}")
message(STATUS "  Deployment Target: ${CMAKE_OSX_DEPLOYMENT_TARGET}")
message(STATUS "  C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "  C++ Compiler: ${CMAKE_CXX_COMPILER}")
