# Android NDK Toolchain Wrapper for Ecliptix.Security.OPAQUE
#
# This wraps the official NDK toolchain with project-specific settings.
# Usage:
#   cmake -DCMAKE_TOOLCHAIN_FILE=cmake/android-toolchain.cmake \
#         -DANDROID_ABI=arm64-v8a \
#         -DANDROID_PLATFORM=android-24 ...
#
# Required Variables:
#   ANDROID_NDK or ANDROID_NDK_HOME - Path to NDK installation
#   ANDROID_ABI - Target architecture (arm64-v8a, armeabi-v7a, x86_64)
#   ANDROID_PLATFORM - Target API level (e.g., android-24)

cmake_minimum_required(VERSION 3.20)

# Find Android NDK
if(NOT ANDROID_NDK)
    if(DEFINED ENV{ANDROID_NDK_HOME})
        set(ANDROID_NDK $ENV{ANDROID_NDK_HOME})
    elseif(DEFINED ENV{ANDROID_NDK})
        set(ANDROID_NDK $ENV{ANDROID_NDK})
    elseif(DEFINED ENV{ANDROID_NDK_ROOT})
        set(ANDROID_NDK $ENV{ANDROID_NDK_ROOT})
    else()
        message(FATAL_ERROR "Android NDK not found. Set ANDROID_NDK, ANDROID_NDK_HOME, or ANDROID_NDK_ROOT environment variable.")
    endif()
endif()

# Validate NDK path
if(NOT EXISTS "${ANDROID_NDK}/build/cmake/android.toolchain.cmake")
    message(FATAL_ERROR "Invalid Android NDK path: ${ANDROID_NDK}")
endif()

# Default ABI if not specified
if(NOT ANDROID_ABI)
    set(ANDROID_ABI "arm64-v8a" CACHE STRING "Android ABI")
endif()

# Default platform/API level
if(NOT ANDROID_PLATFORM)
    set(ANDROID_PLATFORM "android-24" CACHE STRING "Android platform/API level")
endif()

# C++ standard library
if(NOT ANDROID_STL)
    set(ANDROID_STL "c++_shared" CACHE STRING "Android STL library")
endif()

# PIE (Position Independent Executable) - required for Android 5.0+
if(NOT ANDROID_PIE)
    set(ANDROID_PIE ON CACHE BOOL "Enable PIE")
endif()

# ARM mode for armeabi-v7a
if(NOT ANDROID_ARM_MODE)
    set(ANDROID_ARM_MODE "thumb" CACHE STRING "ARM mode")
endif()

# NEON support for ARM
if(NOT ANDROID_ARM_NEON)
    if(ANDROID_ABI STREQUAL "armeabi-v7a")
        set(ANDROID_ARM_NEON ON CACHE BOOL "Enable ARM NEON")
    endif()
endif()

# Include the official NDK toolchain
include("${ANDROID_NDK}/build/cmake/android.toolchain.cmake")

# Project-specific settings after NDK toolchain
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Android-specific definitions
add_compile_definitions(
    ANDROID
    __ANDROID__
    __ANDROID_API__=${ANDROID_NATIVE_API_LEVEL}
)

# Security hardening flags
string(APPEND CMAKE_C_FLAGS " -fstack-protector-strong")
string(APPEND CMAKE_CXX_FLAGS " -fstack-protector-strong")

# Disable RTTI and exceptions to reduce binary size (optional, can be overridden)
# string(APPEND CMAKE_CXX_FLAGS " -fno-rtti -fno-exceptions")

# Release optimizations
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    string(APPEND CMAKE_C_FLAGS_RELEASE " -O3 -DNDEBUG")
    string(APPEND CMAKE_CXX_FLAGS_RELEASE " -O3 -DNDEBUG")

    # LTO for release builds
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
endif()

# Set output library naming
set(ANDROID_LIBRARY_OUTPUT_SUFFIX "${ANDROID_ABI}")

# Mark as cross-compiling
set(CMAKE_CROSSCOMPILING TRUE)

# Log configuration
message(STATUS "Android Toolchain Configuration:")
message(STATUS "  NDK Path: ${ANDROID_NDK}")
message(STATUS "  ABI: ${ANDROID_ABI}")
message(STATUS "  Platform: ${ANDROID_PLATFORM}")
message(STATUS "  API Level: ${ANDROID_NATIVE_API_LEVEL}")
message(STATUS "  STL: ${ANDROID_STL}")
message(STATUS "  Compiler: ${CMAKE_CXX_COMPILER}")
