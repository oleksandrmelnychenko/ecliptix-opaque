# iOS CMake Toolchain File
# This toolchain file configures CMake to cross-compile for iOS
# Usage: cmake -DCMAKE_TOOLCHAIN_FILE=cmake/ios-toolchain.cmake -DPLATFORM=OS64 ..

set(CMAKE_SYSTEM_NAME iOS)
set(CMAKE_SYSTEM_VERSION 17.0)
set(IOS TRUE)

# Set the platform (OS64 = arm64 device, SIMULATOR64 = x86_64/arm64 simulator)
if(NOT DEFINED PLATFORM)
    set(PLATFORM "OS64")
endif()

# Configure SDK and architecture based on platform
if(PLATFORM STREQUAL "OS64")
    # iOS device (arm64)
    set(CMAKE_OSX_SYSROOT iphoneos)
    set(CMAKE_OSX_ARCHITECTURES arm64)
    set(IOS_PLATFORM_LOCATION "iPhoneOS.platform")
    set(CMAKE_XCODE_EFFECTIVE_PLATFORMS "-iphoneos")

elseif(PLATFORM STREQUAL "SIMULATOR64")
    # iOS Simulator (arm64 for Apple Silicon, x86_64 for Intel)
    set(CMAKE_OSX_SYSROOT iphonesimulator)
    # Build for both architectures
    set(CMAKE_OSX_ARCHITECTURES "arm64;x86_64")
    set(IOS_PLATFORM_LOCATION "iPhoneSimulator.platform")
    set(CMAKE_XCODE_EFFECTIVE_PLATFORMS "-iphonesimulator")

elseif(PLATFORM STREQUAL "SIMULATORARM64")
    # iOS Simulator (arm64 only for Apple Silicon)
    set(CMAKE_OSX_SYSROOT iphonesimulator)
    set(CMAKE_OSX_ARCHITECTURES arm64)
    set(IOS_PLATFORM_LOCATION "iPhoneSimulator.platform")
    set(CMAKE_XCODE_EFFECTIVE_PLATFORMS "-iphonesimulator")

else()
    message(FATAL_ERROR "Invalid PLATFORM: ${PLATFORM}. Must be OS64, SIMULATOR64, or SIMULATORARM64")
endif()

# Set minimum iOS version
set(CMAKE_OSX_DEPLOYMENT_TARGET "17.0" CACHE STRING "Minimum iOS deployment version")

# Standard settings
set(CMAKE_C_COMPILER_WORKS TRUE)
set(CMAKE_CXX_COMPILER_WORKS TRUE)
set(CMAKE_SYSTEM_PROCESSOR ${CMAKE_OSX_ARCHITECTURES})

# Use libc++ for iOS
set(CMAKE_CXX_FLAGS_INIT "-stdlib=libc++")

# Skip compiler checks (cross-compilation)
set(CMAKE_C_COMPILER_WORKS 1)
set(CMAKE_CXX_COMPILER_WORKS 1)

# Set the install name for dynamic libraries
set(CMAKE_INSTALL_NAME_DIR "@rpath")
set(CMAKE_BUILD_WITH_INSTALL_NAME_DIR TRUE)

# iOS-specific flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fembed-bitcode-marker")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fembed-bitcode-marker")

# Enable ARC (Automatic Reference Counting)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fobjc-arc")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fobjc-arc")

# Disable RPATH for iOS
set(CMAKE_SKIP_RPATH TRUE)
set(CMAKE_SKIP_BUILD_RPATH TRUE)
set(CMAKE_SKIP_INSTALL_RPATH TRUE)

# Set library output name based on platform
if(PLATFORM STREQUAL "OS64")
    set(IOS_ARCH_SUFFIX "ios-arm64")
elseif(PLATFORM STREQUAL "SIMULATOR64")
    set(IOS_ARCH_SUFFIX "ios-arm64_x86_64-simulator")
elseif(PLATFORM STREQUAL "SIMULATORARM64")
    set(IOS_ARCH_SUFFIX "ios-arm64-simulator")
endif()

# Force static libraries for iOS
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build shared libraries" FORCE)

message(STATUS "=== iOS Toolchain Configuration ===")
message(STATUS "Platform: ${PLATFORM}")
message(STATUS "SDK: ${CMAKE_OSX_SYSROOT}")
message(STATUS "Architectures: ${CMAKE_OSX_ARCHITECTURES}")
message(STATUS "Min iOS Version: ${CMAKE_OSX_DEPLOYMENT_TARGET}")
message(STATUS "Architecture Suffix: ${IOS_ARCH_SUFFIX}")
message(STATUS "===================================")
